use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::parse::{Parse, ParseStream};
use syn::{parse_macro_input, DeriveInput, Ident, ItemFn, Token};

/// Transforms an axum handler to automatically sign responses with TEE attestation.
///
/// The macro:
/// 1. Extracts `Arc<TeeState>` from axum Extension
/// 2. Generates a request ID
/// 3. Runs the original handler
/// 4. Signs the response body via `TeeState::sign_response`
/// 5. Attaches X-TEE-Attestation and X-TEE-Verified headers
///
/// The signing key is never exposed -- `TeeState::sign_response` is the only way
/// to produce attestation signatures.
#[proc_macro_attribute]
pub fn attest(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let input_fn = parse_macro_input!(item as ItemFn);
    let fn_name = &input_fn.sig.ident;
    let fn_vis = &input_fn.vis;
    let fn_inputs = &input_fn.sig.inputs;
    let fn_body = &input_fn.block;
    let fn_attrs = &input_fn.attrs;

    let expanded = quote! {
        #(#fn_attrs)*
        #fn_vis async fn #fn_name(
            ::axum::extract::Extension(tee_state): ::axum::extract::Extension<::std::sync::Arc<TeeState>>,
            #fn_inputs
        ) -> impl ::axum::response::IntoResponse {
            use ::axum::response::IntoResponse;
            use ::axum::http::header::HeaderValue;

            // Generate request ID
            let request_id = ::uuid::Uuid::new_v4().to_string();

            // Execute original handler
            let inner_response = {
                #fn_body
            };

            // Convert to axum response
            let response = inner_response.into_response();
            let (mut parts, body) = response.into_parts();

            // Read body bytes -- return 500 if body cannot be read
            let body_bytes = match ::axum::body::to_bytes(body, usize::MAX).await {
                Ok(bytes) => bytes,
                Err(_) => {
                    let error_response = ::axum::response::Response::builder()
                        .status(::axum::http::StatusCode::INTERNAL_SERVER_ERROR)
                        .header("content-type", "application/json")
                        .body(::axum::body::Body::from(
                            r#"{"error":{"code":"body_read_failed","message":"Failed to read response body for attestation"}}"#
                        ))
                        .expect("failed to build error response");
                    return error_response.into_response();
                }
            };

            // Sign using TeeState -- signing key is never exposed
            let header = tee_state.sign_response(&body_bytes, &request_id);

            // Insert attestation headers
            if let Ok(val) = HeaderValue::from_str(&header.to_header_value()) {
                parts.headers.insert("X-TEE-Attestation", val);
            }
            if let Ok(val) = HeaderValue::from_str("true") {
                parts.headers.insert("X-TEE-Verified", val);
            }
            if let Ok(val) = HeaderValue::from_str(&request_id) {
                parts.headers.insert("X-TEE-Request-Id", val);
            }

            ::axum::response::Response::from_parts(parts, ::axum::body::Body::from(body_bytes))
        }
    };

    TokenStream::from(expanded)
}

// --- state! proc macro ---

/// Convert a PascalCase identifier to snake_case.
fn to_snake_case(name: &str) -> String {
    let mut result = String::new();
    for (i, ch) in name.chars().enumerate() {
        if ch.is_uppercase() {
            if i > 0 {
                result.push('_');
            }
            for lower in ch.to_lowercase() {
                result.push(lower);
            }
        } else {
            result.push(ch);
        }
    }
    result
}

enum SealSection {
    MrEnclave,
    MrSigner,
    External,
}

struct StateInput {
    mrenclave_types: Vec<Ident>,
    mrsigner_types: Vec<Ident>,
    external_types: Vec<Ident>,
}

impl Parse for StateInput {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let mut mrenclave_types = Vec::new();
        let mut mrsigner_types = Vec::new();
        let mut external_types = Vec::new();
        let mut current_section: Option<SealSection> = None;

        while !input.is_empty() {
            if input.peek(Token![#]) {
                input.parse::<Token![#]>()?;
                let content;
                syn::bracketed!(content in input);
                let attr_name: Ident = content.parse()?;
                if attr_name == "mrenclave" {
                    current_section = Some(SealSection::MrEnclave);
                } else if attr_name == "mrsigner" {
                    current_section = Some(SealSection::MrSigner);
                } else if attr_name == "external" {
                    current_section = Some(SealSection::External);
                } else {
                    return Err(syn::Error::new(
                        attr_name.span(),
                        "expected `mrenclave`, `mrsigner`, or `external`",
                    ));
                }
            } else {
                let type_name: Ident = input.parse()?;
                if input.peek(Token![,]) {
                    input.parse::<Token![,]>()?;
                }
                match &current_section {
                    Some(SealSection::MrEnclave) => mrenclave_types.push(type_name),
                    Some(SealSection::MrSigner) => mrsigner_types.push(type_name),
                    Some(SealSection::External) => external_types.push(type_name),
                    None => {
                        return Err(syn::Error::new(
                            type_name.span(),
                            "type must be under #[mrenclave], #[mrsigner], or #[external]",
                        ))
                    }
                }
            }
        }

        Ok(StateInput {
            mrenclave_types,
            mrsigner_types,
            external_types,
        })
    }
}

/// Declare TEE state with automatic key management and sealing.
///
/// Types listed under `#[mrenclave]` are sealed with MRENCLAVE (reset on redeploy).
/// An Ed25519 `signing_key` is auto-generated and included.
///
/// Types listed under `#[mrsigner]` are sealed with MRSIGNER (persist across redeploys).
/// A 256-bit `master_key` is auto-generated and included.
///
/// # Example
///
/// ```rust,ignore
/// use guarantee::state;
/// use serde::{Serialize, Deserialize};
///
/// #[derive(Serialize, Deserialize, Default, Clone, Debug)]
/// struct SessionState { user_id: String }
///
/// #[derive(Serialize, Deserialize, Default, Clone, Debug)]
/// struct UserSecrets { api_key: String }
///
/// state! {
///     #[mrenclave]
///     SessionState,
///
///     #[mrsigner]
///     UserSecrets,
/// }
/// ```
#[proc_macro]
pub fn state(input: TokenStream) -> TokenStream {
    let parsed = parse_macro_input!(input as StateInput);

    let has_enclave = !parsed.mrenclave_types.is_empty();
    let has_signer = !parsed.mrsigner_types.is_empty();

    // Generate field names (snake_case) from type names
    let enclave_fields: Vec<Ident> = parsed
        .mrenclave_types
        .iter()
        .map(|t| format_ident!("{}", to_snake_case(&t.to_string())))
        .collect();
    let enclave_types = &parsed.mrenclave_types;

    let signer_fields: Vec<Ident> = parsed
        .mrsigner_types
        .iter()
        .map(|t| format_ident!("{}", to_snake_case(&t.to_string())))
        .collect();
    let signer_types = &parsed.mrsigner_types;

    // Generate EnclaveState struct + impl
    let enclave_state = if has_enclave {
        quote! {
            /// MRENCLAVE-sealed state. Reset on redeploy (new binary = new measurement).
            /// Contains an auto-generated Ed25519 signing key for per-response attestation.
            #[derive(::serde::Serialize, ::serde::Deserialize)]
            pub struct EnclaveState {
                #[serde(with = "::guarantee::seal::signing_key_serde")]
                signing_key: ::ed25519_dalek::SigningKey,
                #(pub #enclave_fields: #enclave_types,)*
            }

            impl EnclaveState {
                #(
                    /// Read-only accessor for the `#enclave_fields` component.
                    pub fn #enclave_fields(&self) -> &#enclave_types {
                        &self.#enclave_fields
                    }
                )*
            }
        }
    } else {
        quote! {}
    };

    // Generate SignerState struct + impl
    let signer_state = if has_signer {
        quote! {
            /// MRSIGNER-sealed state. Persists across redeploys (same signing key = same MRSIGNER).
            /// Contains an auto-generated 256-bit master key for encrypting user data at rest.
            #[derive(::serde::Serialize, ::serde::Deserialize)]
            pub struct SignerState {
                master_key: [u8; 32],
                #(pub #signer_fields: #signer_types,)*
            }

            impl SignerState {
                #(
                    /// Read-only accessor for the `#signer_fields` component.
                    pub fn #signer_fields(&self) -> &#signer_types {
                        &self.#signer_fields
                    }
                )*
            }
        }
    } else {
        quote! {}
    };

    // TeeState struct fields
    let enclave_field_def = if has_enclave {
        quote! { enclave: EnclaveState, }
    } else {
        quote! {}
    };
    let signer_field_def = if has_signer {
        quote! { signer: SignerState, }
    } else {
        quote! {}
    };

    // Initialization code for enclave state
    let enclave_init = if has_enclave {
        quote! {
            let enclave: EnclaveState = match ::guarantee::seal::unseal_from_file(
                &enclave_path,
                ::guarantee::seal::SealMode::MrEnclave,
            ) {
                Ok(data) => {
                    ::tracing::info!("Unsealed MRENCLAVE state");
                    ::serde_json::from_slice(&data).map_err(|e| {
                        ::guarantee::SdkError::SealError(format!("Deserialize enclave state: {e}"))
                    })?
                }
                Err(_) => {
                    ::tracing::info!("No existing MRENCLAVE state -- generating fresh signing key");
                    let signing_key =
                        ::ed25519_dalek::SigningKey::generate(&mut ::rand::rngs::OsRng);
                    let state = EnclaveState {
                        signing_key,
                        #(#enclave_fields: Default::default(),)*
                    };
                    let data = ::serde_json::to_vec(&state).map_err(|e| {
                        ::guarantee::SdkError::SealError(format!("Serialize enclave state: {e}"))
                    })?;
                    ::guarantee::seal::seal_to_file(
                        &data,
                        &enclave_path,
                        ::guarantee::seal::SealMode::MrEnclave,
                    )?;
                    state
                }
            };
        }
    } else {
        quote! {}
    };

    // Initialization code for signer state
    let signer_init = if has_signer {
        quote! {
            let signer: SignerState = match ::guarantee::seal::unseal_from_file(
                &signer_path,
                ::guarantee::seal::SealMode::MrSigner,
            ) {
                Ok(data) => {
                    ::tracing::info!("Unsealed MRSIGNER state");
                    ::serde_json::from_slice(&data).map_err(|e| {
                        ::guarantee::SdkError::SealError(format!("Deserialize signer state: {e}"))
                    })?
                }
                Err(_) => {
                    ::tracing::info!("No existing MRSIGNER state -- generating fresh master key");
                    let mut master_key = [0u8; 32];
                    ::rand::RngCore::fill_bytes(&mut ::rand::rngs::OsRng, &mut master_key);
                    let state = SignerState {
                        master_key,
                        #(#signer_fields: Default::default(),)*
                    };
                    let data = ::serde_json::to_vec(&state).map_err(|e| {
                        ::guarantee::SdkError::SealError(format!("Serialize signer state: {e}"))
                    })?;
                    ::guarantee::seal::seal_to_file(
                        &data,
                        &signer_path,
                        ::guarantee::seal::SealMode::MrSigner,
                    )?;
                    state
                }
            };
        }
    } else {
        quote! {}
    };

    // TeeState constructor expression
    let tee_state_construct = match (has_enclave, has_signer) {
        (true, true) => quote! { TeeState { enclave, signer } },
        (true, false) => quote! { TeeState { enclave } },
        (false, true) => quote! { TeeState { signer } },
        (false, false) => quote! { TeeState {} },
    };

    // Accessors on TeeState
    let enclave_accessor = if has_enclave {
        quote! {
            /// Access the MRENCLAVE-sealed state (read-only).
            pub fn enclave(&self) -> &EnclaveState {
                &self.enclave
            }
            /// Access the MRENCLAVE-sealed state (mutable).
            pub fn enclave_mut(&mut self) -> &mut EnclaveState {
                &mut self.enclave
            }
        }
    } else {
        quote! {}
    };

    // Attestation methods on TeeState (only when mrenclave section exists)
    let attestation_methods = if has_enclave {
        quote! {
            /// Sign a response body for attestation. Used by the `#[attest]` macro.
            /// The signing key is never exposed -- this is the only way to produce signatures.
            pub fn sign_response(&self, body: &[u8], request_id: &str) -> ::guarantee::AttestationHeader {
                ::guarantee::seal::sign_with_enclave_key(&self.enclave.signing_key, body, request_id)
            }

            /// Get the public verifying key for the attestation endpoint.
            pub fn public_key(&self) -> ::ed25519_dalek::VerifyingKey {
                self.enclave.signing_key.verifying_key()
            }

            /// Get startup attestation JSON for `/.well-known/tee-attestation`.
            pub fn attestation_json(&self) -> ::serde_json::Value {
                let pub_key = self.enclave.signing_key.verifying_key();
                ::serde_json::json!({
                    "public_key": ::guarantee::response::hex_encode(pub_key.as_bytes()),
                    "tee_type": if ::std::env::var("GUARANTEE_ENCLAVE").map(|v| v == "1").unwrap_or(false) {
                        "intel-sgx"
                    } else {
                        "dev-mode"
                    },
                })
            }
        }
    } else {
        quote! {}
    };

    let signer_accessor = if has_signer {
        quote! {
            /// Access the MRSIGNER-sealed state (read-only).
            pub fn signer(&self) -> &SignerState {
                &self.signer
            }
            /// Access the MRSIGNER-sealed state (mutable).
            pub fn signer_mut(&mut self) -> &mut SignerState {
                &mut self.signer
            }
        }
    } else {
        quote! {}
    };

    // Seal logic
    let seal_enclave = if has_enclave {
        quote! {
            let enclave_data = ::serde_json::to_vec(&self.enclave).map_err(|e| {
                ::guarantee::SdkError::SealError(format!("Serialize enclave state: {e}"))
            })?;
            ::guarantee::seal::seal_to_file(
                &enclave_data,
                &enclave_path,
                ::guarantee::seal::SealMode::MrEnclave,
            )?;
        }
    } else {
        quote! {}
    };

    let seal_signer = if has_signer {
        quote! {
            let signer_data = ::serde_json::to_vec(&self.signer).map_err(|e| {
                ::guarantee::SdkError::SealError(format!("Serialize signer state: {e}"))
            })?;
            ::guarantee::seal::seal_to_file(
                &signer_data,
                &signer_path,
                ::guarantee::seal::SealMode::MrSigner,
            )?;
        }
    } else {
        quote! {}
    };

    // Per-type encryption methods on TeeState for each #[external] type.
    // Each type gets its own derived key from master_key + "external:<snake_case_type>".
    let external_snake_names: Vec<Ident> = parsed
        .external_types
        .iter()
        .map(|t| format_ident!("{}", to_snake_case(&t.to_string())))
        .collect();
    let external_types_ref = &parsed.external_types;
    let external_encrypted_names: Vec<Ident> = parsed
        .external_types
        .iter()
        .map(|t| format_ident!("Encrypted{}", t))
        .collect();
    let external_purpose_strings: Vec<String> = parsed
        .external_types
        .iter()
        .map(|t| format!("external:{}", to_snake_case(&t.to_string())))
        .collect();

    let encrypt_method_names: Vec<Ident> = external_snake_names
        .iter()
        .map(|s| format_ident!("encrypt_{}", s))
        .collect();
    let decrypt_method_names: Vec<Ident> = external_snake_names
        .iter()
        .map(|s| format_ident!("decrypt_{}", s))
        .collect();

    let encryption_methods = if has_signer && !parsed.external_types.is_empty() {
        quote! {
            #(
                /// Encrypt a value using a per-type derived key from the MRSIGNER-bound master key.
                /// The key is derived at runtime via HKDF-SHA256 with purpose `"external:<type>"`.
                pub fn #encrypt_method_names(&self, value: &#external_types_ref) -> Result<#external_encrypted_names, ::guarantee::SdkError> {
                    let key = ::guarantee::crypto::derive_key(&self.signer.master_key, #external_purpose_strings.as_bytes());
                    value.encrypt(&key)
                }

                /// Decrypt a value using a per-type derived key from the MRSIGNER-bound master key.
                pub fn #decrypt_method_names(&self, encrypted: &#external_encrypted_names) -> Result<#external_types_ref, ::guarantee::SdkError> {
                    let key = ::guarantee::crypto::derive_key(&self.signer.master_key, #external_purpose_strings.as_bytes());
                    #external_types_ref::decrypt_from(encrypted, &key)
                }
            )*
        }
    } else {
        quote! {}
    };

    let output = quote! {
        #enclave_state
        #signer_state

        /// Unified TEE state container. Holds both MRENCLAVE-sealed and MRSIGNER-sealed state.
        ///
        /// - `enclave()` -- state that resets on redeploy (bound to binary measurement)
        /// - `signer()` -- state that persists across redeploys (bound to signing key)
        pub struct TeeState {
            #enclave_field_def
            #signer_field_def
        }

        impl TeeState {
            /// Initialize TEE state. Attempts to unseal existing state from `seal_dir`.
            /// If no sealed state exists (first boot or MRENCLAVE changed), generates fresh keys.
            pub fn initialize(
                seal_dir: &::std::path::Path,
            ) -> Result<Self, ::guarantee::SdkError> {
                let enclave_path = seal_dir.join("enclave.sealed");
                let signer_path = seal_dir.join("signer.sealed");

                #enclave_init
                #signer_init

                Ok(#tee_state_construct)
            }

            /// Seal all state to disk. Call after mutating state to persist changes.
            pub fn seal(
                &self,
                seal_dir: &::std::path::Path,
            ) -> Result<(), ::guarantee::SdkError> {
                let enclave_path = seal_dir.join("enclave.sealed");
                let signer_path = seal_dir.join("signer.sealed");

                #seal_enclave
                #seal_signer

                Ok(())
            }

            #enclave_accessor
            #signer_accessor
            #attestation_methods
            #encryption_methods
        }
    };

    TokenStream::from(output)
}

// --- Encrypted derive macro ---

/// Derive macro that generates an encrypted version of a struct and `Encryptable` trait impl.
///
/// Fields annotated with `#[encrypt]` will be encrypted using AES-256-GCM when
/// `encrypt()` is called. Non-annotated fields are copied as-is.
///
/// `#[encrypt]` only works on `String` fields.
///
/// # Example
///
/// ```rust,ignore
/// #[derive(Encrypted, Serialize, Deserialize, Clone, Debug, PartialEq)]
/// struct UserRecord {
///     user_id: String,
///     #[encrypt]
///     ssn: String,
///     #[encrypt]
///     bank_account: String,
///     email: String,
/// }
/// ```
///
/// This generates `EncryptedUserRecord` and an `Encryptable` impl on `UserRecord`.
#[proc_macro_derive(Encrypted, attributes(encrypt))]
pub fn derive_encrypted(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    match impl_encrypted(&input) {
        Ok(tokens) => tokens,
        Err(err) => err.to_compile_error().into(),
    }
}

fn impl_encrypted(input: &DeriveInput) -> syn::Result<TokenStream> {
    let name = &input.ident;
    let encrypted_name = format_ident!("Encrypted{}", name);

    let fields = match &input.data {
        syn::Data::Struct(data) => match &data.fields {
            syn::Fields::Named(fields) => &fields.named,
            _ => {
                return Err(syn::Error::new_spanned(
                    input,
                    "Encrypted can only be derived for structs with named fields",
                ))
            }
        },
        _ => {
            return Err(syn::Error::new_spanned(
                input,
                "Encrypted can only be derived for structs",
            ))
        }
    };

    let mut encrypted_field_defs = Vec::new();
    let mut encrypt_exprs = Vec::new();
    let mut decrypt_exprs = Vec::new();

    for field in fields {
        let field_name = field.ident.as_ref().ok_or_else(|| {
            syn::Error::new_spanned(field, "expected named field")
        })?;
        let field_ty = &field.ty;
        let has_encrypt = field.attrs.iter().any(|a| a.path().is_ident("encrypt"));

        if has_encrypt {
            // Encrypted field: type becomes String in the encrypted struct
            encrypted_field_defs.push(quote! {
                pub #field_name: String
            });
            encrypt_exprs.push(quote! {
                #field_name: ::guarantee::crypto::encrypt_field(&self.#field_name, key)?
            });
            decrypt_exprs.push(quote! {
                #field_name: ::guarantee::crypto::decrypt_field(&encrypted.#field_name, key)?
            });
        } else {
            // Non-encrypted field: keep the same type, clone the value
            encrypted_field_defs.push(quote! {
                pub #field_name: #field_ty
            });
            encrypt_exprs.push(quote! {
                #field_name: self.#field_name.clone()
            });
            decrypt_exprs.push(quote! {
                #field_name: encrypted.#field_name.clone()
            });
        }
    }

    let output = quote! {
        /// Encrypted version of [`#name`]. Fields marked `#[encrypt]` contain
        /// AES-256-GCM ciphertext in the format `enc:v1:<nonce_hex>:<ciphertext_hex>`.
        #[derive(::serde::Serialize, ::serde::Deserialize, Debug, Clone)]
        pub struct #encrypted_name {
            #(#encrypted_field_defs,)*
        }

        impl ::guarantee::crypto::Encryptable for #name {
            type Encrypted = #encrypted_name;

            fn encrypt(&self, key: &[u8; 32]) -> Result<#encrypted_name, ::guarantee::SdkError> {
                Ok(#encrypted_name {
                    #(#encrypt_exprs,)*
                })
            }

            fn decrypt_from(encrypted: &#encrypted_name, key: &[u8; 32]) -> Result<Self, ::guarantee::SdkError> {
                Ok(#name {
                    #(#decrypt_exprs,)*
                })
            }
        }
    };

    Ok(output.into())
}
