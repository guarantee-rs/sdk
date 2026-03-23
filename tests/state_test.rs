use guarantee::state;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Default, Clone, Debug)]
struct SessionState {
    user_id: String,
    token: String,
}

#[derive(Serialize, Deserialize, Default, Clone, Debug)]
struct PriceCache {
    price: f64,
}

#[derive(Serialize, Deserialize, Default, Clone, Debug)]
struct UserSecrets {
    api_key: String,
}

state! {
    #[mrenclave]
    SessionState,
    PriceCache,

    #[mrsigner]
    UserSecrets,
}

#[test]
fn tee_state_initializes_with_fresh_keys() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state = TeeState::initialize(dir.path()).expect("initialize");

    // Public key should be accessible via TeeState
    let _pub_key = state.public_key();

    // User state should be defaults
    assert_eq!(state.enclave().session_state().user_id, "");
    assert_eq!(state.enclave().price_cache().price, 0.0);
    assert_eq!(state.signer().user_secrets().api_key, "");
}

#[test]
fn tee_state_persists_across_seal_unseal() {
    let dir = tempfile::tempdir().expect("tempdir");

    let public_key_bytes;
    {
        let mut state = TeeState::initialize(dir.path()).expect("initialize");
        state.enclave_mut().session_state.user_id = "alice".to_string();
        state.enclave_mut().price_cache.price = 99.5;
        state.signer_mut().user_secrets.api_key = "secret-123".to_string();
        public_key_bytes = state.public_key().to_bytes();
        state.seal(dir.path()).expect("seal");
    }

    // Re-initialize from sealed files
    let state = TeeState::initialize(dir.path()).expect("re-initialize");
    assert_eq!(state.enclave().session_state().user_id, "alice");
    assert_eq!(state.enclave().price_cache().price, 99.5);
    assert_eq!(state.signer().user_secrets().api_key, "secret-123");
    assert_eq!(state.public_key().to_bytes(), public_key_bytes);
}

#[test]
fn sign_response_produces_valid_header() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state = TeeState::initialize(dir.path()).expect("initialize");

    let header = state.sign_response(b"hello world", "req-123");
    assert_eq!(header.version, 1);
    assert!(!header.signature_b64.is_empty());
    assert!(!header.payload_hash_hex.is_empty());
    assert!(!header.public_key_hex.is_empty());
}

#[test]
fn sign_response_signature_verifies() {
    use base64::Engine;
    use ed25519_dalek::Verifier;

    let dir = tempfile::tempdir().expect("tempdir");
    let state = TeeState::initialize(dir.path()).expect("initialize");

    let body = b"test body";
    let header = state.sign_response(body, "req-456");

    // Decode and verify the signature
    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(&header.signature_b64)
        .expect("valid base64");
    let signature = ed25519_dalek::Signature::from_bytes(
        sig_bytes.as_slice().try_into().expect("64 bytes"),
    );

    let hash_bytes = hex_decode(&header.payload_hash_hex);
    let pub_key = state.public_key();
    assert!(pub_key.verify(&hash_bytes, &signature).is_ok());
}

#[test]
fn user_fields_are_mutable() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut state = TeeState::initialize(dir.path()).expect("initialize");
    state.enclave_mut().session_state.user_id = "bob".to_string();
    state.enclave_mut().price_cache.price = 42.0;
    state.signer_mut().user_secrets.api_key = "new-key".to_string();

    assert_eq!(state.enclave().session_state().user_id, "bob");
    assert_eq!(state.enclave().price_cache().price, 42.0);
    assert_eq!(state.signer().user_secrets().api_key, "new-key");
}

#[test]
fn seal_then_modify_then_seal_again() {
    let dir = tempfile::tempdir().expect("tempdir");

    let mut state = TeeState::initialize(dir.path()).expect("initialize");
    state.enclave_mut().session_state.user_id = "first".to_string();
    state.seal(dir.path()).expect("first seal");

    // Modify and seal again
    state.enclave_mut().session_state.user_id = "second".to_string();
    state.seal(dir.path()).expect("second seal");

    // Re-initialize should see the latest
    let state = TeeState::initialize(dir.path()).expect("re-initialize");
    assert_eq!(state.enclave().session_state().user_id, "second");
}

#[test]
fn attestation_json_has_required_fields() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state = TeeState::initialize(dir.path()).expect("initialize");
    let json = state.attestation_json();
    assert!(json.get("public_key").is_some());
    assert!(json.get("tee_type").is_some());
}

// Test mrenclave-only state (no mrsigner section)
mod enclave_only {
    use super::*;

    #[derive(Serialize, Deserialize, Default, Clone, Debug)]
    struct Counter {
        value: u64,
    }

    state! {
        #[mrenclave]
        Counter,
    }

    #[test]
    fn enclave_only_state_works() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut state = TeeState::initialize(dir.path()).expect("initialize");
        let _pub_key = state.public_key();
        state.enclave_mut().counter.value = 42;
        state.seal(dir.path()).expect("seal");

        let state = TeeState::initialize(dir.path()).expect("re-initialize");
        assert_eq!(state.enclave().counter().value, 42);
    }

    #[test]
    fn enclave_only_sign_response_works() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = TeeState::initialize(dir.path()).expect("initialize");
        let header = state.sign_response(b"data", "req-1");
        assert_eq!(header.version, 1);
        assert!(!header.signature_b64.is_empty());
    }
}

// Test mrsigner-only state (no mrenclave section)
mod signer_only {
    use super::*;

    #[derive(Serialize, Deserialize, Default, Clone, Debug)]
    struct Credentials {
        secret: String,
    }

    state! {
        #[mrsigner]
        Credentials,
    }

    #[test]
    fn signer_only_state_works() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut state = TeeState::initialize(dir.path()).expect("initialize");
        state.signer_mut().credentials.secret = "top-secret".to_string();
        state.seal(dir.path()).expect("seal");

        let state = TeeState::initialize(dir.path()).expect("re-initialize");
        assert_eq!(state.signer().credentials().secret, "top-secret");
    }
}

fn hex_decode(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("valid hex"))
        .collect()
}

// --- Schema versioning tests ---

#[test]
fn schema_version_tracked() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state = TeeState::initialize(dir.path()).expect("initialize");
    // Default version is 1 (no version attribute specified in our state! macro)
    assert_eq!(state.enclave().schema_version(), 1);
    assert_eq!(state.signer().schema_version(), 1);
}

// Test that schema migration handles new fields via serde(default)
mod schema_migration {
    use serde::{Deserialize, Serialize};

    // Simulate "old" state with fewer fields by manually creating sealed data
    // that lacks a field, then unsealing with a struct that has the extra field.
    #[test]
    fn schema_migration_new_field_gets_default() {
        use guarantee::seal;

        let dir = tempfile::tempdir().expect("tempdir");
        let enclave_path = dir.path().join("enclave.sealed");

        // Seal "old" enclave state JSON that has signing_key but no "extra_counter" field
        // and schema_version = 0
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let old_json = serde_json::json!({
            "schema_version": 0,
            "signing_key": signing_key.to_bytes(),
        });
        let data = serde_json::to_vec(&old_json).expect("serialize old state");
        seal::seal_to_file(&data, &enclave_path, seal::SealMode::MrEnclave)
            .expect("seal old state");

        // Now define a state! with a new field and version = 2
        // The new field should get its default value
        #[derive(Serialize, Deserialize, Default, Clone, Debug)]
        struct NewFeature {
            counter: u64,
        }

        guarantee::state! {
            #[mrenclave(version = 2)]
            NewFeature,
        }

        let state = TeeState::initialize(dir.path()).expect("initialize with migration");

        // The new field should have its default value
        assert_eq!(state.enclave().new_feature().counter, 0);
        // Schema version should be upgraded to 2
        assert_eq!(state.enclave().schema_version(), 2);
    }
}

// Test versioned state! macro syntax
mod versioned_syntax {
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, Default, Clone, Debug)]
    struct SessionData {
        token: String,
    }

    #[derive(Serialize, Deserialize, Default, Clone, Debug)]
    struct Secrets {
        api_key: String,
    }

    guarantee::state! {
        #[mrenclave(version = 5)]
        SessionData,

        #[mrsigner(version = 3)]
        Secrets,
    }

    #[test]
    fn versioned_state_initializes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = TeeState::initialize(dir.path()).expect("initialize");
        assert_eq!(state.enclave().schema_version(), 5);
        assert_eq!(state.signer().schema_version(), 3);
    }

    #[test]
    fn versioned_state_persists() {
        let dir = tempfile::tempdir().expect("tempdir");
        {
            let mut state = TeeState::initialize(dir.path()).expect("initialize");
            state.enclave_mut().session_data.token = "abc".to_string();
            state.signer_mut().secrets.api_key = "key123".to_string();
            state.seal(dir.path()).expect("seal");
        }
        let state = TeeState::initialize(dir.path()).expect("re-initialize");
        assert_eq!(state.enclave().session_data().token, "abc");
        assert_eq!(state.signer().secrets().api_key, "key123");
        assert_eq!(state.enclave().schema_version(), 5);
        assert_eq!(state.signer().schema_version(), 3);
    }
}
