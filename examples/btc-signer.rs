//! # Bitcoin Transaction Signer in a TEE
//!
//! A custodial Bitcoin signing service running inside a Trusted Execution
//! Environment. The private key never leaves the enclave — it's sealed with
//! MRSIGNER so it persists across redeploys but is only accessible inside
//! an attested enclave.
//!
//! Every signing response includes an attestation proof so callers can verify
//! the signature was produced by genuine enclave code, not a compromised server.
//!
//! ```bash
//! cargo run --example btc-signer
//!
//! # Get the public key
//! curl http://localhost:8080/pubkey
//!
//! # Sign a transaction (hex-encoded raw transaction)
//! curl -X POST http://localhost:8080/sign \
//!   -H 'Content-Type: application/json' \
//!   -d '{"tx_hex":"0200000001abcdef...","input_index":0}'
//!
//! # Verify the enclave attestation
//! curl http://localhost:8080/.well-known/tee-attestation
//! ```

use axum::{
    extract::Extension,
    http::StatusCode,
    response::{IntoResponse, Json},
    routing::{get, post},
    Router,
};
use guarantee::{attest, state, Encrypted, crypto::Encryptable};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio::sync::RwLock;

// ---------------------------------------------------------------------------
// Bitcoin key management (simplified — real impl would use secp256k1)
// ---------------------------------------------------------------------------

/// Represents a Bitcoin private key sealed inside the enclave.
/// Uses Ed25519 as a stand-in for secp256k1 (real impl would use k256 crate).
#[derive(Serialize, Deserialize, Clone, Debug)]
struct BtcWallet {
    /// Private key bytes — NEVER leaves the enclave.
    /// Stored as part of MRSIGNER-sealed state.
    #[serde(with = "hex_key_serde")]
    private_key: [u8; 32],
    /// Derivation path used (for HD wallets).
    derivation_path: String,
    /// Total transactions signed (audit counter).
    tx_count: u64,
}

impl Default for BtcWallet {
    fn default() -> Self {
        // Generate a random key on first initialization
        let mut key = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut key);
        Self {
            private_key: key,
            derivation_path: "m/84'/0'/0'/0/0".to_string(),
            tx_count: 0,
        }
    }
}

/// Hex serialization for [u8; 32] (for JSON storage inside sealed state).
mod hex_key_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(key: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        let hex: String = key.iter().map(|b| format!("{:02x}", b)).collect();
        hex.serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let hex = String::deserialize(d)?;
        let mut bytes = [0u8; 32];
        for i in 0..32 {
            bytes[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
                .map_err(serde::de::Error::custom)?;
        }
        Ok(bytes)
    }
}

// ---------------------------------------------------------------------------
// Signing audit log — encrypted at rest in external storage
// ---------------------------------------------------------------------------

#[derive(Encrypted, Serialize, Deserialize, Clone, Debug)]
struct SigningAuditEntry {
    tx_hash: String,
    #[encrypt]
    signature: String,
    timestamp: String,
    input_index: u32,
}

// ---------------------------------------------------------------------------
// TEE State
// ---------------------------------------------------------------------------

/// Per-deploy session data (MRENCLAVE).
#[derive(Serialize, Deserialize, Default, Clone, Debug)]
struct SignerSession {
    requests_this_session: u64,
    last_request_time: Option<String>,
}

state! {
    #[mrenclave]
    SignerSession,

    #[mrsigner]
    BtcWallet,

    #[external]
    SigningAuditEntry,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// GET /pubkey — return the public key (derived from the sealed private key).
#[attest]
async fn get_pubkey(
    Extension(state): Extension<Arc<RwLock<TeeState>>>,
) -> Json<serde_json::Value> {
    let s = state.read().await;
    let wallet = s.signer().btc_wallet();

    // In production: use secp256k1 to derive the actual Bitcoin public key
    // Here we just hash the private key as a stand-in
    let pubkey_hash = Sha256::digest(&wallet.private_key);
    let pubkey_hex: String = pubkey_hash.iter().map(|b| format!("{:02x}", b)).collect();

    Json(serde_json::json!({
        "public_key": pubkey_hex,
        "derivation_path": wallet.derivation_path,
        "total_signatures": wallet.tx_count,
        "network": "bitcoin-mainnet",
        "_note": "Public key derived inside TEE. Private key never leaves the enclave.",
    }))
}

#[derive(Deserialize)]
struct SignRequest {
    tx_hex: String,
    input_index: u32,
}

/// POST /sign — sign a Bitcoin transaction inside the TEE.
/// The private key never leaves enclave memory.
#[attest]
async fn sign_transaction(
    Extension(state): Extension<Arc<RwLock<TeeState>>>,
    Json(req): Json<SignRequest>,
) -> impl IntoResponse {
    let mut s = state.write().await;

    // Compute transaction hash (double SHA-256, as Bitcoin does)
    let tx_bytes = match hex_decode(&req.tx_hex) {
        Some(b) => b,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Invalid hex in tx_hex"})),
            ).into_response()
        }
    };

    let first_hash = Sha256::digest(&tx_bytes);
    let tx_hash = Sha256::digest(&first_hash);
    let tx_hash_hex: String = tx_hash.iter().map(|b| format!("{:02x}", b)).collect();

    // Sign the transaction hash with the private key
    // In production: use secp256k1::sign(tx_hash, private_key)
    // Here we use HMAC-SHA256 as a stand-in for a real signature
    let wallet = s.signer().btc_wallet();
    let mut sig_input = Vec::new();
    sig_input.extend_from_slice(&wallet.private_key);
    sig_input.extend_from_slice(&tx_hash);
    let signature = Sha256::digest(&sig_input);
    let sig_hex: String = signature.iter().map(|b| format!("{:02x}", b)).collect();

    // Update counters
    s.signer_mut().btc_wallet.tx_count += 1;
    s.enclave_mut().signer_session.requests_this_session += 1;
    s.enclave_mut().signer_session.last_request_time =
        Some(chrono::Utc::now().to_rfc3339());

    // Create encrypted audit entry for external storage
    let audit = SigningAuditEntry {
        tx_hash: tx_hash_hex.clone(),
        signature: sig_hex.clone(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        input_index: req.input_index,
    };
    let encrypted_audit = s.encrypt_signing_audit_entry(&audit);

    // Persist state
    let _ = s.seal(std::path::Path::new("./sealed"));

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "tx_hash": tx_hash_hex,
            "signature": sig_hex,
            "input_index": req.input_index,
            "total_signatures": s.signer().btc_wallet().tx_count,
            "audit_encrypted": encrypted_audit.is_ok(),
            "_note": "Signature produced inside TEE. Private key never left enclave memory.",
        })),
    ).into_response()
}

/// GET /status — signer status and session info.
async fn get_status(
    Extension(state): Extension<Arc<RwLock<TeeState>>>,
) -> Json<serde_json::Value> {
    let s = state.read().await;
    let session = s.enclave().signer_session();
    let wallet = s.signer().btc_wallet();

    Json(serde_json::json!({
        "status": "operational",
        "total_signatures_all_time": wallet.tx_count,
        "requests_this_session": session.requests_this_session,
        "last_request": session.last_request_time,
        "derivation_path": wallet.derivation_path,
        "tee_mode": if std::env::var("GUARANTEE_ENCLAVE").map(|v| v == "1").unwrap_or(false) {
            "sgx-enclave"
        } else {
            "dev-mode"
        },
    }))
}

async fn attestation_info(
    Extension(state): Extension<Arc<RwLock<TeeState>>>,
) -> Json<serde_json::Value> {
    let s = state.read().await;
    Json(s.attestation_json())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn hex_decode(hex: &str) -> Option<Vec<u8>> {
    if hex.len() % 2 != 0 {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect()
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    let port = std::env::var("PORT").unwrap_or_else(|_| "8080".to_string());
    let state = TeeState::initialize(std::path::Path::new("./sealed"))
        .expect("Failed to initialize TeeState");

    let wallet = state.signer().btc_wallet();
    let pubkey_hash = Sha256::digest(&wallet.private_key);
    let pubkey_short: String = pubkey_hash[..4].iter().map(|b| format!("{:02x}", b)).collect();

    println!("Bitcoin TEE Signer on port {port}");
    println!("  Public key: {pubkey_short}...");
    println!("  Total signatures: {}", wallet.tx_count);
    println!("  Derivation: {}", wallet.derivation_path);
    println!();
    println!("  GET  /pubkey   — get public key");
    println!("  POST /sign     — sign a transaction");
    println!("  GET  /status   — signer status");

    let app = Router::new()
        .route("/pubkey", get(get_pubkey))
        .route("/sign", post(sign_transaction))
        .route("/status", get(get_status))
        .route("/.well-known/tee-attestation", get(attestation_info))
        .layer(Extension(Arc::new(RwLock::new(state))));

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{port}"))
        .await
        .expect("Failed to bind");
    axum::serve(listener, app).await.expect("Server failed");
}
