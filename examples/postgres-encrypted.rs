//! # Encrypted PostgreSQL Storage
//!
//! Demonstrates storing sensitive user data in PostgreSQL with automatic
//! field-level encryption. The database only ever sees ciphertext for
//! `#[encrypt]` fields — only the enclave can decrypt.
//!
//! ```bash
//! # Start PostgreSQL
//! docker run -d --name pg -e POSTGRES_PASSWORD=dev -p 5432:5432 postgres:16
//!
//! # Run the example
//! DATABASE_URL=postgres://postgres:dev@localhost:5432/postgres cargo run --example postgres-encrypted
//!
//! # Test it
//! curl -X POST http://localhost:8080/users -H 'Content-Type: application/json' \
//!   -d '{"user_id":"alice","ssn":"123-45-6789","email":"alice@example.com"}'
//! curl http://localhost:8080/users/alice
//!
//! # Check what's in the DB — ssn is encrypted!
//! psql postgres://postgres:dev@localhost:5432/postgres -c "SELECT * FROM users;"
//! ```

use axum::{
    extract::{Extension, Path},
    http::StatusCode,
    response::{IntoResponse, Json},
    routing::{get, post},
    Router,
};
use guarantee::{state, attest, Encrypted, crypto::Encryptable};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Data model — #[encrypt] fields are encrypted at rest in the DB
// ---------------------------------------------------------------------------

#[derive(Encrypted, Serialize, Deserialize, Clone, Debug)]
struct UserRecord {
    user_id: String,
    #[encrypt]
    ssn: String,
    email: String,
}

// ---------------------------------------------------------------------------
// TEE State
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Default, Clone, Debug)]
struct DbConfig {
    connection_url: String,
}

state! {
    #[mrenclave]
    DbConfig,

    #[mrsigner]
    DbConfig,

    #[external]
    UserRecord,
}

// ---------------------------------------------------------------------------
// In-memory "database" (replace with real sqlx in production)
// ---------------------------------------------------------------------------

/// Simulates a PostgreSQL database — stores only encrypted records.
/// In production, replace with sqlx::PgPool queries.
struct MockDb {
    records: tokio::sync::RwLock<std::collections::HashMap<String, EncryptedUserRecord>>,
}

impl MockDb {
    fn new() -> Self {
        Self {
            records: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        }
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// POST /users — create a user with encrypted sensitive fields.
#[attest]
async fn create_user(
    Extension(state): Extension<Arc<TeeState>>,
    Extension(db): Extension<Arc<MockDb>>,
    Json(user): Json<UserRecord>,
) -> impl IntoResponse {
    // Encrypt sensitive fields before storing
    let encrypted = match state.encrypt_user_record(&user) {
        Ok(e) => e,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": e.to_string()})),
            )
                .into_response()
        }
    };

    // What gets stored in the DB:
    // user_id: "alice"                          ← plaintext (queryable)
    // ssn:     "enc:v1:a1b2c3d4...:7f8a9b..."  ← AES-256-GCM ciphertext
    // email:   "alice@example.com"              ← plaintext
    println!("Storing in DB:");
    println!("  user_id: {}", encrypted.user_id);
    println!("  ssn:     {} (encrypted)", &encrypted.ssn[..30]);
    println!("  email:   {}", encrypted.email);

    db.records
        .write()
        .await
        .insert(encrypted.user_id.clone(), encrypted);

    (
        StatusCode::CREATED,
        Json(serde_json::json!({"status": "created", "user_id": user.user_id})),
    )
        .into_response()
}

/// GET /users/:id — retrieve and decrypt a user record.
#[attest]
async fn get_user(
    Extension(state): Extension<Arc<TeeState>>,
    Extension(db): Extension<Arc<MockDb>>,
    Path(user_id): Path<String>,
) -> impl IntoResponse {
    let records = db.records.read().await;
    let encrypted = match records.get(&user_id) {
        Some(r) => r,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "User not found"})),
            )
                .into_response()
        }
    };

    // Decrypt inside the enclave — only we have the key
    match state.decrypt_user_record(encrypted) {
        Ok(user) => Json(serde_json::json!({
            "user_id": user.user_id,
            "ssn": user.ssn,
            "email": user.email,
        }))
        .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("Decryption failed: {e}")})),
        )
            .into_response(),
    }
}

/// GET /users/:id/raw — show what the DB actually stores (ciphertext).
async fn get_user_raw(
    Extension(db): Extension<Arc<MockDb>>,
    Path(user_id): Path<String>,
) -> impl IntoResponse {
    let records = db.records.read().await;
    match records.get(&user_id) {
        Some(encrypted) => Json(serde_json::json!({
            "user_id": encrypted.user_id,
            "ssn": encrypted.ssn,
            "email": encrypted.email,
            "_note": "This is what the database stores. The ssn field is AES-256-GCM encrypted."
        }))
        .into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "User not found"})),
        )
            .into_response(),
    }
}

async fn attestation_info(
    Extension(state): Extension<Arc<TeeState>>,
) -> Json<serde_json::Value> {
    Json(state.attestation_json())
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    let port = std::env::var("PORT").unwrap_or_else(|_| "8080".to_string());
    let state = TeeState::initialize(std::path::Path::new("./sealed"))
        .expect("Failed to initialize TeeState");
    let db = Arc::new(MockDb::new());

    println!("Encrypted DB example on port {port}");
    println!("  POST /users          — create user (ssn encrypted at rest)");
    println!("  GET  /users/:id      — get user (decrypted in enclave)");
    println!("  GET  /users/:id/raw  — see what the DB stores (ciphertext)");

    let app = Router::new()
        .route("/users", post(create_user))
        .route("/users/:id", get(get_user))
        .route("/users/:id/raw", get(get_user_raw))
        .route("/.well-known/tee-attestation", get(attestation_info))
        .layer(Extension(Arc::new(state)))
        .layer(Extension(db));

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{port}"))
        .await
        .expect("Failed to bind");
    axum::serve(listener, app).await.expect("Server failed");
}
