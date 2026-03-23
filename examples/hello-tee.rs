// Service configuration (heap_size, max_threads, allowed_hosts, attest_mode)
// is managed via the GuaranTEE API or dashboard -- no guarantee.toml needed.
// Users only need the #[attest] macro on their handlers.

use axum::{extract::Extension, response::Json, routing::get, Router};
use guarantee::{attest, state};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Serialize, Deserialize, Default, Clone, Debug)]
struct AppData {
    request_count: u64,
}

state! {
    #[mrenclave]
    AppData,
}

#[attest]
async fn hello() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "message": "hello from TEE" }))
}

async fn attestation_info(
    Extension(state): Extension<Arc<TeeState>>,
) -> Json<serde_json::Value> {
    Json(state.attestation_json())
}

#[tokio::main]
async fn main() {
    let port = std::env::var("PORT").unwrap_or_else(|_| "8080".to_string());
    let state = TeeState::initialize(std::path::Path::new("./sealed"))
        .expect("Failed to initialize TeeState");

    println!("Starting hello-tee on port {port}");

    let app = Router::new()
        .route("/hello", get(hello))
        .route("/.well-known/tee-attestation", get(attestation_info))
        .layer(Extension(Arc::new(state)));

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{port}"))
        .await
        .expect("Failed to bind");
    axum::serve(listener, app).await.expect("Server failed");
}
