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
async fn hello_handler() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "message": "hello" }))
}

#[tokio::test]
async fn attest_adds_attestation_headers() {
    std::env::remove_var("GUARANTEE_ENCLAVE");
    let dir = tempfile::tempdir().expect("tempdir");
    let state = TeeState::initialize(dir.path()).expect("initialize");

    let app = Router::new()
        .route("/hello", get(hello_handler))
        .layer(Extension(Arc::new(state)));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    // Give server a moment to start
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let resp = reqwest::get(format!("http://{}/hello", addr))
        .await
        .unwrap();

    assert!(resp.headers().contains_key("x-tee-attestation"));
    assert_eq!(
        resp.headers()
            .get("x-tee-verified")
            .unwrap()
            .to_str()
            .unwrap(),
        "true"
    );

    let attestation = resp
        .headers()
        .get("x-tee-attestation")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(attestation.starts_with("v=1;"));
    assert!(attestation.contains("sig="));
    assert!(attestation.contains("key="));
}
