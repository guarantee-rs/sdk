//! # Price Oracle in a TEE
//!
//! An attested price feed oracle. Every price response is signed by the enclave,
//! proving the price came from trusted code — not a manipulated intermediary.
//!
//! ```bash
//! cargo run --example oracle
//! curl http://localhost:8080/price/BTC
//! curl http://localhost:8080/price/ETH
//! curl http://localhost:8080/.well-known/tee-attestation
//! ```

use axum::{
    extract::{Extension, Path},
    response::Json,
    routing::get,
    Router,
};
use guarantee::{attest, state};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/// Cached prices — reset on redeploy (MRENCLAVE-bound).
#[derive(Serialize, Deserialize, Default, Clone, Debug)]
struct PriceCache {
    prices: HashMap<String, f64>,
    last_updated: Option<String>,
}

/// Oracle configuration — persists across redeploys (MRSIGNER-bound).
#[derive(Serialize, Deserialize, Default, Clone, Debug)]
struct OracleConfig {
    /// API keys for upstream price sources (e.g., CoinGecko, Binance).
    source_api_key: String,
    /// Staleness threshold in seconds.
    max_staleness_secs: u64,
}

state! {
    #[mrenclave]
    PriceCache,

    #[mrsigner]
    OracleConfig,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// GET /price/:symbol — returns the attested price for a given asset.
/// Every response is signed by the enclave's ephemeral key.
#[attest]
async fn get_price(
    Extension(state): Extension<Arc<RwLock<TeeState>>>,
    Path(symbol): Path<String>,
) -> Json<serde_json::Value> {
    let state = state.read().await;
    let symbol_upper = symbol.to_uppercase();

    let price = state
        .enclave()
        .price_cache()
        .prices
        .get(&symbol_upper)
        .copied();

    match price {
        Some(p) => Json(serde_json::json!({
            "symbol": symbol_upper,
            "price": p,
            "currency": "USD",
            "source": "tee-oracle",
            "last_updated": state.enclave().price_cache().last_updated,
        })),
        None => Json(serde_json::json!({
            "error": "unknown_symbol",
            "message": format!("No price available for {symbol_upper}"),
        })),
    }
}

/// GET /prices — returns all cached prices.
#[attest]
async fn get_all_prices(
    Extension(state): Extension<Arc<RwLock<TeeState>>>,
) -> Json<serde_json::Value> {
    let state = state.read().await;
    let cache = state.enclave().price_cache();
    Json(serde_json::json!({
        "prices": cache.prices,
        "last_updated": cache.last_updated,
    }))
}

async fn attestation_info(
    Extension(state): Extension<Arc<RwLock<TeeState>>>,
) -> Json<serde_json::Value> {
    let state = state.read().await;
    Json(state.attestation_json())
}

// ---------------------------------------------------------------------------
// Background price updater
// ---------------------------------------------------------------------------

async fn update_prices(state: Arc<RwLock<TeeState>>) {
    loop {
        {
            let mut s = state.write().await;
            // In production, fetch from real APIs (CoinGecko, Binance, etc.)
            // Here we simulate with mock prices.
            let cache = &mut s.enclave_mut().price_cache;
            cache.prices.insert("BTC".into(), 67_432.50);
            cache.prices.insert("ETH".into(), 3_521.75);
            cache.prices.insert("SOL".into(), 142.30);
            cache.prices.insert("AVAX".into(), 35.80);
            cache.last_updated = Some(chrono::Utc::now().to_rfc3339());

            // Persist state (optional — prices are ephemeral anyway)
            let _ = s.seal(std::path::Path::new("./sealed"));
        }

        // Update every 10 seconds
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
    }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    let port = std::env::var("PORT").unwrap_or_else(|_| "8080".to_string());
    let state = TeeState::initialize(std::path::Path::new("./sealed"))
        .expect("Failed to initialize TeeState");
    let state = Arc::new(RwLock::new(state));

    // Start background price updater
    tokio::spawn(update_prices(state.clone()));

    println!("TEE Price Oracle running on port {port}");
    println!("  GET /price/BTC     — attested BTC price");
    println!("  GET /prices        — all attested prices");

    let app = Router::new()
        .route("/price/:symbol", get(get_price))
        .route("/prices", get(get_all_prices))
        .route("/.well-known/tee-attestation", get(attestation_info))
        .layer(Extension(state));

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{port}"))
        .await
        .expect("Failed to bind");
    axum::serve(listener, app).await.expect("Server failed");
}
