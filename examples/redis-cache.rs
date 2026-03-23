//! # Encrypted Redis Cache
//!
//! Demonstrates using a TEE enclave with Redis as an encrypted cache layer.
//! Sensitive values are encrypted before being stored in Redis — even if Redis
//! is compromised, the data is unreadable without the enclave's master key.
//!
//! ```bash
//! # Start Redis
//! docker run -d --name redis -p 6379:6379 redis:7
//!
//! # Run the example
//! REDIS_URL=redis://localhost:6379 cargo run --example redis-cache
//!
//! # Store a secret
//! curl -X POST http://localhost:8080/cache/my-secret \
//!   -H 'Content-Type: application/json' \
//!   -d '{"value":"super-secret-api-key-12345","sensitive":true}'
//!
//! # Retrieve it (decrypted in the enclave)
//! curl http://localhost:8080/cache/my-secret
//!
//! # Check what Redis actually stores
//! redis-cli GET "cache:my-secret"
//! # → "enc:v1:..." (ciphertext, not the plaintext)
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
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

// ---------------------------------------------------------------------------
// Data model
// ---------------------------------------------------------------------------

#[derive(Encrypted, Serialize, Deserialize, Clone, Debug)]
struct CacheEntry {
    key: String,
    #[encrypt]
    value: String,
    sensitive: bool,
}

// ---------------------------------------------------------------------------
// TEE State
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Default, Clone, Debug)]
struct CacheStats {
    total_gets: u64,
    total_sets: u64,
    cache_hits: u64,
    cache_misses: u64,
}

#[derive(Serialize, Deserialize, Default, Clone, Debug)]
struct CacheConfig {
    max_entries: u32,
    default_ttl_secs: u64,
}

state! {
    #[mrenclave]
    CacheStats,

    #[mrsigner]
    CacheConfig,

    #[external]
    CacheEntry,
}

// ---------------------------------------------------------------------------
// Mock Redis (replace with real redis crate in production)
// ---------------------------------------------------------------------------

struct MockRedis {
    data: RwLock<HashMap<String, String>>,
}

impl MockRedis {
    fn new() -> Self {
        Self {
            data: RwLock::new(HashMap::new()),
        }
    }

    async fn set(&self, key: &str, value: &str) {
        self.data.write().await.insert(key.to_string(), value.to_string());
    }

    async fn get(&self, key: &str) -> Option<String> {
        self.data.read().await.get(key).cloned()
    }

    async fn del(&self, key: &str) -> bool {
        self.data.write().await.remove(key).is_some()
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct SetCacheRequest {
    value: String,
    #[serde(default)]
    sensitive: bool,
}

/// POST /cache/:key — store a value in the encrypted cache.
#[attest]
async fn set_cache(
    Extension(tee): Extension<Arc<RwLock<TeeState>>>,
    Extension(redis): Extension<Arc<MockRedis>>,
    Path(key): Path<String>,
    Json(body): Json<SetCacheRequest>,
) -> impl IntoResponse {
    let mut state = tee.write().await;
    state.enclave_mut().cache_stats.total_sets += 1;

    if body.sensitive {
        // Encrypt sensitive values before storing in Redis
        let entry = CacheEntry {
            key: key.clone(),
            value: body.value,
            sensitive: true,
        };
        let encrypted = match state.encrypt_cache_entry(&entry) {
            Ok(e) => e,
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": e.to_string()})),
                ).into_response()
            }
        };
        // Redis stores ciphertext
        redis.set(&format!("cache:{key}"), &encrypted.value).await;
        redis.set(&format!("meta:{key}"), "sensitive").await;
    } else {
        // Non-sensitive values stored as plaintext
        redis.set(&format!("cache:{key}"), &body.value).await;
        redis.set(&format!("meta:{key}"), "plain").await;
    }

    let _ = state.seal(std::path::Path::new("./sealed"));

    (
        StatusCode::CREATED,
        Json(serde_json::json!({
            "status": "stored",
            "key": key,
            "encrypted": body.sensitive,
        })),
    ).into_response()
}

/// GET /cache/:key — retrieve a value, decrypting if needed.
#[attest]
async fn get_cache(
    Extension(tee): Extension<Arc<RwLock<TeeState>>>,
    Extension(redis): Extension<Arc<MockRedis>>,
    Path(key): Path<String>,
) -> impl IntoResponse {
    let mut state = tee.write().await;
    state.enclave_mut().cache_stats.total_gets += 1;

    let raw_value = match redis.get(&format!("cache:{key}")).await {
        Some(v) => {
            state.enclave_mut().cache_stats.cache_hits += 1;
            v
        }
        None => {
            state.enclave_mut().cache_stats.cache_misses += 1;
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "Key not found"})),
            ).into_response()
        }
    };

    let meta = redis.get(&format!("meta:{key}")).await.unwrap_or_default();
    let is_sensitive = meta == "sensitive";

    let value = if is_sensitive {
        // Decrypt inside the enclave
        let encrypted = EncryptedCacheEntry {
            key: key.clone(),
            value: raw_value,
            sensitive: true,
        };
        match state.decrypt_cache_entry(&encrypted) {
            Ok(entry) => entry.value,
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": format!("Decryption failed: {e}")})),
                ).into_response()
            }
        }
    } else {
        raw_value
    };

    Json(serde_json::json!({
        "key": key,
        "value": value,
        "encrypted_at_rest": is_sensitive,
    })).into_response()
}

/// DELETE /cache/:key — remove from cache.
async fn delete_cache(
    Extension(redis): Extension<Arc<MockRedis>>,
    Path(key): Path<String>,
) -> impl IntoResponse {
    let deleted = redis.del(&format!("cache:{key}")).await;
    redis.del(&format!("meta:{key}")).await;
    Json(serde_json::json!({"deleted": deleted, "key": key}))
}

/// GET /stats — cache statistics.
async fn get_stats(
    Extension(tee): Extension<Arc<RwLock<TeeState>>>,
) -> Json<serde_json::Value> {
    let state = tee.read().await;
    let stats = state.enclave().cache_stats();
    Json(serde_json::json!({
        "total_gets": stats.total_gets,
        "total_sets": stats.total_sets,
        "cache_hits": stats.cache_hits,
        "cache_misses": stats.cache_misses,
        "hit_rate": if stats.total_gets > 0 {
            format!("{:.1}%", (stats.cache_hits as f64 / stats.total_gets as f64) * 100.0)
        } else {
            "N/A".to_string()
        },
    }))
}

async fn attestation_info(
    Extension(tee): Extension<Arc<RwLock<TeeState>>>,
) -> Json<serde_json::Value> {
    let state = tee.read().await;
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
    let redis = Arc::new(MockRedis::new());

    println!("Encrypted Redis Cache on port {port}");
    println!("  POST   /cache/:key  — store (sensitive values encrypted)");
    println!("  GET    /cache/:key  — retrieve (auto-decrypted in enclave)");
    println!("  DELETE /cache/:key  — remove");
    println!("  GET    /stats       — cache statistics");

    let app = Router::new()
        .route("/cache/:key", post(set_cache).get(get_cache).delete(delete_cache))
        .route("/stats", get(get_stats))
        .route("/.well-known/tee-attestation", get(attestation_info))
        .layer(Extension(Arc::new(RwLock::new(state))))
        .layer(Extension(redis));

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{port}"))
        .await
        .expect("Failed to bind");
    axum::serve(listener, app).await.expect("Server failed");
}
