import { Link } from "react-router-dom";

export function Home() {
  return (
    <main>
      {/* ── Hero ── */}
      <section className="home-hero">
        <div className="home-hero-text">
          <h2>Prove your code runs where you say it runs.</h2>
          <p>
            Add <code>#[attest]</code> to any axum handler. Guarantee generates an Ed25519 keypair
            inside the enclave, binds it to the enclave measurement with an SGX DCAP
            quote, and signs every response. Callers verify the full chain — hardware
            to JSON — without trusting you, your servers, or GuaranTEE.
          </p>
          <div className="btn-group">
            <Link to="/docs/getting-started" className="btn btn-primary">Get Started</Link>
            <Link to="/docs/how-it-works" className="btn btn-outline">How It Works</Link>
          </div>
          <a href="https://guarantee.rs" target="_blank" rel="noopener noreferrer" className="home-tertiary-link">
            Managed deployment → guarantee.rs ↗
          </a>
        </div>
        <div className="home-hero-terminal">
          <div className="home-hero-terminal-bar">
            <span className="home-hero-terminal-dot" />
            <span className="home-hero-terminal-dot" />
            <span className="home-hero-terminal-dot" />
          </div>
          <pre className="home-hero-terminal-body"><code>{`$ curl -i https://oracle.example.com/price

HTTP/2 200
x-tee-attestation: v=1; sig=mFz3...rK9=;
  hash=a4f2...91c; ts=1743724800;
  key=04ab...f3
x-tee-verified: true
x-tee-request-id: 7a3b...e91f

{"symbol":"BTC","price":67432.50}`}</code></pre>
        </div>
      </section>

      {/* ── 01 Core Principles ── */}
      <div className="section-header">
        <h3>Core Principles</h3>
        <span className="mono">01 // Architecture</span>
      </div>
      <div className="home-grid-3">
        <div className="home-grid-item">
          <h3>Hardware Attestation</h3>
          <p>Every response is signed with an ephemeral Ed25519 key. The key is bound to the exact binary measurement (MRENCLAVE) via an Intel SGX DCAP quote. Any caller verifies the chain independently — no trust in the operator required.</p>
        </div>
        <div className="home-grid-item">
          <h3>Sealed State</h3>
          <p>Two-tier encrypted persistence. MRENCLAVE state resets on redeploy — correct for caches and ephemeral sessions. MRSIGNER state survives binary updates — correct for private keys and long-lived configuration.</p>
        </div>
        <div className="home-grid-item">
          <h3>Zero Conditional Compilation</h3>
          <p>The same binary runs in dev mode on a laptop and inside a Gramine SGX enclave in production. No <code>#[cfg(feature = "sgx")]</code>. No hardware needed to develop or test. Set <code>GUARANTEE_ENCLAVE=1</code> at deploy time.</p>
        </div>
      </div>

      {/* ── 02 Quickstart ── */}
      <div className="section-header">
        <h3>Implementation</h3>
        <span className="mono">02 // Quickstart</span>
      </div>
      <div className="home-tech">
        <div className="home-tech-info">
          <p>
            Install the crate. Annotate any axum handler with <code>#[attest]</code>. On first request,
            the SDK reads the DCAP quote from <code>/dev/attestation</code>, extracts MRENCLAVE, and
            binds the ephemeral signing key. Every subsequent response carries a verifiable
            signature. No other changes to your service.
          </p>
          <div className="install-box">
            <span>$ cargo add guarantee</span>
            <span className="install-box-copy" onClick={() => navigator.clipboard.writeText("cargo add guarantee")}>[COPY]</span>
          </div>
          <div className="install-box">
            <span>$ cargo run --example hello-tee</span>
            <span className="install-box-copy" onClick={() => navigator.clipboard.writeText("cargo run --example hello-tee")}>[COPY]</span>
          </div>
        </div>
        <div className="home-tech-code">
          <pre><code>{`// Attested axum service — full SGX chain in ~20 lines
use guarantee::{attest, state};
use axum::{response::Json, routing::get, Router};

state! {
    // Resets on redeploy (new binary = new measurement)
    #[mrenclave]
    AppData,
}

// One attribute. Every response gets X-TEE-Attestation.
#[attest]
async fn hello() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "message": "hello from TEE" }))
}

#[tokio::main]
async fn main() {
    let state = TeeState::initialize(Path::new("./sealed")).unwrap();
    let app = Router::new()
        .route("/hello", get(hello))
        .layer(Extension(Arc::new(RwLock::new(state))));

    // curl response includes:
    // X-TEE-Attestation: v=1; sig=...; hash=...; ts=...; key=...
    axum::serve(listener, app).await.unwrap();
}`}</code></pre>
        </div>
      </div>

      {/* ── 03 How It Works ── */}
      <div className="section-header">
        <h3>Attestation Chain</h3>
        <span className="mono">03 // How It Works</span>
      </div>
      <div className="home-steps">
        {[
          ["01", "Key Generation", "At startup, the SDK generates an ephemeral Ed25519 keypair entirely inside enclave memory. The private key is never serialised, never logged, and never leaves the enclave boundary."],
          ["02", "DCAP Quote", "The SDK writes SHA-256(public_key) to /dev/attestation/user_report_data and reads back an Intel DCAP quote. The quote cryptographically binds MRENCLAVE + MRSIGNER to that specific key."],
          ["03", "Response Signed", "#[attest] signs SHA-256(body ‖ timestamp_ms ‖ request_id) with the enclave key on every response. The signature and public key are attached as X-TEE-Attestation."],
          ["04", "Independent Verification", "Any caller fetches /.well-known/tee-attestation once, verifies the DCAP quote against Intel hardware, then checks every response signature. No trust in GuaranTEE or the operator required."],
        ].map(([num, title, text]) => (
          <div className="home-step" key={num}>
            <div className="home-step-num">{num}</div>
            <h4>{title}</h4>
            <p>{text}</p>
          </div>
        ))}
      </div>

      {/* ── 04 API Surface ── */}
      <div className="section-header">
        <h3>API Surface</h3>
        <span className="mono">04 // Reference</span>
      </div>
      <table className="home-api-table">
        <thead>
          <tr><th>Export</th><th>Description</th></tr>
        </thead>
        <tbody>
          {[
            ["#[attest]", "Attribute macro — signs every response with the enclave key"],
            ["state! { }", "Declares two-tier sealed state with auto-generated accessors"],
            ["#[derive(Encrypted)]", "Generates encrypted struct variant with AES-256-GCM"],
            ["EnclaveAttestor", "Core struct — keypair, startup quote, response signing"],
            ["MrEnclave / MrSigner", "32-byte enclave identity value types"],
            ["StartupQuote", "SGX DCAP quote binding key to enclave measurement"],
            ["AttestationHeader", "Per-response signature — parse with from_header_value()"],
            ["seal_to_file()", "Low-level sealing to disk (MRENCLAVE or MRSIGNER mode)"],
            ["encrypt_field()", "AES-256-GCM field encryption with optional key versioning"],
            ["derive_key()", "HKDF-SHA256 purpose-specific key derivation"],
            ["serve_ra_tls()", "HTTPS server with attestation-embedded X.509 certificates"],
            ["gramine::write_user_report_data()", "Write 64 bytes to /dev/attestation/user_report_data"],
            ["gramine::read_quote()", "Read the raw DCAP quote from /dev/attestation/quote"],
            ["guarantee::connect()", "RA-TLS client — verifies remote enclave before connecting (feature: ra-tls)"],
          ].map(([exp, desc], i) => (
            <tr key={i}><td>{exp}</td><td>{desc}</td></tr>
          ))}
        </tbody>
      </table>

      {/* ── 05 Examples ── */}
      <div className="section-header">
        <h3>Examples</h3>
        <span className="mono">05 // Use Cases</span>
      </div>
      <div className="home-examples">
        {[
          ["hello-tee", "Starter", "Hello TEE", "The minimum viable attested service. One handler, one #[attest], the full SGX attestation chain. Start here."],
          ["oracle", "DeFi", "Price Oracle", "MRENCLAVE-scoped state with background price updates. Every price response is signed — consumers verify without calling a price feed contract."],
          ["btc-signer", "Custody", "Bitcoin Signer", "MRSIGNER-sealed private key custody. The key survives binary updates but never leaves enclave memory. No HSM required."],
          ["postgres-encrypted", "Database", "Encrypted Postgres", "AES-256-GCM field encryption before INSERT. The database stores only ciphertext. Keys are derived from the enclave master key and never written to disk in plaintext."],
          ["redis-cache", "Cache", "Encrypted Redis", "Selective field encryption for cache values. Sensitive fields encrypted with per-key derivation. Queryable fields left in plaintext. Zero change to Redis configuration."],
          ["websocket-ratls", "Streaming", "WebSocket RA-TLS", "Real-time attested data streaming. WebSocket over RA-TLS — the entire channel is authenticated to the enclave with zero per-message overhead."],
        ].map(([slug, tag, title, desc]) => (
          <Link to={`/docs/${slug}`} className="home-example-card" key={slug}>
            <span className="home-example-tag">{tag}</span>
            <h4>{title}</h4>
            <p>{desc}</p>
          </Link>
        ))}
      </div>

      {/* ── 06 Configuration ── */}
      <div className="section-header">
        <h3>Configuration</h3>
        <span className="mono">06 // Environment</span>
      </div>
      <div className="home-config">
        {[
          ["GUARANTEE_ENCLAVE=1", "Enclave mode. Reads /dev/attestation/* for real SGX DCAP quotes. Requires Gramine. Unset for dev mode."],
          ["(unset)", "Dev mode. Mock quote with 0xDE fill bytes. Same API surface, real Ed25519 signatures, no hardware required. Use in CI."],
          ["GUARANTEE_ATTEST_MODE=startup-only", "Disables per-response signing. Startup quote still generated. Use when callers only need MRENCLAVE, not response provenance."],
          ["PORT", "HTTP listen port. Defaults to 8080. Used by all examples."],
        ].map(([k, v], i) => (
          <div className="home-config-item" key={i}>
            <div className="home-config-key">{k}</div>
            <div className="home-config-val">{v}</div>
          </div>
        ))}
      </div>

      {/* ── Managed platform CTA ── */}
      <div className="home-platform-cta">
        <span>Want managed enclave deployment?</span>
        <a href="https://guarantee.rs" target="_blank" rel="noopener noreferrer" className="mono">
          guarantee.rs ↗
        </a>
      </div>
    </main>
  );
}
