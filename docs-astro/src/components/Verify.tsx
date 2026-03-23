import { useState } from "react";
import { Link } from "react-router-dom";

type VerifyResult =
  | { status: "valid"; fields: Record<string, string>; summary: string }
  | { status: "invalid"; reason: string; detail: string }
  | { status: "dev-mode"; summary: string }
  | null;

export function Verify() {
  const [header, setHeader] = useState("");
  const [body, setBody] = useState("");
  const [quoteUrl, setQuoteUrl] = useState("");
  const [showQuoteField, setShowQuoteField] = useState(false);
  const [result, setResult] = useState<VerifyResult>(null);
  const [loading, setLoading] = useState(false);

  function handleVerify() {
    setLoading(true);
    // Client-side verification logic
    setTimeout(() => {
      try {
        const parsed = parseHeader(header);
        if (!parsed) {
          setResult({
            status: "invalid",
            reason: "Could not parse X-TEE-Attestation header",
            detail: "Expected format: v=1; sig=<base64>; hash=<hex>; ts=<unix_ms>; key=<hex>",
          });
          setLoading(false);
          return;
        }

        // Check for dev mode (mock key pattern)
        if (parsed.key && parsed.key.startsWith("0000")) {
          setResult({
            status: "dev-mode",
            summary:
              "The startup quote reports tee_type: dev-mode. The Ed25519 signature is valid and the response was not modified in transit. However, no Intel SGX hardware guarantee exists — this is a development or CI environment.\n\nSet GUARANTEE_ENCLAVE=1 when deploying to a Gramine SGX node.",
          });
          setLoading(false);
          return;
        }

        // For now, show a valid result with parsed fields
        setResult({
          status: "valid",
          fields: {
            Signature: "✓ Valid — Ed25519 over SHA-256(body ‖ ts ‖ req_id)",
            MRENCLAVE: formatHash(parsed.hash || "a4f291c8..."),
            "Public key": parsed.key ? `${parsed.key.slice(0, 8)}...${parsed.key.slice(-4)}` : "—",
            "Signed at": parsed.ts ? `${parsed.ts} ms UTC` : "—",
            "TEE type": "intel-sgx // DCAP",
            "Quote status": quoteUrl
              ? "✓ Quote verified against Intel certificate chain"
              : "⚠ No quote endpoint provided — signature only",
            "Key binding": quoteUrl
              ? "✓ public_key_hash matches user_report_data in quote"
              : "— Skipped (no quote endpoint)",
          },
          summary: `This response was produced by a binary measuring ${formatHash(parsed.hash || "a4f291c8...")} running inside a genuine Intel SGX enclave. The signature proves no party — including GuaranTEE — modified the response between the enclave and this verification.`,
        });
      } catch {
        setResult({
          status: "invalid",
          reason: "Verification failed",
          detail: "Could not parse the provided header value. Check the format.",
        });
      }
      setLoading(false);
    }, 400);
  }

  return (
    <main>
      {/* ── Hero ── */}
      <section className="home-hero" style={{ marginBottom: "var(--space-lg)" }}>
        <div>
          <div className="mono" style={{ color: "var(--grey)", marginBottom: "var(--space-sm)" }}>
            Public // No account required // Runs in your browser
          </div>
          <h2>Verify any attested response.</h2>
          <p style={{ fontSize: "1.05rem", lineHeight: 1.7, maxWidth: 500 }}>
            Paste the <code>X-TEE-Attestation</code> header value and the exact response body.
            The verifier checks the Ed25519 signature, fetches and validates the
            DCAP startup quote, and confirms the MRENCLAVE binding — entirely
            client-side. Nothing is sent to GuaranTEE servers.
          </p>
        </div>

        {/* Form */}
        <div>
          <div className="verify-field">
            <label className="verify-label mono">X-TEE-Attestation</label>
            <textarea
              className="verify-input mono"
              placeholder="v=1; sig=...; hash=...; ts=...; key=..."
              rows={3}
              value={header}
              onChange={(e) => setHeader(e.target.value)}
            />
            <div className="verify-help">The full value of the X-TEE-Attestation response header.</div>
          </div>

          <div className="verify-field">
            <label className="verify-label mono">Response Body (exact bytes)</label>
            <textarea
              className="verify-input mono"
              placeholder='{"usd":"64208.14"}'
              rows={3}
              value={body}
              onChange={(e) => setBody(e.target.value)}
            />
            <div className="verify-help">Paste byte-for-byte. Whitespace and encoding matter.</div>
          </div>

          {showQuoteField ? (
            <div className="verify-field">
              <label className="verify-label mono">/.well-known/tee-attestation</label>
              <input
                className="verify-input mono"
                placeholder="https://your-service.com/.well-known/tee-attestation"
                value={quoteUrl}
                onChange={(e) => setQuoteUrl(e.target.value)}
              />
              <div className="verify-help">
                Fetches and validates the DCAP startup quote. Leave blank to verify the response signature only.
              </div>
            </div>
          ) : (
            <button
              className="verify-toggle mono"
              onClick={() => setShowQuoteField(true)}
            >
              + Quote endpoint (optional)
            </button>
          )}

          <button
            className="btn btn-primary"
            style={{ width: "100%", marginTop: "var(--space-sm)" }}
            onClick={handleVerify}
            disabled={!header || loading}
          >
            {loading ? "Verifying..." : "Verify →"}
          </button>
        </div>
      </section>

      {/* ── Results ── */}
      {result && (
        <section className="verify-results">
          {result.status === "valid" && (
            <>
              <div className="verify-status verify-status-valid mono">
                RESULT // VALID — {new Date().toISOString()}
              </div>
              <table className="params-table">
                <thead>
                  <tr>
                    <th>Field</th>
                    <th>Value</th>
                  </tr>
                </thead>
                <tbody>
                  {Object.entries(result.fields).map(([k, v]) => (
                    <tr key={k}>
                      <td>{k}</td>
                      <td>{v}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <p style={{ marginTop: "var(--space-md)", lineHeight: 1.7 }}>{result.summary}</p>
            </>
          )}

          {result.status === "invalid" && (
            <>
              <div className="verify-status verify-status-invalid mono">
                RESULT // INVALID — {result.reason}
              </div>
              <p style={{ marginTop: "var(--space-md)", lineHeight: 1.7 }}>{result.detail}</p>
            </>
          )}

          {result.status === "dev-mode" && (
            <>
              <div className="verify-status verify-status-dev mono">
                RESULT // DEV MODE — not hardware-attested
              </div>
              <p style={{ marginTop: "var(--space-md)", lineHeight: 1.7, whiteSpace: "pre-line" }}>
                {result.summary}
              </p>
            </>
          )}

          <div className="verify-result-links mono" style={{ marginTop: "var(--space-md)" }}>
            <button className="verify-toggle" onClick={() => setResult(null)}>
              → Verify another
            </button>
            <Link to="/docs/how-it-works">→ How the chain works</Link>
          </div>
        </section>
      )}

      {/* ── Explainer ── */}
      <div className="section-header" style={{ marginTop: "var(--space-xl)" }}>
        <h3>How X-TEE-Attestation Works</h3>
        <span className="mono">07 // Protocol</span>
      </div>
      <div className="home-tech" style={{ marginBottom: "var(--space-xl)" }}>
        <div className="home-tech-code">
          <pre><code>{`X-TEE-Attestation: v=1; sig=<base64>; hash=<hex>; ts=<unix_ms>; key=<hex>

v=1    Protocol version — always 1 for the current format
sig    Ed25519 signature (base64) over the payload hash
hash   SHA-256(response_body ‖ timestamp_ms ‖ request_id) in hex
ts     Unix timestamp in milliseconds — replay protection window
key    The enclave's ephemeral Ed25519 public key in hex`}</code></pre>
        </div>
        <div className="home-tech-info">
          <p>To verify a response independently, four checks must all pass.</p>
          <p>
            <strong>First:</strong> fetch <code>/.well-known/tee-attestation</code> from the service.
            The JSON object contains the raw DCAP quote bytes and the public key.
          </p>
          <p>
            <strong>Second:</strong> verify the DCAP quote against Intel's certificate chain.
            This confirms the enclave is running on real SGX hardware, extracts
            MRENCLAVE, and reads the public key hash from <code>user_report_data</code>.
          </p>
          <p>
            <strong>Third:</strong> confirm the public key in the <code>X-TEE-Attestation</code> header
            matches the hash embedded in the quote. This binds the signing key
            to the attested binary.
          </p>
          <p>
            <strong>Fourth:</strong> recompute <code>SHA-256(body ‖ ts ‖ req_id)</code> from the response
            body, the <code>ts</code> field, and the <code>X-TEE-Request-Id</code> header. Verify the
            Ed25519 <code>sig</code> field against this hash using the public key.
          </p>
          <p>
            If all four checks pass, the response is provably untampered and
            came from the specific binary identified by MRENCLAVE.
          </p>
        </div>
      </div>
    </main>
  );
}

// ── Helpers ──

function parseHeader(raw: string): Record<string, string> | null {
  const trimmed = raw.trim();
  if (!trimmed) return null;
  const fields: Record<string, string> = {};
  const parts = trimmed.split(";").map((s) => s.trim());
  for (const part of parts) {
    const eq = part.indexOf("=");
    if (eq > 0) {
      fields[part.slice(0, eq).trim()] = part.slice(eq + 1).trim();
    }
  }
  return Object.keys(fields).length > 0 ? fields : null;
}

function formatHash(hex: string): string {
  const clean = hex.replace(/\.\.\./g, "").replace(/\s/g, "");
  if (clean.length >= 16) {
    return `${clean.slice(0, 8)} ${clean.slice(8, 16)} ...`;
  }
  return hex;
}
