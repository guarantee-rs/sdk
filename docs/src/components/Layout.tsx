import { useEffect } from "react";
import { Outlet, Link, useLocation } from "react-router-dom";

const PAGE_TITLES: Record<string, string> = {
  "getting-started": "Getting Started — Rust SGX Attestation in 5 min | Guarantee SDK",
  "how-it-works": "SGX Attestation Chain — DCAP, MRENCLAVE, Ed25519 | Guarantee SDK",
  "attestation": "Attestation Types — MrEnclave, StartupQuote, DCAP | Guarantee SDK",
  "state": "MRENCLAVE-Scoped State in Gramine Enclaves — state! macro | Guarantee SDK",
  "encryption": "AES-256-GCM Field Encryption in SGX Enclaves | Guarantee SDK",
  "sealing": "Enclave State Sealing — MRENCLAVE vs MRSIGNER | Guarantee SDK",
  "attest-macro": "#[attest] Macro — Per-Response Ed25519 Signing | Guarantee SDK",
  "state-macro": "state! Macro — Two-Tier Sealed State | Guarantee SDK",
  "encrypted-derive": "#[derive(Encrypted)] — AES-256-GCM Field Encryption | Guarantee SDK",
  "crypto": "Crypto Utilities — encrypt_field, derive_key, HKDF | Guarantee SDK",
  "enclave-attestor": "EnclaveAttestor API — Keypair, Quote, Signing | Guarantee SDK",
  "ra-tls": "RA-TLS for Rust — SGX Quote in TLS Certificate | Guarantee SDK",
  "errors": "SdkError Reference — Error Handling | Guarantee SDK",
  "hello-tee": "Hello TEE Example — Minimal Attested Service | Guarantee SDK",
  "oracle": "Price Oracle Example — Attested DeFi Feed | Guarantee SDK",
  "btc-signer": "Bitcoin Signer Example — SGX Key Custody | Guarantee SDK",
  "postgres-encrypted": "Encrypted Postgres Example — Field-Level AES | Guarantee SDK",
  "redis-cache": "Encrypted Redis Example — Selective Cache Encryption | Guarantee SDK",
  "websocket-ratls": "WebSocket RA-TLS Example — Attested Real-Time Streaming | Guarantee SDK",
  "verify": "Verify SGX Attestation — X-TEE-Attestation Header Checker | Guarantee",
};

export function Layout() {
  const { pathname } = useLocation();

  // Scroll to top on route change
  useEffect(() => {
    window.scrollTo(0, 0);
  }, [pathname]);

  // Page title
  useEffect(() => {
    if (pathname === "/") {
      document.title = "Guarantee — Rust SGX Attestation SDK for Gramine Enclaves";
    } else if (pathname === "/verify") {
      document.title = PAGE_TITLES["verify"];
    } else if (pathname.startsWith("/docs/")) {
      const slug = pathname.replace("/docs/", "");
      document.title = PAGE_TITLES[slug] || `${slug} | Guarantee SDK`;
    }
  }, [pathname]);

  const isHome = pathname === "/";

  return (
    <div className="container">
      <header className={`site-header${isHome ? " site-header-home" : ""}`}>
        <div className="header-top">
          <Link to="/" className="logo-text">
            Guarantee
          </Link>
          <nav className="header-nav mono">
            <Link to="/docs/getting-started" className={pathname.startsWith("/docs") ? "active" : ""}>
              Documentation
            </Link>
            <Link to="/verify" className={pathname === "/verify" ? "active" : ""}>
              Verify
            </Link>
            <a href="https://github.com/susruth/guarantee" target="_blank" rel="noopener noreferrer">
              GitHub ↗
            </a>
            <a href="https://crates.io/crates/guarantee" target="_blank" rel="noopener noreferrer">
              Crates.io ↗
            </a>
          </nav>
        </div>
        <div className="header-bottom">
          <span>Open Source Rust TEE Attestation SDK</span>
          <span>v0.1.2</span>
        </div>
      </header>

      <Outlet />

      <footer className="site-footer mono">
        <div>Guarantee SDK // 2025</div>
        <div className="footer-links">
          <Link to="/docs/getting-started">Documentation</Link>
          <Link to="/verify">Verify</Link>
          <a href="https://github.com/susruth/guarantee" target="_blank" rel="noopener noreferrer">
            GitHub ↗
          </a>
          <a href="https://crates.io/crates/guarantee" target="_blank" rel="noopener noreferrer">
            Crates.io ↗
          </a>
          <a href="https://guarantee.rs" target="_blank" rel="noopener noreferrer">
            guarantee.rs ↗
          </a>
          <a href="https://github.com/susruth/guarantee/blob/main/LICENSE" target="_blank" rel="noopener noreferrer">
            MIT License ↗
          </a>
        </div>
      </footer>
    </div>
  );
}
