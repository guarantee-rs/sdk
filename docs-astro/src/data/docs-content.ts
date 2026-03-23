export interface Section {
  heading?: string;
  text?: string;
  code?: string;
  lang?: string;
  table?: { headers: string[]; rows: string[][] };
  list?: string[];
}

export interface DocEntry {
  slug: string;
  title: string;
  lead: string;
  section: string;
  body: Section[];
}

export const docs: DocEntry[] = [
  // =========================================================================
  // SECTION: Introduction
  // =========================================================================
  {
    slug: "getting-started",
    title: "Getting Started",
    lead: "Install the Guarantee SDK and run your first attested handler in under five minutes.",
    section: "Introduction",
    body: [
      {
        heading: "Installation",
        text: "Add the guarantee crate to your project. The SDK works with any axum-based Rust web service.",
        code: `[dependencies]
guarantee = "0.1.2"

# Required peer dependencies
axum = "0.7"
tokio = { version = "1", features = ["full"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"`,
        lang: "toml",
      },
      {
        heading: "Minimal Example",
        text: "The smallest possible attested service. The #[attest] macro wraps your handler so every response includes an X-TEE-Attestation header with an Ed25519 signature.",
        code: `use axum::{extract::Extension, response::Json, routing::get, Router};
use guarantee::{attest, state};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;

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

#[tokio::main]
async fn main() {
    let state = TeeState::initialize(std::path::Path::new("./sealed"))
        .expect("Failed to initialize TeeState");

    let app = Router::new()
        .route("/hello", get(hello))
        .layer(Extension(Arc::new(RwLock::new(state))));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080")
        .await
        .expect("Failed to bind");
    axum::serve(listener, app).await.expect("Server failed");
}`,
        lang: "rust",
      },
      {
        heading: "Dev Mode vs Enclave Mode",
        text: "The SDK works in two modes. Dev mode runs on any machine without SGX hardware. Enclave mode activates real SGX attestation when deployed inside a Gramine enclave.",
        table: {
          headers: ["", "Dev Mode", "Enclave Mode"],
          rows: [
            ["Activation", "Default (no env var)", "Set GUARANTEE_ENCLAVE=1"],
            ["Startup quote", "Mock (0xDE fill bytes)", "Real DCAP quote from /dev/attestation"],
            ["MRENCLAVE", "0xdededede... (placeholder)", "Actual binary measurement from SGX"],
            ["Signing key", "Ephemeral Ed25519 (random)", "Ephemeral Ed25519 (random)"],
            ["Per-response signatures", "Real Ed25519 signatures", "Real Ed25519 signatures"],
            ["Sealing", "Plaintext files with header prefix", "Gramine Protected Files (encrypted)"],
            ["Encryption", "AES-256-GCM (identical)", "AES-256-GCM (identical)"],
            ["Use case", "Local development, CI testing", "Production deployment"],
          ],
        },
      },
      {
        heading: "Environment Variables",
        table: {
          headers: ["Variable", "Values", "Description"],
          rows: [
            ["GUARANTEE_ENCLAVE", "1", "Activates real SGX /dev/attestation calls. Unset for dev mode."],
            ["GUARANTEE_ATTEST_MODE", "startup-only", "Only produce the startup quote; skip per-response signatures."],
            ["PORT", "Any port number", "Convention used by examples to set the HTTP listen port."],
          ],
        },
      },
      {
        heading: "Running the Example",
        text: "Clone the repository and run the hello-tee example. No SGX hardware is needed for dev mode.",
        code: `# Run the example
cargo run --example hello-tee

# In another terminal, test it
curl -v http://localhost:8080/hello

# Check the attestation endpoint
curl http://localhost:8080/.well-known/tee-attestation`,
        lang: "bash",
      },
    ],
  },
  {
    slug: "how-it-works",
    title: "How It Works",
    lead: "The full attestation chain: from SGX hardware to verified HTTP responses.",
    section: "Introduction",
    body: [
      {
        heading: "Overview",
        text: "Guarantee creates an unbroken cryptographic chain from Intel SGX hardware to every individual HTTP response. This chain has four links, each building on the previous one. A client can verify the entire chain independently, proving that a response was produced by a specific binary running inside a genuine SGX enclave.",
      },
      {
        heading: "Step 1: Enclave Key Generation",
        text: "At startup, the SDK generates a fresh ephemeral Ed25519 signing keypair. The private key exists only in enclave memory and is never serialized to disk or transmitted over the network. It is sealed with MRENCLAVE scope, meaning only the exact same binary can unseal it after a restart.\n\nThe public key becomes the enclave's identity for this deployment. All subsequent steps bind to this key.",
        code: `// Generated automatically by TeeState::initialize()
// The signing key lives inside EnclaveState (MRENCLAVE-sealed)
let signing_key = ed25519_dalek::SigningKey::generate(&mut OsRng);
let public_key = signing_key.verifying_key();`,
        lang: "rust",
      },
      {
        heading: "Step 2: Startup Attestation Quote",
        text: "The SDK writes a SHA-256 hash of the public key to /dev/attestation/user_report_data (64 bytes, hash in the first 32 bytes). It then reads back /dev/attestation/quote, which returns a DCAP attestation quote signed by Intel SGX hardware.\n\nThis quote cryptographically binds three values together:\n- MRENCLAVE: the exact binary measurement (SHA-256 of all enclave pages)\n- MRSIGNER: the hash of the signing key used to sign the enclave\n- The Ed25519 public key hash (via user_report_data)\n\nThe quote is served at GET /.well-known/tee-attestation so any client can fetch and verify it against Intel's DCAP infrastructure.",
        code: `// What /dev/attestation operations look like internally:
// 1. Write public key hash to user_report_data
let mut user_data = [0u8; 64];
let hash = Sha256::digest(pub_key.as_bytes());
user_data[..32].copy_from_slice(&hash);
gramine::write_user_report_data(&user_data)?;

// 2. Read the DCAP quote
let raw_quote = gramine::read_quote()?;`,
        lang: "rust",
      },
      {
        heading: "Step 3: Per-Response Signing",
        text: "Every handler annotated with #[attest] automatically signs its response. The payload hash is computed as:\n\nSHA-256(response_body || timestamp_ms_big_endian || request_id_utf8)\n\nThe Ed25519 signature over this hash is attached as the X-TEE-Attestation header. Two additional headers are also set:\n- X-TEE-Verified: true\n- X-TEE-Request-Id: <uuid>",
        code: `// Header format:
// X-TEE-Attestation: v=1; sig=<base64>; hash=<hex>; ts=<unix_ms>; key=<hex>

// The #[attest] macro does this automatically:
let header = state.sign_response(&body_bytes, &request_id);`,
        lang: "rust",
      },
      {
        heading: "Step 4: Client Verification",
        text: "A client verifies a response in three steps:\n\n1. Fetch the startup quote from GET /.well-known/tee-attestation. Verify it against Intel DCAP to confirm the enclave is genuine. Record the public_key field.\n\n2. For each response, parse the X-TEE-Attestation header. Recompute the payload hash from the response body, timestamp (ts), and request ID (X-TEE-Request-Id header).\n\n3. Verify the Ed25519 signature (sig) against the payload hash using the public key from step 1. If it matches, the response provably came from the attested enclave.",
      },
      {
        heading: "Trust Chain Diagram",
        text: "The complete trust chain flows from hardware to individual responses:",
        code: `Intel SGX Hardware (root of trust)
  |
  +-- signs the DCAP quote
        |
        +-- quote embeds: MRENCLAVE + MRSIGNER + public_key_hash
              |
              +-- public_key signs every HTTP response body
                    |
                    +-- X-TEE-Attestation header = Ed25519(SHA-256(body || ts || req_id))`,
        lang: "text",
      },
      {
        heading: "Attestation Endpoint Response",
        text: "The /.well-known/tee-attestation endpoint returns a JSON object with the following fields:",
        table: {
          headers: ["Field", "Type", "Description"],
          rows: [
            ["public_key", "hex string", "The enclave's ephemeral Ed25519 public key"],
            ["quote", "base64 string or null", "Raw DCAP quote bytes (base64-encoded)"],
            ["mr_enclave", "hex string or null", "Enclave code measurement (32 bytes, hex)"],
            ["mr_signer", "hex string or null", "Signing key measurement (32 bytes, hex)"],
            ["tee_type", "string", "\"intel-sgx\" in enclave mode, \"dev-mode\" otherwise"],
            ["produced_at", "RFC 3339 string or null", "Quote generation timestamp"],
          ],
        },
      },
    ],
  },

  // =========================================================================
  // SECTION: Concepts
  // =========================================================================
  {
    slug: "attestation",
    title: "Attestation",
    lead: "Core attestation concepts: measurements, quotes, signatures, and the .well-known endpoint.",
    section: "Concepts",
    body: [
      {
        heading: "MRENCLAVE",
        text: "MRENCLAVE is a 32-byte SHA-256 hash computed by SGX hardware over every page of the enclave binary at load time. It uniquely identifies the exact code running inside the enclave. If you change a single line of source code, a compiler flag, or a dependency version, MRENCLAVE changes.\n\nIn the SDK, MRENCLAVE-scoped state (declared with #[mrenclave] in the state! macro) resets on every redeploy because a new binary produces a different MRENCLAVE, making the old sealed data inaccessible.",
        code: `use guarantee::MrEnclave;

let bytes = [0xAB_u8; 32];
let mr = MrEnclave::new(bytes);
println!("MRENCLAVE: {mr}"); // lowercase hex, 64 characters
assert_eq!(mr.as_bytes(), &bytes);`,
        lang: "rust",
      },
      {
        heading: "MRSIGNER",
        text: "MRSIGNER is a 32-byte hash of the RSA key used to sign the enclave with gramine-sgx-sign. Unlike MRENCLAVE, it does not change when the binary is updated -- only when the signing key changes. This makes MRSIGNER ideal for sealing state that must survive across redeployments.\n\nIn the SDK, MRSIGNER-scoped state (declared with #[mrsigner]) persists across redeploys as long as the same signing key is used. This is where long-lived secrets like master encryption keys and private keys are stored.",
        code: `use guarantee::MrSigner;

let bytes = [0xCD_u8; 32];
let mr = MrSigner::new(bytes);
println!("MRSIGNER: {mr}"); // lowercase hex, 64 characters`,
        lang: "rust",
      },
      {
        heading: "StartupQuote",
        text: "A StartupQuote is the SGX DCAP attestation quote produced at enclave startup. It cryptographically binds the enclave's identity (MRENCLAVE + MRSIGNER) to the ephemeral Ed25519 public key generated by the SDK. The quote is signed by Intel SGX hardware and can be verified against Intel's DCAP infrastructure.\n\nThe quote is produced by writing the public key hash to /dev/attestation/user_report_data and reading back /dev/attestation/quote. In dev mode, a mock quote with 0xDE fill bytes is returned instead.",
        code: `use guarantee::StartupQuote;

// StartupQuote fields:
pub struct StartupQuote {
    pub raw_quote: Vec<u8>,              // Raw DCAP quote bytes
    pub mr_enclave: MrEnclave,           // Binary measurement
    pub mr_signer: MrSigner,             // Signing key measurement
    pub attested_public_key: VerifyingKey, // Ed25519 public key
    pub produced_at: DateTime<Utc>,       // When the quote was generated
}`,
        lang: "rust",
      },
      {
        heading: "AttestationHeader",
        text: "Every response from an #[attest]-annotated handler includes the X-TEE-Attestation header. This header contains an Ed25519 signature over the response body, a timestamp, and the request ID.",
        code: `// Header format:
// X-TEE-Attestation: v=1; sig=<base64>; hash=<hex>; ts=<unix_ms>; key=<hex>

// Parsing the header:
use guarantee::AttestationHeader;

let raw = "v=1; sig=abc=; hash=deadbeef; ts=1700000000000; key=0102";
let header = AttestationHeader::from_header_value(raw)?;
println!("Version: {}", header.version);
println!("Timestamp: {}ms", header.timestamp_ms);
println!("Public key: {}", header.public_key_hex);`,
        lang: "rust",
      },
      {
        heading: "AttestationHeader Fields",
        table: {
          headers: ["Field", "Format", "Description"],
          rows: [
            ["v", "Integer", "Header schema version (currently always 1)"],
            ["sig", "Base64", "Ed25519 signature over the payload hash"],
            ["hash", "Hex", "SHA-256(body || timestamp_ms_be || request_id)"],
            ["ts", "Integer", "Unix timestamp in milliseconds when signed"],
            ["key", "Hex", "Ed25519 public key (matches startup quote)"],
          ],
        },
      },
      {
        heading: "The .well-known Endpoint",
        text: "Every Guarantee service should expose GET /.well-known/tee-attestation. This endpoint serves the startup attestation data as JSON, allowing clients to verify the enclave before making attested requests.\n\nThe endpoint is not added automatically -- you must register the route yourself. This is by design, so you retain full control over your routing.",
        code: `async fn attestation_info(
    Extension(state): Extension<Arc<RwLock<TeeState>>>,
) -> Json<serde_json::Value> {
    let s = state.read().await;
    Json(s.attestation_json())
}

let app = Router::new()
    .route("/.well-known/tee-attestation", get(attestation_info))
    .layer(Extension(Arc::new(RwLock::new(state))));`,
        lang: "rust",
      },
      {
        heading: "AttestationMode",
        text: "The SDK supports two attestation modes. EveryResponse (default) signs every HTTP response. StartupOnly only produces the startup quote and skips per-response signing, reducing overhead for latency-sensitive workloads.\n\nSet the mode via the GUARANTEE_ATTEST_MODE environment variable, or programmatically:",
        code: `use guarantee::{EnclaveAttestor, AttestationMode};

// From environment variable:
// GUARANTEE_ATTEST_MODE=startup-only
let attestor = EnclaveAttestor::initialize().await?;

// Or programmatically:
let attestor = EnclaveAttestor::initialize_with_mode(
    AttestationMode::StartupOnly
).await?;`,
        lang: "rust",
      },
    ],
  },
  {
    slug: "state",
    title: "TEE State",
    lead: "The state! macro: three tiers of sealed and encrypted state with automatic key management.",
    section: "Concepts",
    body: [
      {
        heading: "Overview",
        text: "The state! macro declares your application's TEE state. It generates a TeeState struct that manages key generation, sealing, attestation, and encryption automatically. State is organized into three tiers based on how it should be persisted and protected.",
      },
      {
        heading: "Three Tiers of State",
        table: {
          headers: ["Tier", "Attribute", "Sealed With", "Survives Redeploy", "Use Cases"],
          rows: [
            ["MRENCLAVE", "#[mrenclave]", "Binary measurement", "No -- resets on new binary", "Session data, caches, ephemeral counters, signing keys"],
            ["MRSIGNER", "#[mrsigner]", "Signing key hash", "Yes -- same signing key", "Private keys, master encryption keys, API keys, config"],
            ["External", "#[external]", "N/A (encrypted for DB)", "Yes -- stored externally", "User records, audit logs, any data in PostgreSQL/Redis"],
          ],
        },
      },
      {
        heading: "Basic Usage",
        text: "Each tier is declared with an attribute followed by one or more type names. All types must implement Serialize, Deserialize, Default, Clone, and Debug.",
        code: `use guarantee::state;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Default, Clone, Debug)]
struct SessionData {
    request_count: u64,
}

#[derive(Serialize, Deserialize, Default, Clone, Debug)]
struct MasterConfig {
    api_key: String,
}

state! {
    #[mrenclave]
    SessionData,

    #[mrsigner]
    MasterConfig,
}`,
        lang: "rust",
      },
      {
        heading: "Generated TeeState API",
        text: "The state! macro generates several types and methods. The main type is TeeState, which wraps EnclaveState (MRENCLAVE tier) and SignerState (MRSIGNER tier).",
        list: [
          "TeeState::initialize(seal_dir) -- Load or create sealed state from the given directory",
          "state.seal(seal_dir) -- Persist current state to disk",
          "state.enclave() / state.enclave_mut() -- Access MRENCLAVE-scoped state",
          "state.signer() / state.signer_mut() -- Access MRSIGNER-scoped state",
          "state.sign_response(body, request_id) -- Sign a response (used by #[attest])",
          "state.attestation_json() -- Get startup attestation JSON for the .well-known endpoint",
          "state.public_key() -- Get the Ed25519 verifying key",
          "state.check_rotation() -- Check if master key rotation is due",
          "state.rotate_master_key() -- Manually rotate the master key",
          "state.backup(seal_dir, backup_dir) -- Copy sealed files to a backup directory",
          "TeeState::restore(backup_dir, seal_dir) -- Restore from backup",
        ],
      },
      {
        heading: "Accessing State Fields",
        text: "Field names are derived from type names using snake_case conversion. For example, PriceCache becomes price_cache. Accessor methods are generated on both EnclaveState and SignerState.",
        code: `state! {
    #[mrenclave]
    PriceCache,

    #[mrsigner]
    OracleConfig,
}

// Generated accessors:
let state = TeeState::initialize(Path::new("./sealed"))?;
let cache: &PriceCache = state.enclave().price_cache();
let config: &OracleConfig = state.signer().oracle_config();

// Mutable access:
state.enclave_mut().price_cache.request_count += 1;
state.signer_mut().oracle_config.api_key = "new-key".into();`,
        lang: "rust",
      },
      {
        heading: "External Types and Encryption",
        text: "Types listed under #[external] must additionally derive Encrypted and annotate sensitive fields with #[encrypt]. The state! macro generates encrypt_<type>() and decrypt_<type>() methods on TeeState that use the MRSIGNER-bound master key for encryption.",
        code: `use guarantee::{state, Encrypted, crypto::Encryptable};

#[derive(Encrypted, Serialize, Deserialize, Clone, Debug)]
struct UserRecord {
    user_id: String,
    #[encrypt]
    ssn: String,
    email: String,
}

state! {
    #[mrenclave]
    SessionData,

    #[mrsigner]
    AppConfig,

    #[external]
    UserRecord,
}

// Generated methods on TeeState:
let encrypted = state.encrypt_user_record(&record)?;  // -> EncryptedUserRecord
let decrypted = state.decrypt_user_record(&encrypted)?; // -> UserRecord`,
        lang: "rust",
      },
      {
        heading: "Auto-Generated Keys",
        text: "The state! macro automatically generates and manages two cryptographic keys:\n\n1. An Ed25519 signing key (in EnclaveState, MRENCLAVE-bound) -- used for per-response attestation signatures. This key resets on every redeploy.\n\n2. A 256-bit AES master key (in SignerState, MRSIGNER-bound) -- used for encrypting #[external] data. This key persists across redeploys and supports automatic rotation.",
      },
      {
        heading: "Key Rotation",
        text: "The master encryption key supports automatic rotation. When rotated, the old key is moved to a retired_keys list so that data encrypted with the old key can still be decrypted. The default rotation interval is 90 days.",
        code: `// Check if rotation is due (call periodically)
if state.check_rotation()? {
    println!("Key rotated to version {}", state.signer().current_key_version);
    state.seal(Path::new("./sealed"))?;
}

// Or rotate manually
state.rotate_master_key()?;
state.seal(Path::new("./sealed"))?;`,
        lang: "rust",
      },
      {
        heading: "Schema Versioning",
        text: "You can version your state schemas to handle migrations when adding new fields. New fields receive their Default value automatically.",
        code: `state! {
    #[mrenclave(version = 2)]
    SessionData,

    #[mrsigner(version = 3)]
    MasterConfig,
}

// When TeeState::initialize() loads state with an older schema_version,
// it logs a warning, updates the version, and re-seals. New fields
// added since the last version will have their Default values.`,
        lang: "rust",
      },
    ],
  },
  {
    slug: "encryption",
    title: "Field-Level Encryption",
    lead: "Encrypt individual struct fields with AES-256-GCM before storing them in external databases.",
    section: "Concepts",
    body: [
      {
        heading: "Overview",
        text: "When you store data in an external database (PostgreSQL, Redis, etc.), sensitive fields should be encrypted so the database never sees plaintext. The Guarantee SDK provides field-level encryption using AES-256-GCM with HKDF-SHA256 key derivation.\n\nThe encryption key is the master_key stored in MRSIGNER-sealed state. It never leaves the enclave. The database only ever stores ciphertext for annotated fields.",
      },
      {
        heading: "#[derive(Encrypted)] and #[encrypt]",
        text: "Annotate your struct with #[derive(Encrypted)] and mark sensitive fields with #[encrypt]. The macro generates an Encrypted<Name> struct where #[encrypt] fields are stored as ciphertext strings. Non-annotated fields are copied as-is.",
        code: `use guarantee::{Encrypted, crypto::Encryptable};
use serde::{Serialize, Deserialize};

#[derive(Encrypted, Serialize, Deserialize, Clone, Debug)]
struct UserRecord {
    user_id: String,        // plaintext (queryable)
    #[encrypt]
    ssn: String,            // encrypted at rest
    #[encrypt]
    bank_account: String,   // encrypted at rest
    email: String,          // plaintext
}

// Generates:
// pub struct EncryptedUserRecord {
//     pub user_id: String,        // same type
//     pub ssn: String,            // ciphertext string
//     pub bank_account: String,   // ciphertext string
//     pub email: String,          // same type
// }`,
        lang: "rust",
      },
      {
        heading: "Encryption and Decryption",
        text: "Use the Encryptable trait methods or the generated TeeState helpers to encrypt and decrypt.",
        code: `// Via TeeState (recommended -- uses versioned keys automatically):
let encrypted = state.encrypt_user_record(&record)?;
let decrypted = state.decrypt_user_record(&encrypted)?;

// Via Encryptable trait directly:
let key = [0u8; 32]; // use a real key
let encrypted = record.encrypt(&key)?;
let decrypted = UserRecord::decrypt_from(&encrypted, &key)?;`,
        lang: "rust",
      },
      {
        heading: "AES-256-GCM Details",
        text: "Each encrypt call generates a fresh 12-byte random nonce, so encrypting the same plaintext twice always produces different ciphertexts. The encryption uses AES-256-GCM which provides both confidentiality and integrity (authenticated encryption).",
      },
      {
        heading: "Ciphertext Format",
        text: "Encrypted fields are stored as strings in one of two formats:",
        table: {
          headers: ["Format", "Pattern", "Description"],
          rows: [
            ["Unversioned (legacy)", "enc:v1:<nonce_hex>:<ciphertext_hex>", "Original format, no key version tracking"],
            ["Versioned (recommended)", "enc:v1:k<version>:<nonce_hex>:<ciphertext_hex>", "Includes key version for rotation support"],
          ],
        },
      },
      {
        heading: "Key Derivation",
        text: "The SDK uses HKDF-SHA256 to derive per-type encryption keys from the master key. Each struct type gets a different derived key based on a purpose string (\"external:<snake_case_type>\"). This ensures that compromising the derived key for one type does not expose data encrypted for another type.",
        code: `use guarantee::crypto::derive_key;

let master = [0u8; 32]; // loaded from sealed storage
let user_key = derive_key(&master, b"external:user_record");
let audit_key = derive_key(&master, b"external:audit_entry");
// user_key != audit_key, even though master is the same`,
        lang: "rust",
      },
      {
        heading: "What the Database Sees",
        text: "When you store an EncryptedUserRecord, the database stores something like this:",
        code: `{
    "user_id": "alice",
    "ssn": "enc:v1:k1:a1b2c3d4e5f6a1b2c3d4e5f6:7f8a9b0c1d2e3f4a5b6c7d8e9f...",
    "email": "alice@example.com"
}

// user_id and email are plaintext (queryable)
// ssn is AES-256-GCM ciphertext (only the enclave can decrypt)`,
        lang: "json",
      },
      {
        heading: "Key Rotation and Retired Keys",
        text: "When the master key is rotated, the old key is stored in the retired_keys list. The decrypt methods automatically detect the key version from the ciphertext (k<N> tag) and fall back to retired keys when needed. This means data encrypted with any previous key version can still be decrypted as long as the retired key has not been purged.",
        code: `use guarantee::RetiredKeyEntry;

// Retired keys are managed automatically by TeeState.
// After rotation, the old key is stored in signer.retired_keys:
RetiredKeyEntry {
    version: 1,
    key: [/* old 32-byte key */],
    retired_at: "2026-01-15T10:30:00Z",
    expires_at: Some("2027-01-15T10:30:00Z"), // optional expiry
}`,
        lang: "rust",
      },
    ],
  },
  {
    slug: "sealing",
    title: "Sealing",
    lead: "Persist state across restarts using SGX sealing with MRENCLAVE or MRSIGNER scope.",
    section: "Concepts",
    body: [
      {
        heading: "What Is Sealing?",
        text: "SGX sealing encrypts data so that only a specific enclave (or family of enclaves) can decrypt it. The encryption key is derived from the enclave's measurement, making it impossible for any other process -- even the host operating system -- to read the sealed data.\n\nThe Guarantee SDK abstracts sealing behind the seal_to_file and unseal_from_file functions, which work transparently in both dev mode and enclave mode.",
      },
      {
        heading: "SealMode::MrEnclave vs SealMode::MrSigner",
        table: {
          headers: ["", "SealMode::MrEnclave", "SealMode::MrSigner"],
          rows: [
            ["Sealing key derived from", "Enclave binary measurement", "Enclave signing key hash"],
            ["Survives binary update", "No", "Yes"],
            ["Survives signing key change", "No", "No"],
            ["Use case", "Ephemeral session data, signing keys", "Long-lived secrets, master keys, private keys"],
            ["state! attribute", "#[mrenclave]", "#[mrsigner]"],
            ["Sealed file name", "enclave.sealed", "signer.sealed"],
          ],
        },
      },
      {
        heading: "Direct Sealing API",
        text: "You can use the low-level sealing API directly if you need more control than the state! macro provides.",
        code: `use guarantee::seal::{seal_to_file, unseal_from_file, SealMode};
use std::path::Path;

// Seal data
let data = serde_json::to_vec(&my_state)?;
seal_to_file(&data, Path::new("./sealed/state.bin"), SealMode::MrEnclave)?;

// Unseal data
let raw = unseal_from_file(Path::new("./sealed/state.bin"), SealMode::MrEnclave)?;
let my_state: MyState = serde_json::from_slice(&raw)?;`,
        lang: "rust",
      },
      {
        heading: "Dev Mode Behavior",
        text: "In dev mode (GUARANTEE_ENCLAVE not set), sealed files use a plaintext format with a header prefix identifying the seal mode. This is not cryptographically secure and is intended for development and testing only.\n\nDev mode enforces seal mode matching: trying to unseal an MRENCLAVE-sealed file with SealMode::MrSigner returns an error.",
        code: `# Dev mode file format:
# MrEnclave file starts with:
SEAL_MRENCLAVE_DEV\\n<data bytes>

# MrSigner file starts with:
SEAL_MRSIGNER_DEV\\n<data bytes>`,
        lang: "text",
      },
      {
        heading: "Enclave Mode Behavior",
        text: "In enclave mode (GUARANTEE_ENCLAVE=1), the SDK writes raw bytes to disk. Gramine's Protected Files feature intercepts the I/O at the OS layer and applies SGX sealing transparently. For this to work, the file paths must be declared in the Gramine manifest:\n\n- sgx.protected_files for MRENCLAVE-scoped files\n- sgx.protected_mrsigner_files for MRSIGNER-scoped files",
      },
      {
        heading: "File Layout",
        text: "TeeState::initialize() and TeeState::seal() use a seal directory with the following structure:",
        code: `./sealed/
  enclave.sealed    # MRENCLAVE-bound state (EnclaveState)
  signer.sealed     # MRSIGNER-bound state (SignerState)`,
        lang: "text",
      },
      {
        heading: "Backup and Restore",
        text: "TeeState provides backup and restore operations for disaster recovery. Backups copy the sealed files and write a metadata JSON file.",
        code: `// Backup current state
state.backup(
    Path::new("./sealed"),
    Path::new("./backups/2026-03-23"),
)?;

// Restore from backup (before calling TeeState::initialize)
TeeState::restore(
    Path::new("./backups/2026-03-23"),
    Path::new("./sealed"),
)?;
let state = TeeState::initialize(Path::new("./sealed"))?;`,
        lang: "rust",
      },
    ],
  },

  // =========================================================================
  // SECTION: SDK Reference
  // =========================================================================
  {
    slug: "attest-macro",
    title: "#[attest] Macro",
    lead: "Automatically sign every HTTP response with the enclave's Ed25519 key.",
    section: "SDK Reference",
    body: [
      {
        heading: "Overview",
        text: "The #[attest] attribute macro wraps axum handler functions so that every response is signed with the enclave's ephemeral Ed25519 key. The signature is attached as the X-TEE-Attestation header.",
      },
      {
        heading: "Usage",
        text: "Apply #[attest] to any async function that returns an axum response type. The macro injects TeeState extraction from axum's Extension layer automatically, so do not include it in your function signature.",
        code: `use guarantee::attest;
use axum::response::Json;

#[attest]
async fn my_handler() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "data": "value" }))
}`,
        lang: "rust",
      },
      {
        heading: "What the Macro Generates",
        text: "The macro transforms your handler into a new function that:\n\n1. Extracts Arc<RwLock<TeeState>> from axum Extension\n2. Generates a UUID request ID\n3. Executes your original handler body\n4. Converts the response to bytes\n5. Calls state.sign_response(&body_bytes, &request_id)\n6. Inserts three headers into the response",
        list: [
          "X-TEE-Attestation: v=1; sig=<base64>; hash=<hex>; ts=<ms>; key=<hex>",
          "X-TEE-Verified: true",
          "X-TEE-Request-Id: <uuid>",
        ],
      },
      {
        heading: "Handler Signatures",
        text: "The macro works with any handler that returns impl IntoResponse. You can use axum extractors as usual -- the macro prepends its own Extension extractor before your parameters.",
        code: `// Simple handler -- no parameters
#[attest]
async fn hello() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "message": "hello" }))
}

// Handler with extractors
#[attest]
async fn get_user(
    Extension(db): Extension<Arc<Database>>,
    Path(user_id): Path<String>,
) -> impl IntoResponse {
    // ...
}

// Handler with TeeState access (add your own Extension extractor)
#[attest]
async fn with_state(
    Extension(state): Extension<Arc<RwLock<TeeState>>>,
) -> Json<serde_json::Value> {
    let s = state.read().await;
    Json(serde_json::json!({ "key": s.public_key().to_bytes() }))
}`,
        lang: "rust",
      },
      {
        heading: "Header Format",
        text: "The X-TEE-Attestation header follows a semicolon-separated key=value format:",
        code: `X-TEE-Attestation: v=1; sig=dGVzdA==; hash=ab01cd02...; ts=1700000000000; key=0102ab...`,
        lang: "text",
      },
      {
        heading: "Payload Hash Computation",
        text: "The payload hash is computed as:",
        code: `SHA-256(response_body_bytes || timestamp_ms_as_u64_big_endian || request_id_utf8_bytes)`,
        lang: "text",
      },
      {
        heading: "Error Handling",
        text: "If the response body cannot be read for signing, the macro returns a 500 error with a structured JSON body:",
        code: `{
    "error": {
        "code": "body_read_failed",
        "message": "Failed to read response body for attestation"
    }
}`,
        lang: "json",
      },
      {
        heading: "Prerequisites",
        text: "For the macro to work, your axum Router must have TeeState registered as an Extension layer:",
        code: `let state = TeeState::initialize(Path::new("./sealed"))?;

let app = Router::new()
    .route("/api", get(my_handler))
    .layer(Extension(Arc::new(RwLock::new(state))));`,
        lang: "rust",
      },
    ],
  },
  {
    slug: "state-macro",
    title: "state! Macro",
    lead: "Declare TEE state with automatic key management, sealing, and schema migration.",
    section: "SDK Reference",
    body: [
      {
        heading: "Syntax",
        text: "The state! macro accepts one or more sections, each prefixed with an attribute: #[mrenclave], #[mrsigner], or #[external]. Each section lists one or more type names separated by commas.",
        code: `guarantee::state! {
    #[mrenclave]
    TypeA,
    TypeB,

    #[mrsigner]
    TypeC,

    #[external]
    TypeD,
    TypeE,
}`,
        lang: "rust",
      },
      {
        heading: "Type Requirements",
        text: "All types used in state! must implement these traits:",
        list: [
          "serde::Serialize -- for sealing to JSON",
          "serde::Deserialize -- for unsealing from JSON",
          "Default -- for first-boot initialization and schema migration",
          "Clone -- for backup and accessor methods",
          "Debug -- for logging",
        ],
      },
      {
        heading: "Generated Types",
        text: "The macro generates three struct types:",
        table: {
          headers: ["Type", "Condition", "Contents"],
          rows: [
            ["EnclaveState", "At least one #[mrenclave] type", "Ed25519 signing_key + your MRENCLAVE fields + schema_version"],
            ["SignerState", "At least one #[mrsigner] type", "master_key + key rotation metadata + retired_keys + your MRSIGNER fields + schema_version"],
            ["TeeState", "Always", "Wraps EnclaveState and/or SignerState"],
          ],
        },
      },
      {
        heading: "Field Naming Convention",
        text: "Type names are converted to snake_case for field names and accessor methods. Examples:",
        table: {
          headers: ["Type Name", "Field Name", "Accessor"],
          rows: [
            ["PriceCache", "price_cache", "state.enclave().price_cache()"],
            ["OracleConfig", "oracle_config", "state.signer().oracle_config()"],
            ["BtcWallet", "btc_wallet", "state.signer().btc_wallet()"],
            ["SignerSession", "signer_session", "state.enclave().signer_session()"],
            ["AppData", "app_data", "state.enclave().app_data()"],
          ],
        },
      },
      {
        heading: "SignerState Auto-Generated Fields",
        text: "When #[mrsigner] is used, SignerState includes these auto-generated fields in addition to your declared types:",
        list: [
          "master_key: [u8; 32] -- 256-bit AES master key (generated on first boot)",
          "current_key_version: u32 -- Key version number (starts at 1)",
          "rotation_interval_days: u64 -- Days between automatic rotations (default 90)",
          "last_rotation: String -- RFC3339 timestamp of last rotation",
          "next_rotation: String -- RFC3339 timestamp of next scheduled rotation",
          "retired_keys: Vec<RetiredKeyEntry> -- Old keys kept for backward decryption",
          "schema_version: u32 -- Schema version for migration support",
        ],
      },
      {
        heading: "External Type Methods",
        text: "For each type listed under #[external], the macro generates encrypt and decrypt methods on TeeState. These methods use the MRSIGNER master key with versioned key derivation.",
        code: `state! {
    #[mrsigner]
    AppConfig,

    #[external]
    UserRecord,
    AuditEntry,
}

// Generated methods:
// state.encrypt_user_record(&record) -> Result<EncryptedUserRecord>
// state.decrypt_user_record(&encrypted) -> Result<UserRecord>
// state.encrypt_audit_entry(&entry) -> Result<EncryptedAuditEntry>
// state.decrypt_audit_entry(&encrypted) -> Result<AuditEntry>`,
        lang: "rust",
      },
      {
        heading: "Schema Versioning",
        text: "Add a version annotation to handle schema migrations when you add new fields to your state types.",
        code: `state! {
    #[mrenclave(version = 2)]
    SessionData,

    #[mrsigner(version = 3)]
    MasterConfig,
}

// On initialize(), if the sealed state has schema_version < current:
// 1. New fields get Default values
// 2. schema_version is updated
// 3. State is re-sealed
// A warning is logged: "Migrating MRENCLAVE state schema"`,
        lang: "rust",
      },
    ],
  },
  {
    slug: "encrypted-derive",
    title: "#[derive(Encrypted)]",
    lead: "Generate encrypted struct variants with automatic AES-256-GCM field encryption.",
    section: "SDK Reference",
    body: [
      {
        heading: "Overview",
        text: "The Encrypted derive macro generates a companion struct where #[encrypt]-annotated fields are stored as AES-256-GCM ciphertext strings. It also implements the Encryptable trait, providing encrypt/decrypt methods.",
      },
      {
        heading: "Usage",
        text: "Apply #[derive(Encrypted)] to your struct and mark sensitive fields with #[encrypt]. The #[encrypt] attribute only works on String fields.",
        code: `use guarantee::Encrypted;
use serde::{Serialize, Deserialize};

#[derive(Encrypted, Serialize, Deserialize, Clone, Debug)]
struct UserRecord {
    user_id: String,
    #[encrypt]
    ssn: String,
    #[encrypt]
    bank_account: String,
    email: String,
}`,
        lang: "rust",
      },
      {
        heading: "Generated Struct",
        text: "The macro generates Encrypted<Name> (e.g., EncryptedUserRecord) where all fields have the same name and non-encrypted fields keep their original type. Encrypted fields become String type containing ciphertext.",
        code: `// Generated by #[derive(Encrypted)] on UserRecord:
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EncryptedUserRecord {
    pub user_id: String,        // same type, plaintext
    pub ssn: String,            // ciphertext: "enc:v1:k1:..."
    pub bank_account: String,   // ciphertext: "enc:v1:k1:..."
    pub email: String,          // same type, plaintext
}`,
        lang: "rust",
      },
      {
        heading: "Encryptable Trait",
        text: "The macro implements the Encryptable trait on your struct, providing four methods:",
        code: `pub trait Encryptable: Sized {
    type Encrypted;

    // Basic encryption (unversioned)
    fn encrypt(&self, key: &[u8; 32]) -> Result<Self::Encrypted, SdkError>;
    fn decrypt_from(encrypted: &Self::Encrypted, key: &[u8; 32]) -> Result<Self, SdkError>;

    // Versioned encryption (with key rotation support)
    fn encrypt_versioned(
        &self,
        key: &[u8; 32],
        version: u32,
        purpose: &[u8],
    ) -> Result<Self::Encrypted, SdkError>;

    fn decrypt_versioned(
        encrypted: &Self::Encrypted,
        current_key: &[u8; 32],
        current_version: u32,
        retired_keys: &[RetiredKeyEntry],
        purpose: &[u8],
    ) -> Result<Self, SdkError>;
}`,
        lang: "rust",
      },
      {
        heading: "Using with TeeState",
        text: "When used with the #[external] attribute in state!, TeeState provides convenience methods that handle key management automatically.",
        code: `state! {
    #[mrsigner]
    AppConfig,

    #[external]
    UserRecord,
}

// Encrypt -- uses current master key version + per-type derivation
let encrypted: EncryptedUserRecord = state.encrypt_user_record(&record)?;

// Decrypt -- automatically handles key version fallback
let record: UserRecord = state.decrypt_user_record(&encrypted)?;`,
        lang: "rust",
      },
      {
        heading: "Constraints",
        list: [
          "#[encrypt] only works on String fields",
          "The struct must have named fields (no tuple structs)",
          "Only works on structs, not enums or unions",
          "The struct must also derive Serialize and Deserialize",
        ],
      },
    ],
  },
  {
    slug: "crypto",
    title: "Crypto Module",
    lead: "Low-level AES-256-GCM encryption, HKDF key derivation, and versioned key management.",
    section: "SDK Reference",
    body: [
      {
        heading: "Module Path",
        text: "All cryptographic functions are in the guarantee::crypto module. Most users will not need these directly -- the #[derive(Encrypted)] macro and TeeState methods handle encryption automatically.",
        code: `use guarantee::crypto::{
    encrypt_field,
    decrypt_field,
    encrypt_field_versioned,
    decrypt_field_versioned,
    derive_key,
    Encryptable,
    RetiredKeyEntry,
};`,
        lang: "rust",
      },
      {
        heading: "encrypt_field / decrypt_field",
        text: "Basic encryption functions that operate on individual string values. These use the key directly without version tracking.",
        code: `use guarantee::crypto::{encrypt_field, decrypt_field};

let key = [42u8; 32];
let encrypted = encrypt_field("my secret", &key)?;
assert!(encrypted.starts_with("enc:v1:"));

let plaintext = decrypt_field(&encrypted, &key)?;
assert_eq!(plaintext, "my secret");`,
        lang: "rust",
      },
      {
        heading: "encrypt_field_versioned / decrypt_field_versioned",
        text: "Versioned encryption with key tagging and per-type key derivation. The key is first derived via HKDF with a purpose string, then the key version is embedded in the ciphertext.",
        code: `use guarantee::crypto::{encrypt_field_versioned, decrypt_field_versioned};

let master = [42u8; 32];

// Encrypt with version 1
let enc = encrypt_field_versioned("secret", &master, 1, b"UserRecord::email")?;
assert!(enc.starts_with("enc:v1:k1:"));

// Decrypt (same key, same version)
let plain = decrypt_field_versioned(&enc, &master, 1, &[], b"UserRecord::email")?;
assert_eq!(plain, "secret");`,
        lang: "rust",
      },
      {
        heading: "derive_key",
        text: "Derives a purpose-specific 256-bit key from a master key using HKDF-SHA256. Different purpose values produce cryptographically independent keys.",
        code: `use guarantee::crypto::derive_key;

let master = [0u8; 32];
let email_key = derive_key(&master, b"UserRecord::email");
let token_key = derive_key(&master, b"UserRecord::token");
// email_key != token_key

// Same inputs always produce the same output
let key1 = derive_key(&master, b"purpose");
let key2 = derive_key(&master, b"purpose");
assert_eq!(key1, key2);`,
        lang: "rust",
      },
      {
        heading: "RetiredKeyEntry",
        text: "Represents a retired encryption key kept for backward decryption after a key rotation event.",
        code: `use guarantee::crypto::RetiredKeyEntry;

let entry = RetiredKeyEntry {
    version: 1,                                     // key version
    key: [1u8; 32],                                 // 256-bit key material
    retired_at: "2026-01-01T00:00:00Z".to_string(), // when it was retired
    expires_at: Some("2027-01-01T00:00:00Z".to_string()), // optional expiry
};`,
        lang: "rust",
      },
      {
        heading: "Encryptable Trait",
        text: "The Encryptable trait is implemented automatically by #[derive(Encrypted)]. You can also implement it manually for custom encryption logic.",
        code: `use guarantee::crypto::Encryptable;
use guarantee::SdkError;

// The trait provides four methods:
// encrypt(&self, key) -> Result<Self::Encrypted, SdkError>
// decrypt_from(encrypted, key) -> Result<Self, SdkError>
// encrypt_versioned(&self, key, version, purpose) -> Result<Self::Encrypted, SdkError>
// decrypt_versioned(encrypted, current_key, version, retired, purpose) -> Result<Self, SdkError>`,
        lang: "rust",
      },
      {
        heading: "Key Version Fallback",
        text: "decrypt_field_versioned handles both old and new ciphertext formats automatically:",
        list: [
          "Unversioned (enc:v1:<nonce>:<ct>): tries current_key first, then each retired key",
          "Versioned (enc:v1:k<N>:<nonce>:<ct>): looks up key by version N, derives per-type key, then decrypts",
        ],
      },
    ],
  },
  {
    slug: "enclave-attestor",
    title: "EnclaveAttestor",
    lead: "The core attestation engine: key generation, startup quotes, and per-response signing.",
    section: "SDK Reference",
    body: [
      {
        heading: "Overview",
        text: "EnclaveAttestor is the SDK's central attestation type. It holds the ephemeral Ed25519 signing keypair and the startup attestation quote. In most applications, you will use TeeState instead (which embeds the signing key), but EnclaveAttestor is available for standalone use.",
      },
      {
        heading: "Initialization",
        text: "Initialize the attestor once at startup. It generates an Ed25519 keypair and obtains a startup quote (real DCAP quote in enclave mode, mock quote in dev mode).",
        code: `use guarantee::{EnclaveAttestor, AttestationMode};

// Auto-detect mode from GUARANTEE_ATTEST_MODE env var
let attestor = EnclaveAttestor::initialize().await?;

// Or specify mode explicitly
let attestor = EnclaveAttestor::initialize_with_mode(
    AttestationMode::EveryResponse
).await?;`,
        lang: "rust",
      },
      {
        heading: "sign_response",
        text: "Signs a response body and produces an AttestationHeader. This is called automatically by the #[attest] macro. The payload hash is SHA-256(body || timestamp_ms_be || request_id).",
        code: `let header = attestor.sign_response(b"response body", "request-id-123");
println!("Header: {}", header.to_header_value());
// v=1; sig=<base64>; hash=<hex>; ts=<unix_ms>; key=<hex>`,
        lang: "rust",
      },
      {
        heading: "startup_attestation_json",
        text: "Returns a JSON value suitable for serving at the /.well-known/tee-attestation endpoint.",
        code: `let json = attestor.startup_attestation_json()?;
// Returns:
// {
//   "public_key": "<hex>",
//   "quote": "<base64>",
//   "mr_enclave": "<hex>",
//   "mr_signer": "<hex>",
//   "tee_type": "dev-mode" | "intel-sgx",
//   "produced_at": "<rfc3339>"
// }`,
        lang: "rust",
      },
      {
        heading: "Public Fields",
        table: {
          headers: ["Field", "Type", "Description"],
          rows: [
            ["public_key", "ed25519_dalek::VerifyingKey", "The ephemeral Ed25519 public key"],
            ["startup_quote", "Arc<RwLock<Option<StartupQuote>>>", "The startup attestation quote"],
            ["mode", "AttestationMode", "EveryResponse or StartupOnly"],
          ],
        },
      },
      {
        heading: "AttestationMode",
        code: `pub enum AttestationMode {
    /// Every HTTP response is signed (default)
    EveryResponse,

    /// Only the startup quote is produced; per-response sig/hash are empty
    StartupOnly,
}

// In StartupOnly mode, sign_response returns a header with empty
// signature_b64 and payload_hash_hex fields, but the public_key_hex
// is still present for enclave identification.`,
        lang: "rust",
      },
      {
        heading: "Standalone Usage (without state! macro)",
        text: "If you do not need sealed state management, you can use EnclaveAttestor directly with axum's Extension layer.",
        code: `use guarantee::EnclaveAttestor;

let attestor = EnclaveAttestor::initialize().await?;

let app = Router::new()
    .route("/api", get(handler))
    .layer(Extension(attestor));

// Note: #[attest] macro expects TeeState in the Extension, not
// EnclaveAttestor. For standalone EnclaveAttestor, you would need
// to sign responses manually in your handler.`,
        lang: "rust",
      },
    ],
  },
  {
    slug: "ra-tls",
    title: "RA-TLS",
    lead: "HTTPS with embedded SGX attestation for inter-enclave communication and WebSocket support.",
    section: "SDK Reference",
    body: [
      {
        heading: "Overview",
        text: "RA-TLS (Remote Attestation TLS) embeds an SGX attestation quote inside a self-signed X.509 certificate. When two enclaves communicate over TLS, each side can verify the other's attestation during the TLS handshake, before any application data is exchanged.\n\nRA-TLS is available behind the ra-tls feature flag.",
        code: `[dependencies]
guarantee = { version = "0.1.2", features = ["ra-tls"] }`,
        lang: "toml",
      },
      {
        heading: "Server: serve_ra_tls",
        text: "Start an HTTPS server with an RA-TLS certificate and an optional HTTP server for health checks. Both servers share the same Router.",
        code: `use axum::Router;
use guarantee::serve_ra_tls;

let app = Router::new()
    .route("/api", get(handler));

// Starts HTTPS on 8443 and HTTP on 8080
serve_ra_tls(app, "my-service", "0.0.0.0:8443", "0.0.0.0:8080").await?;`,
        lang: "rust",
      },
      {
        heading: "serve_ra_tls Parameters",
        table: {
          headers: ["Parameter", "Type", "Description"],
          rows: [
            ["app", "axum::Router", "The axum Router to serve on both ports"],
            ["service_name", "&str", "Used as the CN in the self-signed certificate"],
            ["https_addr", "&str", "Address for the HTTPS server (e.g., \"0.0.0.0:8443\")"],
            ["http_addr", "&str", "Address for the HTTP server (e.g., \"0.0.0.0:8080\")"],
          ],
        },
      },
      {
        heading: "Client: Inter-Enclave Connections",
        text: "Use EnclaveConnectionBuilder to create an HTTP client that verifies the target enclave's RA-TLS certificate during the TLS handshake. Optionally pin to a specific MRENCLAVE.",
        code: `use guarantee::{connect, MrEnclave};

// Connect to another enclave with MRENCLAVE verification
let expected = MrEnclave::new([0xAB; 32]);
let conn = guarantee::connect("https://oracle.internal:8443")
    .with_mrenclave(expected)
    .build()?;

// Make requests -- TLS handshake verifies the attestation quote
let resp = conn.get("/price/BTC").await?;
let data: serde_json::Value = resp.json().await.map_err(|e| /* ... */)?;

// POST with JSON body
conn.post("/submit", &my_payload).await?;`,
        lang: "rust",
      },
      {
        heading: "EnclaveConnection Methods",
        table: {
          headers: ["Method", "Description"],
          rows: [
            ["get(path)", "Send a GET request to the connected enclave"],
            ["post(path, body)", "Send a POST request with a JSON body"],
            ["url()", "Get the target URL"],
            ["expected_mrenclave()", "Get the expected MRENCLAVE (if set)"],
          ],
        },
      },
      {
        heading: "WebSocket over RA-TLS",
        text: "The ra_tls::websocket module provides WebSocket support over RA-TLS connections for real-time inter-enclave communication. The WebSocket upgrade happens after RA-TLS verification, so the attestation is checked before any WebSocket frames are exchanged.",
      },
      {
        heading: "Modules",
        text: "The ra_tls feature enables these submodules:",
        list: [
          "ra_tls::cert -- X.509 certificate generation with embedded SGX quotes",
          "ra_tls::server -- serve_ra_tls for dual HTTP/HTTPS serving",
          "ra_tls::client -- EnclaveConnection and EnclaveConnectionBuilder",
          "ra_tls::verifier -- Custom rustls verifier for RA-TLS certificates",
          "ra_tls::websocket -- WebSocket support over RA-TLS",
        ],
      },
    ],
  },
  {
    slug: "errors",
    title: "Error Handling",
    lead: "SdkError variants for attestation, cryptography, sealing, and RA-TLS operations.",
    section: "SDK Reference",
    body: [
      {
        heading: "SdkError Enum",
        text: "All fallible operations in the guarantee crate return SdkError. The variants map to the major SDK subsystems.",
        code: `use guarantee::SdkError;

match result {
    Err(SdkError::AttestationUnavailable(msg)) => {
        eprintln!("SGX not available: {msg}");
    }
    Err(SdkError::CryptoError(msg)) => {
        eprintln!("Encryption failed: {msg}");
    }
    Err(e) => eprintln!("Error: {e}"),
    Ok(v) => { /* use v */ }
}`,
        lang: "rust",
      },
      {
        heading: "Variant Reference",
        table: {
          headers: ["Variant", "Description", "Common Causes"],
          rows: [
            [
              "AttestationUnavailable(String)",
              "SGX /dev/attestation not available",
              "GUARANTEE_ENCLAVE=1 set but not in Gramine; manifest missing /dev/attestation mount",
            ],
            [
              "QuoteReadFailed(String)",
              "Failed to read DCAP quote",
              "user_report_data not written first; SGX quoting disabled",
            ],
            [
              "KeyGenerationFailed(String)",
              "Ed25519 key generation failed",
              "Extremely unlikely -- requires OS randomness failure",
            ],
            [
              "SigningFailed(String)",
              "Ed25519 signing failed or header parse error",
              "Invalid version or timestamp in X-TEE-Attestation header",
            ],
            [
              "IoError(std::io::Error)",
              "Low-level I/O error",
              "File system errors during sealing/unsealing",
            ],
            [
              "NotInitialized",
              "Attestor used before initialization",
              "Forgot to call EnclaveAttestor::initialize() at startup",
            ],
            [
              "SealError(String)",
              "Sealing or unsealing failed",
              "File not found, seal-mode mismatch, corrupt sealed data, Gramine PF error",
            ],
            [
              "CryptoError(String)",
              "AES-256-GCM or HKDF error",
              "Wrong key, corrupted ciphertext, missing key version, malformed enc:v1: payload",
            ],
            [
              "RaTlsError(String)",
              "RA-TLS connection or verification error",
              "MRENCLAVE mismatch, network error, invalid attestation in certificate",
            ],
            [
              "CertificateError(String)",
              "X.509 certificate generation error",
              "rcgen failed to generate keypair or self-sign",
            ],
            [
              "TlsError(String)",
              "TLS configuration or server error",
              "rustls failed to load certificate; server bind error",
            ],
          ],
        },
      },
      {
        heading: "Error Display",
        text: "SdkError implements std::fmt::Display via thiserror, so you can print human-readable error messages directly.",
        code: `let err = SdkError::CryptoError("Invalid nonce length".into());
println!("{err}");
// Output: "Crypto error: Invalid nonce length"

let err = SdkError::SealError("File not found".into());
println!("{err}");
// Output: "Seal error: File not found"`,
        lang: "rust",
      },
      {
        heading: "Conversion",
        text: "SdkError implements From<std::io::Error>, so I/O errors are automatically converted when using the ? operator.",
        code: `fn read_data() -> Result<Vec<u8>, SdkError> {
    let data = std::fs::read("./sealed/state.bin")?; // IoError auto-converted
    Ok(data)
}`,
        lang: "rust",
      },
    ],
  },

  // =========================================================================
  // SECTION: Examples
  // =========================================================================
  {
    slug: "hello-tee",
    title: "Hello TEE",
    lead: "The simplest attested service: a single endpoint that returns a signed JSON response.",
    section: "Examples",
    body: [
      {
        heading: "Overview",
        text: "This example demonstrates the minimum viable attested service. It defines a single MRENCLAVE state type, one attested handler, and the attestation info endpoint. Every response to /hello includes an X-TEE-Attestation header.",
      },
      {
        heading: "Running the Example",
        code: `cargo run --example hello-tee

# Test the attested endpoint
curl -v http://localhost:8080/hello
# Look for X-TEE-Attestation and X-TEE-Verified headers

# Check attestation info
curl http://localhost:8080/.well-known/tee-attestation`,
        lang: "bash",
      },
      {
        heading: "Full Source",
        code: `use axum::{extract::Extension, response::Json, routing::get, Router};
use guarantee::{attest, state};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;

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
    Extension(state): Extension<Arc<RwLock<TeeState>>>,
) -> Json<serde_json::Value> {
    let s = state.read().await;
    Json(s.attestation_json())
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
        .layer(Extension(Arc::new(RwLock::new(state))));

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{port}"))
        .await
        .expect("Failed to bind");
    axum::serve(listener, app).await.expect("Server failed");
}`,
        lang: "rust",
      },
      {
        heading: "Key Points",
        list: [
          "state! { #[mrenclave] AppData } generates TeeState with an auto-managed Ed25519 signing key",
          "#[attest] on hello() injects TeeState extraction and response signing automatically",
          "The attestation_info handler manually accesses TeeState to serve the .well-known endpoint",
          "TeeState is shared via Arc<RwLock<TeeState>> in axum's Extension layer",
          "In dev mode, the service works identically but the startup quote contains mock data",
        ],
      },
    ],
  },
  {
    slug: "oracle",
    title: "Price Oracle",
    lead: "An attested price feed with two-tier state: MRENCLAVE cache and MRSIGNER config.",
    section: "Examples",
    body: [
      {
        heading: "Overview",
        text: "This example demonstrates a price oracle service that uses both state tiers. PriceCache is MRENCLAVE-bound (resets on redeploy since cached prices are ephemeral), while OracleConfig is MRSIGNER-bound (API keys and configuration persist across redeployments). A background task updates prices periodically.",
      },
      {
        heading: "Running the Example",
        code: `cargo run --example oracle

# Get a single price
curl http://localhost:8080/price/BTC

# Get all prices
curl http://localhost:8080/prices

# Check attestation
curl http://localhost:8080/.well-known/tee-attestation`,
        lang: "bash",
      },
      {
        heading: "Full Source",
        code: `use axum::{
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

/// Cached prices -- reset on redeploy (MRENCLAVE-bound).
#[derive(Serialize, Deserialize, Default, Clone, Debug)]
struct PriceCache {
    prices: HashMap<String, f64>,
    last_updated: Option<String>,
}

/// Oracle configuration -- persists across redeploys (MRSIGNER-bound).
#[derive(Serialize, Deserialize, Default, Clone, Debug)]
struct OracleConfig {
    source_api_key: String,
    max_staleness_secs: u64,
}

state! {
    #[mrenclave]
    PriceCache,

    #[mrsigner]
    OracleConfig,
}

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

async fn update_prices(state: Arc<RwLock<TeeState>>) {
    loop {
        {
            let mut s = state.write().await;
            let cache = &mut s.enclave_mut().price_cache;
            cache.prices.insert("BTC".into(), 67_432.50);
            cache.prices.insert("ETH".into(), 3_521.75);
            cache.prices.insert("SOL".into(), 142.30);
            cache.prices.insert("AVAX".into(), 35.80);
            cache.last_updated = Some(chrono::Utc::now().to_rfc3339());

            let _ = s.seal(std::path::Path::new("./sealed"));
        }
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
    }
}

#[tokio::main]
async fn main() {
    let port = std::env::var("PORT").unwrap_or_else(|_| "8080".to_string());
    let state = TeeState::initialize(std::path::Path::new("./sealed"))
        .expect("Failed to initialize TeeState");
    let state = Arc::new(RwLock::new(state));

    tokio::spawn(update_prices(state.clone()));

    println!("TEE Price Oracle running on port {port}");

    let app = Router::new()
        .route("/price/:symbol", get(get_price))
        .route("/prices", get(get_all_prices))
        .route("/.well-known/tee-attestation", get(attestation_info))
        .layer(Extension(state));

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{port}"))
        .await
        .expect("Failed to bind");
    axum::serve(listener, app).await.expect("Server failed");
}`,
        lang: "rust",
      },
      {
        heading: "Key Points",
        list: [
          "Two-tier state: PriceCache (MRENCLAVE) and OracleConfig (MRSIGNER)",
          "Background task via tokio::spawn updates prices every 10 seconds",
          "State is sealed after each update with state.seal()",
          "Both /price/:symbol and /prices routes are attested with #[attest]",
          "The attestation endpoint is not attested (no signature overhead needed)",
          "In production, replace mock prices with real API calls to CoinGecko, Binance, etc.",
        ],
      },
    ],
  },
  {
    slug: "btc-signer",
    title: "Bitcoin Signer",
    lead: "A custodial signing service with MRSIGNER-sealed private keys and encrypted audit logs.",
    section: "Examples",
    body: [
      {
        heading: "Overview",
        text: "This example demonstrates key custody in a TEE. A Bitcoin private key is generated on first boot and sealed with MRSIGNER scope, so it persists across redeployments. Per-session data tracks request counts. Signing audit entries are encrypted for external storage using #[derive(Encrypted)].",
      },
      {
        heading: "Running the Example",
        code: `cargo run --example btc-signer

# Get the public key
curl http://localhost:8080/pubkey

# Sign a transaction
curl -X POST http://localhost:8080/sign \\
  -H 'Content-Type: application/json' \\
  -d '{"tx_hex":"0200000001abcdef","input_index":0}'

# Check status
curl http://localhost:8080/status

# Verify attestation
curl http://localhost:8080/.well-known/tee-attestation`,
        lang: "bash",
      },
      {
        heading: "Full Source",
        code: `use axum::{
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

#[derive(Serialize, Deserialize, Clone, Debug)]
struct BtcWallet {
    #[serde(with = "hex_key_serde")]
    private_key: [u8; 32],
    derivation_path: String,
    tx_count: u64,
}

impl Default for BtcWallet {
    fn default() -> Self {
        let mut key = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut key);
        Self {
            private_key: key,
            derivation_path: "m/84'/0'/0'/0/0".to_string(),
            tx_count: 0,
        }
    }
}

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

#[derive(Encrypted, Serialize, Deserialize, Clone, Debug)]
struct SigningAuditEntry {
    tx_hash: String,
    #[encrypt]
    signature: String,
    timestamp: String,
    input_index: u32,
}

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

#[attest]
async fn get_pubkey(
    Extension(state): Extension<Arc<RwLock<TeeState>>>,
) -> Json<serde_json::Value> {
    let s = state.read().await;
    let wallet = s.signer().btc_wallet();
    let pubkey_hash = Sha256::digest(&wallet.private_key);
    let pubkey_hex: String = pubkey_hash.iter().map(|b| format!("{:02x}", b)).collect();

    Json(serde_json::json!({
        "public_key": pubkey_hex,
        "derivation_path": wallet.derivation_path,
        "total_signatures": wallet.tx_count,
        "network": "bitcoin-mainnet",
    }))
}

#[derive(Deserialize)]
struct SignRequest {
    tx_hex: String,
    input_index: u32,
}

#[attest]
async fn sign_transaction(
    Extension(state): Extension<Arc<RwLock<TeeState>>>,
    Json(req): Json<SignRequest>,
) -> impl IntoResponse {
    let mut s = state.write().await;

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

    let wallet = s.signer().btc_wallet();
    let mut sig_input = Vec::new();
    sig_input.extend_from_slice(&wallet.private_key);
    sig_input.extend_from_slice(&tx_hash);
    let signature = Sha256::digest(&sig_input);
    let sig_hex: String = signature.iter().map(|b| format!("{:02x}", b)).collect();

    s.signer_mut().btc_wallet.tx_count += 1;
    s.enclave_mut().signer_session.requests_this_session += 1;
    s.enclave_mut().signer_session.last_request_time =
        Some(chrono::Utc::now().to_rfc3339());

    let audit = SigningAuditEntry {
        tx_hash: tx_hash_hex.clone(),
        signature: sig_hex.clone(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        input_index: req.input_index,
    };
    let encrypted_audit = s.encrypt_signing_audit_entry(&audit);

    let _ = s.seal(std::path::Path::new("./sealed"));

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "tx_hash": tx_hash_hex,
            "signature": sig_hex,
            "input_index": req.input_index,
            "total_signatures": s.signer().btc_wallet().tx_count,
            "audit_encrypted": encrypted_audit.is_ok(),
        })),
    ).into_response()
}

async fn attestation_info(
    Extension(state): Extension<Arc<RwLock<TeeState>>>,
) -> Json<serde_json::Value> {
    let s = state.read().await;
    Json(s.attestation_json())
}

fn hex_decode(hex: &str) -> Option<Vec<u8>> {
    if hex.len() % 2 != 0 { return None; }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect()
}

#[tokio::main]
async fn main() {
    let port = std::env::var("PORT").unwrap_or_else(|_| "8080".to_string());
    let state = TeeState::initialize(std::path::Path::new("./sealed"))
        .expect("Failed to initialize TeeState");

    let app = Router::new()
        .route("/pubkey", get(get_pubkey))
        .route("/sign", post(sign_transaction))
        .route("/.well-known/tee-attestation", get(attestation_info))
        .layer(Extension(Arc::new(RwLock::new(state))));

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{port}"))
        .await
        .expect("Failed to bind");
    axum::serve(listener, app).await.expect("Server failed");
}`,
        lang: "rust",
      },
      {
        heading: "Key Points",
        list: [
          "Three-tier state: SignerSession (MRENCLAVE), BtcWallet (MRSIGNER), SigningAuditEntry (external)",
          "BtcWallet::default() generates a random private key on first boot",
          "The private key is sealed with MRSIGNER -- it persists across redeploys",
          "SigningAuditEntry uses #[derive(Encrypted)] with #[encrypt] on the signature field",
          "state.encrypt_signing_audit_entry() encrypts the audit entry for external storage",
          "Double SHA-256 hashing follows Bitcoin's transaction signing convention",
          "State is sealed after every signing operation to persist the updated tx_count",
        ],
      },
    ],
  },
  {
    slug: "postgres-encrypted",
    title: "PostgreSQL Encrypted",
    lead: "Field-level encryption for database records: the database only ever sees ciphertext.",
    section: "Examples",
    body: [
      {
        heading: "Overview",
        text: "This example demonstrates storing sensitive user data in PostgreSQL with automatic field-level encryption. The #[encrypt] attribute on the ssn field ensures the database only ever sees AES-256-GCM ciphertext. The /users/:id/raw endpoint shows exactly what the database stores.",
      },
      {
        heading: "Running the Example",
        code: `# Start PostgreSQL (optional -- example uses mock DB)
docker run -d --name pg -e POSTGRES_PASSWORD=dev -p 5432:5432 postgres:16

# Run the example
cargo run --example postgres-encrypted

# Create a user
curl -X POST http://localhost:8080/users \\
  -H 'Content-Type: application/json' \\
  -d '{"user_id":"alice","ssn":"123-45-6789","email":"alice@example.com"}'

# Get user (decrypted in enclave)
curl http://localhost:8080/users/alice

# See what the DB stores (ciphertext)
curl http://localhost:8080/users/alice/raw`,
        lang: "bash",
      },
      {
        heading: "Full Source",
        code: `use axum::{
    extract::{Extension, Path},
    http::StatusCode,
    response::{IntoResponse, Json},
    routing::{get, post},
    Router,
};
use guarantee::{state, attest, Encrypted, crypto::Encryptable};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Encrypted, Serialize, Deserialize, Clone, Debug)]
struct UserRecord {
    user_id: String,
    #[encrypt]
    ssn: String,
    email: String,
}

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

#[attest]
async fn create_user(
    Extension(state): Extension<Arc<RwLock<TeeState>>>,
    Extension(db): Extension<Arc<MockDb>>,
    Json(user): Json<UserRecord>,
) -> impl IntoResponse {
    let state = state.read().await;
    let encrypted = match state.encrypt_user_record(&user) {
        Ok(e) => e,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": e.to_string()})),
            ).into_response()
        }
    };

    db.records.write().await.insert(encrypted.user_id.clone(), encrypted);

    (
        StatusCode::CREATED,
        Json(serde_json::json!({"status": "created", "user_id": user.user_id})),
    ).into_response()
}

#[attest]
async fn get_user(
    Extension(state): Extension<Arc<RwLock<TeeState>>>,
    Extension(db): Extension<Arc<MockDb>>,
    Path(user_id): Path<String>,
) -> impl IntoResponse {
    let state = state.read().await;
    let records = db.records.read().await;
    let encrypted = match records.get(&user_id) {
        Some(r) => r,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "User not found"})),
            ).into_response()
        }
    };

    match state.decrypt_user_record(encrypted) {
        Ok(user) => Json(serde_json::json!({
            "user_id": user.user_id,
            "ssn": user.ssn,
            "email": user.email,
        })).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("Decryption failed: {e}")})),
        ).into_response(),
    }
}

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
        })).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "User not found"})),
        ).into_response(),
    }
}

async fn attestation_info(
    Extension(state): Extension<Arc<RwLock<TeeState>>>,
) -> Json<serde_json::Value> {
    let s = state.read().await;
    Json(s.attestation_json())
}

#[tokio::main]
async fn main() {
    let port = std::env::var("PORT").unwrap_or_else(|_| "8080".to_string());
    let state = TeeState::initialize(std::path::Path::new("./sealed"))
        .expect("Failed to initialize TeeState");
    let db = Arc::new(MockDb::new());

    println!("Encrypted DB example on port {port}");

    let app = Router::new()
        .route("/users", post(create_user))
        .route("/users/:id", get(get_user))
        .route("/users/:id/raw", get(get_user_raw))
        .route("/.well-known/tee-attestation", get(attestation_info))
        .layer(Extension(Arc::new(RwLock::new(state))))
        .layer(Extension(db));

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{port}"))
        .await
        .expect("Failed to bind");
    axum::serve(listener, app).await.expect("Server failed");
}`,
        lang: "rust",
      },
      {
        heading: "What the Database Stores",
        text: "When you POST a user, the database stores a mix of plaintext and ciphertext. Only #[encrypt] fields are encrypted.",
        code: `// POST body (plaintext):
{ "user_id": "alice", "ssn": "123-45-6789", "email": "alice@example.com" }

// Stored in database (EncryptedUserRecord):
{
    "user_id": "alice",                                          // plaintext
    "ssn": "enc:v1:k1:a1b2c3d4e5f6a1b2c3d4e5f6:7f8a9b0c...",  // ciphertext
    "email": "alice@example.com"                                 // plaintext
}

// GET /users/alice returns the decrypted record
// GET /users/alice/raw returns the encrypted record as stored`,
        lang: "json",
      },
      {
        heading: "Key Points",
        list: [
          "#[derive(Encrypted)] generates EncryptedUserRecord with ssn as ciphertext",
          "state.encrypt_user_record() uses the MRSIGNER master key with per-type derivation",
          "state.decrypt_user_record() automatically handles key version fallback",
          "The /raw endpoint demonstrates that the database never sees plaintext SSNs",
          "Replace MockDb with sqlx::PgPool for real PostgreSQL integration",
          "Non-encrypted fields (user_id, email) remain queryable in the database",
        ],
      },
    ],
  },
  {
    slug: "redis-cache",
    title: "Redis Encrypted Cache",
    lead: "Conditional encryption for a Redis cache: sensitive values are encrypted, others stored as-is.",
    section: "Examples",
    body: [
      {
        heading: "Overview",
        text: "This example demonstrates using a TEE enclave with Redis as an encrypted cache layer. When a value is marked as sensitive, it is encrypted before being stored in Redis. Non-sensitive values are stored as plaintext for efficiency. The enclave tracks cache statistics in MRENCLAVE-sealed state.",
      },
      {
        heading: "Running the Example",
        code: `# Start Redis
docker run -d --name redis -p 6379:6379 redis:7

# Run the example
REDIS_URL=redis://localhost:6379 cargo run --example redis-cache

# Store a sensitive value (encrypted)
curl -X POST http://localhost:8080/cache/my-secret \\
  -H 'Content-Type: application/json' \\
  -d '{"value":"super-secret-api-key-12345","sensitive":true}'

# Store a non-sensitive value (plaintext)
curl -X POST http://localhost:8080/cache/greeting \\
  -H 'Content-Type: application/json' \\
  -d '{"value":"hello world","sensitive":false}'

# Retrieve (auto-decrypted in enclave)
curl http://localhost:8080/cache/my-secret

# Cache statistics
curl http://localhost:8080/stats

# Delete
curl -X DELETE http://localhost:8080/cache/my-secret`,
        lang: "bash",
      },
      {
        heading: "Full Source",
        code: `use axum::{
    extract::{Extension, Path},
    http::StatusCode,
    response::{IntoResponse, Json},
    routing::{delete, get, post},
    Router,
};
use guarantee::{state, attest, Encrypted, crypto::Encryptable};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Encrypted, Serialize, Deserialize, Clone, Debug)]
struct CacheEntry {
    key: String,
    #[encrypt]
    value: String,
    sensitive: bool,
}

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

struct MockRedis {
    data: RwLock<HashMap<String, String>>,
}

impl MockRedis {
    fn new() -> Self {
        Self { data: RwLock::new(HashMap::new()) }
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

#[derive(Deserialize)]
struct SetCacheRequest {
    value: String,
    #[serde(default)]
    sensitive: bool,
}

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
        redis.set(&format!("cache:{key}"), &encrypted.value).await;
        redis.set(&format!("meta:{key}"), "sensitive").await;
    } else {
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

async fn delete_cache(
    Extension(redis): Extension<Arc<MockRedis>>,
    Path(key): Path<String>,
) -> impl IntoResponse {
    let deleted = redis.del(&format!("cache:{key}")).await;
    redis.del(&format!("meta:{key}")).await;
    Json(serde_json::json!({"deleted": deleted, "key": key}))
}

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

#[tokio::main]
async fn main() {
    let port = std::env::var("PORT").unwrap_or_else(|_| "8080".to_string());
    let state = TeeState::initialize(std::path::Path::new("./sealed"))
        .expect("Failed to initialize TeeState");
    let redis = Arc::new(MockRedis::new());

    println!("Encrypted Redis Cache on port {port}");

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
}`,
        lang: "rust",
      },
      {
        heading: "Key Points",
        list: [
          "Conditional encryption: only values with sensitive: true are encrypted",
          "A meta: key tracks whether each cache entry is encrypted or plaintext",
          "CacheStats (MRENCLAVE) tracks hit rates and resets on redeploy",
          "CacheConfig (MRSIGNER) stores persistent cache configuration",
          "The EncryptedCacheEntry is reconstructed manually for decryption",
          "Replace MockRedis with the redis crate for real Redis integration",
          "Both set_cache and get_cache are attested -- every response is signed",
        ],
      },
    ],
  },

  // =========================================================================
  // WebSocket RA-TLS
  // =========================================================================
  {
    slug: "websocket-ratls",
    title: "WebSocket Over RA-TLS",
    lead: "Real-time attested data streaming. The TLS handshake verifies the SGX quote — the entire WebSocket channel is authenticated to the enclave with zero per-message overhead.",
    section: "Examples",
    body: [
      {
        heading: "Overview",
        text: "This example combines WebSocket real-time streaming with RA-TLS attestation. The TLS certificate carries the SGX attestation quote, so by the time the WebSocket connection is established, the client has cryptographic proof they're talking to a genuine enclave. No per-message signing needed — the entire channel is attested at the transport layer.",
      },
      {
        heading: "Run It",
        code: `# HTTP mode (dev, no SGX)
cargo run --example websocket-ratls

# With RA-TLS (attested TLS)
cargo run --example websocket-ratls --features ra-tls`,
        lang: "bash",
      },
      {
        heading: "Connect",
        code: `# Install wscat: npm install -g wscat
wscat -c ws://localhost:8080/ws

# Subscribe to price feed
> {"type":"subscribe","channel":"prices"}
< {"type":"subscribed","channel":"prices"}

# Prices stream every 2 seconds
< {"type":"price_update","channel":"prices","data":{"symbol":"BTC","price":67150.00,...}}
< {"type":"price_update","channel":"prices","data":{"symbol":"ETH","price":3525.00,...}}

# Unsubscribe
> {"type":"unsubscribe","channel":"prices"}

# Ping/pong heartbeat
> {"type":"ping"}
< {"type":"pong"}`,
        lang: "bash",
      },
      {
        heading: "State Management",
        text: "The example uses two-tier sealed state. StreamStats (MRENCLAVE) tracks connection counts and resets on redeploy. StreamConfig (MRSIGNER) holds persistent settings that survive code updates.",
        code: `#[derive(Serialize, Deserialize, Default, Clone, Debug)]
struct StreamStats {
    total_connections: u64,
    total_messages_sent: u64,
    active_subscriptions: u64,
}

#[derive(Serialize, Deserialize, Default, Clone, Debug)]
struct StreamConfig {
    max_clients: u32,
    price_update_interval_ms: u64,
}

state! {
    #[mrenclave]
    StreamStats,

    #[mrsigner]
    StreamConfig,
}`,
        lang: "rust",
      },
      {
        heading: "WebSocket Handler",
        text: "The handler upgrades HTTP to WebSocket. Clients subscribe to channels and receive real-time updates via a Tokio broadcast channel. The connection is already attested via RA-TLS.",
        code: `async fn ws_handler(
    ws: WebSocketUpgrade,
    Extension(tee_state): Extension<Arc<RwLock<TeeState>>>,
    Extension(price_tx): Extension<broadcast::Sender<PriceUpdate>>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, tee_state, price_tx))
}

async fn handle_socket(
    mut socket: WebSocket,
    tee_state: Arc<RwLock<TeeState>>,
    price_tx: broadcast::Sender<PriceUpdate>,
) {
    let mut price_rx = price_tx.subscribe();
    let mut subscribed = false;

    loop {
        tokio::select! {
            // Handle client messages (subscribe/unsubscribe/ping)
            msg = socket.recv() => { /* ... */ }

            // Forward price updates to subscribed clients
            update = price_rx.recv() => {
                if let Ok(price) = update {
                    if subscribed {
                        let json = serde_json::to_string(&price).unwrap_or_default();
                        if socket.send(Message::Text(json.into())).await.is_err() {
                            break;
                        }
                    }
                }
            }
        }
    }
}`,
        lang: "rust",
      },
      {
        heading: "Dual Mode Server",
        text: "In dev mode, runs as plain HTTP WebSocket. With the ra-tls feature flag and USE_RATLS=1, starts dual-port: HTTPS with RA-TLS cert on 8443 + HTTP on 8080.",
        code: `let app = Router::new()
    .route("/ws", get(ws_handler))
    .route("/stats", get(get_stats))
    .route("/.well-known/tee-attestation", get(attestation_info))
    .layer(Extension(tee_state))
    .layer(Extension(price_tx));

#[cfg(feature = "ra-tls")]
{
    // HTTPS with SGX quote in TLS cert + plain HTTP for health checks
    guarantee::serve_ra_tls(app, "ws-service", "0.0.0.0:8443", "0.0.0.0:8080").await?;
}`,
        lang: "rust",
      },
      {
        heading: "Client Messages",
        table: {
          headers: ["Type", "Payload", "Description"],
          rows: [
            ["subscribe", '{"type":"subscribe","channel":"prices"}', "Start receiving price updates"],
            ["unsubscribe", '{"type":"unsubscribe","channel":"prices"}', "Stop receiving updates"],
            ["ping", '{"type":"ping"}', "Heartbeat — server replies with pong"],
          ],
        },
      },
      {
        heading: "Server Messages",
        table: {
          headers: ["Type", "Description"],
          rows: [
            ["connected", "Sent on connection — includes welcome message"],
            ["subscribed", "Confirms subscription to a channel"],
            ["unsubscribed", "Confirms unsubscription"],
            ["price_update", "Real-time price data (symbol, price, timestamp, source)"],
            ["pong", "Reply to client ping"],
            ["error", "Invalid message format"],
          ],
        },
      },
      {
        heading: "Key Points",
        list: [
          "No per-message signing — RA-TLS authenticates the entire channel at the TLS layer",
          "broadcast::channel fans out price updates to all connected WebSocket clients",
          "REST endpoints alongside WebSocket use #[attest] for per-response attestation (belt and suspenders)",
          "Dev mode works without SGX — same code, same protocol, plain HTTP",
          "StreamStats sealed with MRENCLAVE resets on redeploy (ephemeral counters)",
          "StreamConfig sealed with MRSIGNER persists across code updates",
        ],
      },
    ],
  },
];
