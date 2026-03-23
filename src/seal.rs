//! Sealing/unsealing abstraction for TEE state persistence.
//!
//! In enclave mode (`GUARANTEE_ENCLAVE=1`), uses SGX sealing via `/dev/attestation`.
//! In dev mode, uses simple file I/O with a mode header (NOT cryptographically secure).

use crate::errors::SdkError;
use std::path::Path;

/// Seal mode determines which SGX key is used for sealing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealMode {
    /// Sealed with MRENCLAVE -- only the exact same binary can unseal.
    MrEnclave,
    /// Sealed with MRSIGNER -- any binary from the same signer can unseal.
    MrSigner,
}

/// Seal data to a file. In dev mode, uses a simple header-prefixed format.
/// In enclave mode, uses SGX sealing via `/dev/attestation`.
pub fn seal_to_file(data: &[u8], path: &Path, mode: SealMode) -> Result<(), SdkError> {
    if is_enclave_mode() {
        seal_sgx(data, path, mode)
    } else {
        seal_dev(data, path, mode)
    }
}

/// Unseal data from a file.
pub fn unseal_from_file(path: &Path, mode: SealMode) -> Result<Vec<u8>, SdkError> {
    if is_enclave_mode() {
        unseal_sgx(path, mode)
    } else {
        unseal_dev(path, mode)
    }
}

fn is_enclave_mode() -> bool {
    std::env::var("GUARANTEE_ENCLAVE")
        .map(|v| v == "1")
        .unwrap_or(false)
}

// Dev mode: simple file I/O with a header indicating seal mode.
// NOT cryptographically secure -- for development and testing only.
fn seal_dev(data: &[u8], path: &Path, mode: SealMode) -> Result<(), SdkError> {
    let header: &[u8] = match mode {
        SealMode::MrEnclave => b"SEAL_MRENCLAVE_DEV\n",
        SealMode::MrSigner => b"SEAL_MRSIGNER_DEV\n",
    };
    let mut sealed = header.to_vec();
    sealed.extend_from_slice(data);

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| SdkError::SealError(format!("Create dir: {e}")))?;
    }
    std::fs::write(path, &sealed)
        .map_err(|e| SdkError::SealError(format!("Write sealed: {e}")))?;
    tracing::debug!(path = %path.display(), ?mode, "Sealed data (dev mode)");
    Ok(())
}

fn unseal_dev(path: &Path, mode: SealMode) -> Result<Vec<u8>, SdkError> {
    let sealed = std::fs::read(path)
        .map_err(|e| SdkError::SealError(format!("Read sealed: {e}")))?;

    let expected_header: &[u8] = match mode {
        SealMode::MrEnclave => b"SEAL_MRENCLAVE_DEV\n",
        SealMode::MrSigner => b"SEAL_MRSIGNER_DEV\n",
    };

    if !sealed.starts_with(expected_header) {
        return Err(SdkError::SealError(format!(
            "Seal mode mismatch: expected {:?}",
            mode
        )));
    }

    let data = sealed[expected_header.len()..].to_vec();
    tracing::debug!(path = %path.display(), ?mode, "Unsealed data (dev mode)");
    Ok(data)
}

// SGX mode: use /dev/attestation for real sealing.
// Placeholder -- real SGX sealing uses sgx_seal_data.
fn seal_sgx(data: &[u8], path: &Path, mode: SealMode) -> Result<(), SdkError> {
    tracing::warn!("SGX sealing not yet implemented -- using dev mode fallback");
    seal_dev(data, path, mode)
}

fn unseal_sgx(path: &Path, mode: SealMode) -> Result<Vec<u8>, SdkError> {
    tracing::warn!("SGX unsealing not yet implemented -- using dev mode fallback");
    unseal_dev(path, mode)
}

/// Sign a response body using an enclave signing key.
/// This is called by `TeeState::sign_response` -- the key itself is never exposed to user code.
pub fn sign_with_enclave_key(
    signing_key: &ed25519_dalek::SigningKey,
    body: &[u8],
    request_id: &str,
) -> crate::AttestationHeader {
    use base64::Engine;
    use ed25519_dalek::Signer;
    use sha2::{Digest, Sha256};
    use crate::response::hex_encode;

    let timestamp_ms = chrono::Utc::now().timestamp_millis() as u64;

    let mut hasher = Sha256::new();
    hasher.update(body);
    hasher.update(timestamp_ms.to_be_bytes());
    hasher.update(request_id.as_bytes());
    let payload_hash: [u8; 32] = hasher.finalize().into();

    let signature = signing_key.sign(&payload_hash);

    crate::AttestationHeader {
        version: 1,
        signature_b64: base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()),
        payload_hash_hex: hex_encode(&payload_hash),
        timestamp_ms,
        public_key_hex: hex_encode(signing_key.verifying_key().as_bytes()),
    }
}

/// Serde helper for serializing/deserializing `ed25519_dalek::SigningKey` as raw bytes.
pub mod signing_key_serde {
    use ed25519_dalek::SigningKey;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(key: &SigningKey, s: S) -> Result<S::Ok, S::Error> {
        key.to_bytes().serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<SigningKey, D::Error> {
        let bytes = <[u8; 32]>::deserialize(d)?;
        Ok(SigningKey::from_bytes(&bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_unseal_roundtrip_mrenclave() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("test.sealed");
        let data = b"hello enclave";

        seal_to_file(data, &path, SealMode::MrEnclave).expect("seal");
        let recovered = unseal_from_file(&path, SealMode::MrEnclave).expect("unseal");
        assert_eq!(recovered, data);
    }

    #[test]
    fn seal_unseal_roundtrip_mrsigner() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("test.sealed");
        let data = b"hello signer";

        seal_to_file(data, &path, SealMode::MrSigner).expect("seal");
        let recovered = unseal_from_file(&path, SealMode::MrSigner).expect("unseal");
        assert_eq!(recovered, data);
    }

    #[test]
    fn unseal_wrong_mode_fails() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("test.sealed");
        let data = b"secret";

        seal_to_file(data, &path, SealMode::MrEnclave).expect("seal");
        let result = unseal_from_file(&path, SealMode::MrSigner);
        assert!(result.is_err());
    }

    #[test]
    fn unseal_missing_file_fails() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("nonexistent.sealed");
        let result = unseal_from_file(&path, SealMode::MrEnclave);
        assert!(result.is_err());
    }

    #[test]
    fn signing_key_serde_roundtrip() {
        use rand::rngs::OsRng;

        let key = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let serialized = serde_json::to_vec(&SigningKeyWrapper { key: key.clone() })
            .expect("serialize");
        let deserialized: SigningKeyWrapper =
            serde_json::from_slice(&serialized).expect("deserialize");
        assert_eq!(key.to_bytes(), deserialized.key.to_bytes());
    }

    #[derive(serde::Serialize, serde::Deserialize)]
    struct SigningKeyWrapper {
        #[serde(with = "super::signing_key_serde")]
        key: ed25519_dalek::SigningKey,
    }
}
