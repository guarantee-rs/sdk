pub mod attestation;
pub mod crypto;
pub mod errors;
pub mod gramine;
pub mod macros;
pub mod response;
pub mod seal;
pub mod types;

pub use attestation::{AttestationMode, EnclaveAttestor};
pub use crypto::Encryptable;
pub use errors::SdkError;
pub use macros::attest;
pub use response::{AttestationHeader, AttestedResponse};
pub use types::{MrEnclave, MrSigner, StartupQuote};

// Re-export proc macros
pub use guarantee_macros::state;
pub use guarantee_macros::Encrypted;
