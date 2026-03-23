use guarantee::crypto::Encryptable;
use guarantee::{state, Encrypted};
use serde::{Deserialize, Serialize};

#[derive(Encrypted, Serialize, Deserialize, Clone, Debug, PartialEq)]
struct UserRecord {
    user_id: String,
    #[encrypt]
    ssn: String,
    #[encrypt]
    bank_account: String,
    email: String,
}

#[derive(Serialize, Deserialize, Default, Clone, Debug)]
struct AppSecrets {
    internal_token: String,
}

#[derive(Serialize, Deserialize, Default, Clone, Debug)]
struct SessionData {
    counter: u32,
}

state! {
    #[mrenclave]
    SessionData,

    #[mrsigner]
    AppSecrets,

    #[external]
    UserRecord,
}

#[test]
fn encrypt_decrypt_roundtrip() {
    let record = UserRecord {
        user_id: "alice".into(),
        ssn: "123-45-6789".into(),
        bank_account: "9876543210".into(),
        email: "alice@example.com".into(),
    };

    let dir = tempfile::tempdir().expect("tempdir");
    let state = TeeState::initialize(dir.path()).expect("init");

    let encrypted = state.encrypt(&record).expect("encrypt");

    // Plaintext fields unchanged
    assert_eq!(encrypted.user_id, "alice");
    assert_eq!(encrypted.email, "alice@example.com");

    // Encrypted fields are ciphertext
    assert!(encrypted.ssn.starts_with("enc:v1:"));
    assert!(encrypted.bank_account.starts_with("enc:v1:"));
    assert_ne!(encrypted.ssn, "123-45-6789");

    // Decrypt
    let decrypted: UserRecord = state.decrypt(&encrypted).expect("decrypt");
    assert_eq!(decrypted, record);
}

#[test]
fn encrypted_fields_differ_each_time() {
    let record = UserRecord {
        user_id: "bob".into(),
        ssn: "same-value".into(),
        bank_account: "same-value".into(),
        email: "bob@example.com".into(),
    };

    let dir = tempfile::tempdir().expect("tempdir");
    let state = TeeState::initialize(dir.path()).expect("init");

    let enc1 = state.encrypt(&record).expect("encrypt 1");
    let enc2 = state.encrypt(&record).expect("encrypt 2");

    // Same plaintext, different ciphertext (unique nonces)
    assert_ne!(enc1.ssn, enc2.ssn);
}

#[test]
fn wrong_key_fails_decrypt() {
    let record = UserRecord {
        user_id: "carol".into(),
        ssn: "secret".into(),
        bank_account: "secret".into(),
        email: "carol@example.com".into(),
    };

    let key1 = [1u8; 32];
    let key2 = [2u8; 32];

    let encrypted = record.encrypt(&key1).expect("encrypt");
    let result = UserRecord::decrypt_from(&encrypted, &key2);
    assert!(result.is_err());
}

#[test]
fn derive_key_is_deterministic() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state = TeeState::initialize(dir.path()).expect("init");

    let k1 = state.derive_key(b"database");
    let k2 = state.derive_key(b"database");
    let k3 = state.derive_key(b"redis");

    assert_eq!(k1, k2); // same purpose = same key
    assert_ne!(k1, k3); // different purpose = different key
}

#[test]
fn derive_key_differs_from_master() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state = TeeState::initialize(dir.path()).expect("init");

    let derived = state.derive_key(b"test");
    assert_ne!(&derived, state.signer().master_key());
}

#[test]
fn encrypted_struct_is_serializable() {
    let record = UserRecord {
        user_id: "dave".into(),
        ssn: "111-22-3333".into(),
        bank_account: "5555555555".into(),
        email: "dave@example.com".into(),
    };

    let dir = tempfile::tempdir().expect("tempdir");
    let state = TeeState::initialize(dir.path()).expect("init");

    let encrypted = state.encrypt(&record).expect("encrypt");

    // Should serialize to JSON (for storage in DB, Redis, etc.)
    let json = serde_json::to_string(&encrypted).expect("serialize");
    let deserialized: EncryptedUserRecord =
        serde_json::from_str(&json).expect("deserialize");

    // And decrypt from the deserialized version
    let decrypted: UserRecord = state.decrypt(&deserialized).expect("decrypt");
    assert_eq!(decrypted, record);
}
