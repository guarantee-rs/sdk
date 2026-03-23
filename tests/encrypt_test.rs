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

    let encrypted = state.encrypt_user_record(&record).expect("encrypt");

    // Plaintext fields unchanged
    assert_eq!(encrypted.user_id, "alice");
    assert_eq!(encrypted.email, "alice@example.com");

    // Encrypted fields are ciphertext
    assert!(encrypted.ssn.starts_with("enc:v1:"));
    assert!(encrypted.bank_account.starts_with("enc:v1:"));
    assert_ne!(encrypted.ssn, "123-45-6789");

    // Decrypt
    let decrypted = state.decrypt_user_record(&encrypted).expect("decrypt");
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

    let enc1 = state.encrypt_user_record(&record).expect("encrypt 1");
    let enc2 = state.encrypt_user_record(&record).expect("encrypt 2");

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
fn per_type_key_differs_from_raw_master_key() {
    // Encrypting with a per-type derived key should produce ciphertext
    // that cannot be decrypted with a different key (including raw master key).
    let record = UserRecord {
        user_id: "dave".into(),
        ssn: "111-22-3333".into(),
        bank_account: "5555555555".into(),
        email: "dave@example.com".into(),
    };

    let dir = tempfile::tempdir().expect("tempdir");
    let state = TeeState::initialize(dir.path()).expect("init");

    let encrypted = state.encrypt_user_record(&record).expect("encrypt");

    // Attempting to decrypt with a wrong key should fail
    let wrong_key = [0u8; 32];
    let result = UserRecord::decrypt_from(&encrypted, &wrong_key);
    assert!(result.is_err());
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

    let encrypted = state.encrypt_user_record(&record).expect("encrypt");

    // Should serialize to JSON (for storage in DB, Redis, etc.)
    let json = serde_json::to_string(&encrypted).expect("serialize");
    let deserialized: EncryptedUserRecord =
        serde_json::from_str(&json).expect("deserialize");

    // And decrypt from the deserialized version
    let decrypted = state.decrypt_user_record(&deserialized).expect("decrypt");
    assert_eq!(decrypted, record);
}

#[test]
fn per_type_key_is_deterministic_across_reinit() {
    let dir = tempfile::tempdir().expect("tempdir");

    let record = UserRecord {
        user_id: "eve".into(),
        ssn: "999-88-7777".into(),
        bank_account: "1234567890".into(),
        email: "eve@example.com".into(),
    };

    // Encrypt with first state instance
    let state1 = TeeState::initialize(dir.path()).expect("init");
    state1.seal(dir.path()).expect("seal");
    let encrypted = state1.encrypt_user_record(&record).expect("encrypt");

    // Re-initialize (unseal) and decrypt -- should work because same master key
    let state2 = TeeState::initialize(dir.path()).expect("reinit");
    let decrypted = state2.decrypt_user_record(&encrypted).expect("decrypt");
    assert_eq!(decrypted, record);
}

#[test]
fn versioned_encrypt_decrypt_roundtrip() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state = TeeState::initialize(dir.path()).expect("init");

    let record = UserRecord {
        user_id: "frank".into(),
        ssn: "555-66-7777".into(),
        bank_account: "1111111111".into(),
        email: "frank@example.com".into(),
    };

    let encrypted = state.encrypt_user_record(&record).expect("encrypt");

    // Versioned format uses "enc:v1:k<N>:" prefix
    assert!(encrypted.ssn.starts_with("enc:v1:k"));
    assert!(encrypted.bank_account.starts_with("enc:v1:k"));

    let decrypted = state.decrypt_user_record(&encrypted).expect("decrypt");
    assert_eq!(decrypted, record);
}

#[test]
fn rotate_then_decrypt_old_data() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut state = TeeState::initialize(dir.path()).expect("init");

    let record = UserRecord {
        user_id: "grace".into(),
        ssn: "888-99-0000".into(),
        bank_account: "2222222222".into(),
        email: "grace@example.com".into(),
    };

    // Encrypt with original key (version 1)
    let encrypted = state.encrypt_user_record(&record).expect("encrypt");

    // Rotate key
    state.rotate_master_key().expect("rotate");
    assert_eq!(state.signer().current_key_version, 2);
    assert_eq!(state.signer().retired_keys.len(), 1);

    // Old data should still decrypt using the retired key
    let decrypted = state.decrypt_user_record(&encrypted).expect("decrypt after rotation");
    assert_eq!(decrypted, record);
}

#[test]
fn rotate_multiple_times_decrypt_all() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut state = TeeState::initialize(dir.path()).expect("init");

    let record = UserRecord {
        user_id: "heidi".into(),
        ssn: "111-11-1111".into(),
        bank_account: "3333333333".into(),
        email: "heidi@example.com".into(),
    };

    // Encrypt with version 1
    let enc_v1 = state.encrypt_user_record(&record).expect("encrypt v1");

    // Rotate to version 2
    state.rotate_master_key().expect("rotate to v2");
    let enc_v2 = state.encrypt_user_record(&record).expect("encrypt v2");

    // Rotate to version 3
    state.rotate_master_key().expect("rotate to v3");
    let enc_v3 = state.encrypt_user_record(&record).expect("encrypt v3");

    assert_eq!(state.signer().current_key_version, 3);
    assert_eq!(state.signer().retired_keys.len(), 2);

    // All versions should decrypt
    let dec_v1 = state.decrypt_user_record(&enc_v1).expect("decrypt v1");
    let dec_v2 = state.decrypt_user_record(&enc_v2).expect("decrypt v2");
    let dec_v3 = state.decrypt_user_record(&enc_v3).expect("decrypt v3");
    assert_eq!(dec_v1, record);
    assert_eq!(dec_v2, record);
    assert_eq!(dec_v3, record);
}

#[test]
fn rotation_persists_across_seal_unseal() {
    let dir = tempfile::tempdir().expect("tempdir");

    let record = UserRecord {
        user_id: "ivan".into(),
        ssn: "444-55-6666".into(),
        bank_account: "4444444444".into(),
        email: "ivan@example.com".into(),
    };

    let encrypted;
    {
        let mut state = TeeState::initialize(dir.path()).expect("init");
        encrypted = state.encrypt_user_record(&record).expect("encrypt v1");
        state.rotate_master_key().expect("rotate");
        state.seal(dir.path()).expect("seal");
    }

    // Re-initialize from sealed state — retired keys should be preserved
    let state = TeeState::initialize(dir.path()).expect("reinit");
    assert_eq!(state.signer().current_key_version, 2);
    assert_eq!(state.signer().retired_keys.len(), 1);
    let decrypted = state.decrypt_user_record(&encrypted).expect("decrypt after reinit");
    assert_eq!(decrypted, record);
}
