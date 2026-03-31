use lurpax::crypto::kdf::{argon2_derive_master, compose_ikm, derive_subkeys};
use lurpax::constants::ARGON2_OUTPUT_LEN;

#[test]
fn compose_ikm_length_prefix() {
    let ikm = compose_ikm(b"hello", None).unwrap();
    let len_prefix = u32::from_le_bytes(ikm[..4].try_into().unwrap());
    assert_eq!(len_prefix, 5);
    assert_eq!(&ikm[4..9], b"hello");
    assert_eq!(ikm.len(), 4 + 5);
}

#[test]
fn compose_ikm_with_yubi() {
    let ikm = compose_ikm(b"pw", Some(b"resp")).unwrap();

    let pw_len = u32::from_le_bytes(ikm[..4].try_into().unwrap());
    assert_eq!(pw_len, 2);
    assert_eq!(&ikm[4..6], b"pw");

    let resp_len = u32::from_le_bytes(ikm[6..10].try_into().unwrap());
    assert_eq!(resp_len, 4);
    assert_eq!(&ikm[10..14], b"resp");
    assert_eq!(ikm.len(), 4 + 2 + 4 + 4);
}

#[test]
fn empty_password_rejected() {
    let result = compose_ikm(b"", None);
    assert!(result.is_err());
}

#[test]
fn too_long_password_rejected() {
    let big = vec![0u8; 9000];
    let result = compose_ikm(&big, None);
    assert!(result.is_err());
}

#[test]
fn subkey_derivation_properties() {
    let ikm = compose_ikm(b"test-password-for-kdf", None).unwrap();
    let salt = [0x42u8; 32];
    let mut master = [0u8; ARGON2_OUTPUT_LEN];

    argon2_derive_master(&ikm, &salt, 262144, 3, 4, &mut master).unwrap();

    assert_eq!(master.len(), 64);
    assert_ne!(master, [0u8; 64], "master key must not be all zeros");

    let (enc, commit) = derive_subkeys(&master).unwrap();
    assert_eq!(enc.len(), 32);
    assert_eq!(commit.len(), 32);
    assert_ne!(enc, commit, "enc_key and commit_key must differ");
    assert_ne!(enc, [0u8; 32]);
    assert_ne!(commit, [0u8; 32]);
}
