//! Header wire-format roundtrip.

use lurpax::constants::{
    CHUNK_PLAINTEXT_SIZE, DEFAULT_ARGON2_ITERATIONS, DEFAULT_ARGON2_MEM_KIB,
    DEFAULT_ARGON2_PARALLELISM, HEADER_VERSION_V1, KDF_ARGON2ID, RS_DATA_SHARDS_PER_GROUP,
    RS_PARITY_SHARDS_PER_GROUP,
};
use lurpax::vault::Header;

#[test]
fn header_roundtrip() {
    let h = Header {
        version: HEADER_VERSION_V1,
        kdf_algorithm: KDF_ARGON2ID,
        argon2_mem_kib: DEFAULT_ARGON2_MEM_KIB,
        argon2_iterations: DEFAULT_ARGON2_ITERATIONS,
        argon2_parallelism: DEFAULT_ARGON2_PARALLELISM,
        salt: [7u8; 32],
        base_nonce: [8u8; 24],
        key_commitment: [9u8; 32],
        chunk_plaintext_size: CHUNK_PLAINTEXT_SIZE,
        chunk_count: 3,
        compressed_payload_size: CHUNK_PLAINTEXT_SIZE as u64 * 2 + 100,
        rs_data_shards_per_group: RS_DATA_SHARDS_PER_GROUP,
        rs_parity_shards_per_group: RS_PARITY_SHARDS_PER_GROUP,
        yubi_required: false,
        yubi_slot: 0,
        yubi_challenge: [0u8; 32],
    };
    h.validate_schema().unwrap();
    let b = h.to_bytes();
    let h2 = Header::from_bytes_exact(&b).unwrap();
    assert_eq!(h, h2);
}

fn valid_header() -> Header {
    Header {
        version: HEADER_VERSION_V1,
        kdf_algorithm: KDF_ARGON2ID,
        argon2_mem_kib: DEFAULT_ARGON2_MEM_KIB,
        argon2_iterations: DEFAULT_ARGON2_ITERATIONS,
        argon2_parallelism: DEFAULT_ARGON2_PARALLELISM,
        salt: [7u8; 32],
        base_nonce: [8u8; 24],
        key_commitment: [9u8; 32],
        chunk_plaintext_size: CHUNK_PLAINTEXT_SIZE,
        chunk_count: 3,
        compressed_payload_size: CHUNK_PLAINTEXT_SIZE as u64 * 2 + 100,
        rs_data_shards_per_group: RS_DATA_SHARDS_PER_GROUP,
        rs_parity_shards_per_group: RS_PARITY_SHARDS_PER_GROUP,
        yubi_required: false,
        yubi_slot: 0,
        yubi_challenge: [0u8; 32],
    }
}

#[test]
fn truncated_header_rejected() {
    let bytes = valid_header().to_bytes();
    let truncated = &bytes[..bytes.len() / 2];
    let err = Header::from_bytes_exact(truncated).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("truncated"), "expected truncated, got: {msg}");
}

#[test]
fn trailing_bytes_rejected() {
    let mut bytes = valid_header().to_bytes();
    bytes.push(0xFF);
    let err = Header::from_bytes_exact(&bytes).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("trailing"), "expected trailing, got: {msg}");
}

#[test]
fn unsupported_version_rejected() {
    let h = valid_header();
    let mut bytes = h.to_bytes();
    // Version occupies the first two bytes (LE u16).
    bytes[0] = 99;
    bytes[1] = 0;
    let err = Header::from_bytes_exact(&bytes).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("unsupported version"),
        "expected unsupported version, got: {msg}"
    );
}

#[test]
fn out_of_policy_kdf_rejected() {
    let mut h = valid_header();
    h.argon2_mem_kib = 100; // below MIN_ARGON2_MEM_KIB (262 144)
    let bytes = h.to_bytes();
    let err = Header::from_bytes_exact(&bytes).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("argon2") && msg.contains("policy"),
        "expected argon2 policy error, got: {msg}"
    );
}

#[test]
fn zero_chunk_count_rejected() {
    let mut h = valid_header();
    h.chunk_count = 0;
    h.compressed_payload_size = 0;
    let bytes = h.to_bytes();
    let err = Header::from_bytes_exact(&bytes).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("chunk_count") && msg.contains("zero"),
        "expected chunk_count zero error, got: {msg}"
    );
}
