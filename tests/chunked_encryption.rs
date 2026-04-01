use lurpax::crypto::stream::{decrypt_single_chunk, derive_chunk_nonce, encrypt_all_chunks};
use lurpax::vault::Header;

fn test_header(chunk_count: u64, compressed_payload_size: u64) -> Header {
    Header {
        version: 1,
        kdf_algorithm: 1,
        argon2_mem_kib: 262144,
        argon2_iterations: 3,
        argon2_parallelism: 4,
        salt: [0u8; 32],
        base_nonce: [1u8; 24],
        key_commitment: [0u8; 32],
        chunk_plaintext_size: 65536,
        chunk_count,
        compressed_payload_size,
        rs_data_shards_per_group: 19,
        rs_parity_shards_per_group: 3,
        yubi_required: false,
        yubi_slot: 0,
        yubi_challenge: [0u8; 32],
        yubi_wrap_salt: [0u8; 32],
        yubi_chal_nonce: [0u8; 24],
        yubi_chal_ciphertext: [0u8; 48],
    }
}

#[test]
fn nonce_derivation_uniqueness() {
    let base = [1u8; 24];
    let n0 = derive_chunk_nonce(&base, 0);
    let n1 = derive_chunk_nonce(&base, 1);
    let n2 = derive_chunk_nonce(&base, 2);
    assert_ne!(n0, n1);
    assert_ne!(n1, n2);
    assert_ne!(n0, n2);
}

#[test]
fn nonce_derivation_deterministic() {
    let base = [1u8; 24];
    let a = derive_chunk_nonce(&base, 42);
    let b = derive_chunk_nonce(&base, 42);
    assert_eq!(a, b);
}

#[test]
fn encrypt_decrypt_roundtrip() {
    let data = vec![42u8; 100_000];
    let compressed = zstd::encode_all(&data[..], 3).unwrap();
    let comp_len = compressed.len() as u64;
    let chunk_plain = 65536u64;
    let chunk_count = comp_len.div_ceil(chunk_plain);

    let header = test_header(chunk_count, comp_len);
    let header_body = header.to_bytes();
    let enc_key = [0xABu8; 32];

    let enc_shards = encrypt_all_chunks(&header, &header_body, &compressed, &enc_key).unwrap();
    assert_eq!(enc_shards.len(), chunk_count as usize);

    let mut reassembled = Vec::new();
    for (i, shard) in enc_shards.iter().enumerate() {
        let pt = decrypt_single_chunk(&header, &header_body, shard, i, &enc_key).unwrap();
        reassembled.extend_from_slice(&pt);
    }
    assert_eq!(reassembled.len(), comp_len as usize);
    assert_eq!(reassembled, compressed);
}

#[test]
fn chunk_reorder_rejected() {
    let mut data = vec![0u8; 200_000];
    getrandom::getrandom(&mut data).unwrap();
    let compressed = zstd::encode_all(&data[..], 3).unwrap();
    let comp_len = compressed.len() as u64;
    let chunk_count = comp_len.div_ceil(65536);
    assert!(chunk_count >= 2, "need at least 2 chunks for reorder test");

    let header = test_header(chunk_count, comp_len);
    let header_body = header.to_bytes();
    let enc_key = [0xABu8; 32];

    let enc_shards = encrypt_all_chunks(&header, &header_body, &compressed, &enc_key).unwrap();

    let result = decrypt_single_chunk(&header, &header_body, &enc_shards[0], 1, &enc_key);
    assert!(
        matches!(result, Err(lurpax::LurpaxError::DecryptAuthFailed)),
        "decrypting chunk 0 ciphertext at index 1 must fail"
    );
}

#[test]
fn single_bit_flip_detected() {
    let data = vec![42u8; 100_000];
    let compressed = zstd::encode_all(&data[..], 3).unwrap();
    let comp_len = compressed.len() as u64;
    let chunk_count = comp_len.div_ceil(65536);

    let header = test_header(chunk_count, comp_len);
    let header_body = header.to_bytes();
    let enc_key = [0xABu8; 32];

    let enc_shards = encrypt_all_chunks(&header, &header_body, &compressed, &enc_key).unwrap();

    let mut corrupted = (*enc_shards[0]).clone();
    corrupted[10] ^= 0x01;

    let result = decrypt_single_chunk(&header, &header_body, &corrupted, 0, &enc_key);
    assert!(
        matches!(result, Err(lurpax::LurpaxError::DecryptAuthFailed)),
        "bit-flipped ciphertext must fail AEAD authentication"
    );
}
