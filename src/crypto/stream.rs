//! STREAM-style chunked XChaCha20-Poly1305 with per-chunk AAD.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

use crate::constants::MAGIC;
use crate::errors::{LurpaxError, Result};
use crate::vault::header::Header;

/// Derives the 24-byte nonce for `chunk_index` from `base_nonce`.
pub fn derive_chunk_nonce(base_nonce: &[u8; 24], chunk_index: u64) -> [u8; 24] {
    // AUDIT: XOR with chunk_index guarantees unique nonces without per-chunk randomness
    let mut out = [0u8; 24];
    out[..16].copy_from_slice(&base_nonce[..16]);
    let mut low = [0u8; 8];
    low.copy_from_slice(&base_nonce[16..24]);
    let low_u = u64::from_le_bytes(low) ^ chunk_index;
    out[16..24].copy_from_slice(&low_u.to_le_bytes());
    out
}

fn header_aad(header_len: u32, header_body: &[u8]) -> Vec<u8> {
    let mut a = Vec::with_capacity(5 + 4 + header_body.len());
    a.extend_from_slice(MAGIC);
    a.extend_from_slice(&header_len.to_le_bytes());
    a.extend_from_slice(header_body);
    a
}

fn chunk_aad(
    header_len: u32,
    header_body: &[u8],
    chunk_index: u64,
    is_final: bool,
) -> Vec<u8> {
    // AUDIT: chunk_index in AAD prevents reordering; is_final prevents truncation
    let mut v = header_aad(header_len, header_body);
    v.extend_from_slice(&chunk_index.to_le_bytes());
    v.push(u8::from(is_final));
    v
}

/// Encrypts all plaintext chunks; each ciphertext is padded to `shard_size` with zeros.
pub fn encrypt_all_chunks(
    header: &Header,
    header_body: &[u8],
    compressed: &[u8],
    enc_key: &[u8; 32],
) -> Result<Vec<Zeroizing<Vec<u8>>>> {
    let chunk_plain =
        usize::try_from(header.chunk_plaintext_size).map_err(|_| LurpaxError::Overflow)?;
    let n = header.chunk_count as usize;
    let total = compressed.len();
    let expected_total =
        usize::try_from(header.compressed_payload_size).map_err(|_| LurpaxError::Overflow)?;
    if total != expected_total {
        return Err(LurpaxError::Crypto("compressed size mismatch".into()));
    }
    // AUDIT: XChaCha20-Poly1305 192-bit nonce eliminates birthday-bound collision risk
    let cipher = XChaCha20Poly1305::new(Key::from_slice(enc_key));
    let header_len = u32::try_from(header_body.len()).map_err(|_| LurpaxError::Overflow)?;
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let start = i
            .checked_mul(chunk_plain)
            .ok_or(LurpaxError::Overflow)?;
        let end = if i + 1 == n {
            total
        } else {
            start
                .checked_add(chunk_plain)
                .ok_or(LurpaxError::Overflow)?
        };
        if end > total || start > end {
            return Err(LurpaxError::Crypto("chunk bounds".into()));
        }
        let pt = &compressed[start..end];
        let is_final = i + 1 == n;
        let nonce_b = derive_chunk_nonce(&header.base_nonce, i as u64);
        let nonce = XNonce::from_slice(&nonce_b);
        let aad = chunk_aad(header_len, header_body, i as u64, is_final);
        let ct = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: pt,
                    aad: aad.as_slice(),
                },
            )
            .map_err(|_| LurpaxError::Crypto("aead encrypt".into()))?;
        let shard_sz = chunk_plain
            .checked_add(16)
            .ok_or(LurpaxError::Overflow)?;
        if ct.len() > shard_sz {
            return Err(LurpaxError::Crypto("ciphertext too long".into()));
        }
        let mut shard = vec![0u8; shard_sz];
        shard[..ct.len()].copy_from_slice(&ct);
        out.push(Zeroizing::new(shard));
    }
    Ok(out)
}

/// Attempts to decrypt a single chunk. Returns `Ok(plaintext)` or `Err` on AEAD failure.
pub fn decrypt_single_chunk(
    header: &Header,
    header_body: &[u8],
    shard: &[u8],
    chunk_index: usize,
    enc_key: &[u8; 32],
) -> Result<Vec<u8>> {
    let n = header.chunk_count as usize;
    let chunk_plain =
        usize::try_from(header.chunk_plaintext_size).map_err(|_| LurpaxError::Overflow)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(enc_key));
    let header_len = u32::try_from(header_body.len()).map_err(|_| LurpaxError::Overflow)?;
    let is_final = chunk_index + 1 == n;
    let nonce_b = derive_chunk_nonce(&header.base_nonce, chunk_index as u64);
    let nonce = XNonce::from_slice(&nonce_b);
    let aad = chunk_aad(header_len, header_body, chunk_index as u64, is_final);
    let ct_len = if is_final {
        let last_pt = crate::vault::header::last_chunk_plaintext_size(header)?;
        let last_ct = last_pt
            .checked_add(16)
            .ok_or(LurpaxError::Overflow)? as usize;
        if last_ct > shard.len() {
            return Err(LurpaxError::DecryptAuthFailed);
        }
        last_ct
    } else {
        chunk_plain
            .checked_add(16)
            .ok_or(LurpaxError::Overflow)?
    };
    let ct = &shard[..ct_len];
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: ct,
                aad: aad.as_slice(),
            },
        )
        .map_err(|_| LurpaxError::DecryptAuthFailed)
}

/// Decrypts padded shards back into the compressed payload.
pub fn decrypt_all_chunks(
    header: &Header,
    header_body: &[u8],
    shards: &[Zeroizing<Vec<u8>>],
    enc_key: &[u8; 32],
) -> Result<Zeroizing<Vec<u8>>> {
    let n = header.chunk_count as usize;
    if shards.len() != n {
        return Err(LurpaxError::InvalidVault("shard count".into()));
    }
    let mut plain = Vec::new();
    for (i, zshard) in shards.iter().enumerate().take(n) {
        let pt = decrypt_single_chunk(header, header_body, zshard.as_slice(), i, enc_key)?;
        plain.extend_from_slice(&pt);
    }
    if plain.len() as u64 != header.compressed_payload_size {
        return Err(LurpaxError::DecryptAuthFailed);
    }
    Ok(Zeroizing::new(plain))
}
