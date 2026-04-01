//! Password-wrapped YubiKey challenge (header v2): challenge is not stored in plaintext.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

use super::kdf::{argon2_derive_wrap_key, compose_ikm};
use crate::errors::{LurpaxError, Result};
use crate::vault::header::Header;

const WRAP_AAD: &[u8] = b"lurpax-yubi-challenge-wrap-v1";

/// Encrypts a 32-byte YubiKey challenge under a password-derived Argon2id subkey.
pub fn seal_challenge(
    password: &[u8],
    challenge_plain: &[u8; 32],
) -> Result<([u8; 32], [u8; 24], [u8; 48])> {
    let mut wrap_salt = [0u8; 32];
    getrandom::getrandom(&mut wrap_salt).map_err(|_| LurpaxError::RandomUnavailable)?;
    let mut nonce = [0u8; 24];
    getrandom::getrandom(&mut nonce).map_err(|_| LurpaxError::RandomUnavailable)?;
    let ikm = compose_ikm(password, None)?;
    let mut key = Zeroizing::new([0u8; 32]);
    argon2_derive_wrap_key(ikm.as_ref(), &wrap_salt, &mut *key)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key.as_ref()));
    let ct = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: challenge_plain.as_slice(),
                aad: WRAP_AAD,
            },
        )
        .map_err(|_| LurpaxError::Crypto("challenge wrap encrypt".into()))?;
    if ct.len() != 48 {
        return Err(LurpaxError::Crypto("challenge wrap ciphertext length".into()));
    }
    let mut out_ct = [0u8; 48];
    out_ct.copy_from_slice(&ct);
    Ok((wrap_salt, nonce, out_ct))
}

/// Decrypts the header v2 YubiKey challenge (wrong password → AEAD failure).
pub fn unwrap_challenge(password: &[u8], header: &Header) -> Result<Zeroizing<[u8; 32]>> {
    let ikm = compose_ikm(password, None)?;
    let mut key = Zeroizing::new([0u8; 32]);
    argon2_derive_wrap_key(ikm.as_ref(), &header.yubi_wrap_salt, &mut *key)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key.as_ref()));
    let pt = cipher
        .decrypt(
            XNonce::from_slice(&header.yubi_chal_nonce),
            Payload {
                msg: header.yubi_chal_ciphertext.as_slice(),
                aad: WRAP_AAD,
            },
        )
        .map_err(|_| LurpaxError::DecryptAuthFailed)?;
    if pt.len() != 32 {
        return Err(LurpaxError::DecryptAuthFailed);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&pt);
    Ok(Zeroizing::new(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_unwrap_roundtrip() {
        let pw = b"correct-horse-battery-staple";
        let mut ch = [0xabu8; 32];
        ch[0] = 0x11;
        let (salt, nonce, ct) = seal_challenge(pw, &ch).unwrap();
        let header = Header {
            version: crate::constants::HEADER_VERSION_V2,
            kdf_algorithm: crate::constants::KDF_ARGON2ID,
            argon2_mem_kib: crate::constants::DEFAULT_ARGON2_MEM_KIB,
            argon2_iterations: crate::constants::DEFAULT_ARGON2_ITERATIONS,
            argon2_parallelism: crate::constants::DEFAULT_ARGON2_PARALLELISM,
            salt: [0u8; 32],
            base_nonce: [0u8; 24],
            key_commitment: [0u8; 32],
            chunk_plaintext_size: crate::constants::CHUNK_PLAINTEXT_SIZE,
            chunk_count: 1,
            compressed_payload_size: 1,
            rs_data_shards_per_group: crate::constants::RS_DATA_SHARDS_PER_GROUP,
            rs_parity_shards_per_group: crate::constants::RS_PARITY_SHARDS_PER_GROUP,
            yubi_required: true,
            yubi_slot: 2,
            yubi_challenge: [0u8; 32],
            yubi_wrap_salt: salt,
            yubi_chal_nonce: nonce,
            yubi_chal_ciphertext: ct,
        };
        let got = unwrap_challenge(pw, &header).unwrap();
        assert_eq!(got.as_ref(), &ch);
        assert!(unwrap_challenge(b"wrong-password", &header).is_err());
    }
}
