//! Key commitment via HMAC-SHA256 over `base_nonce` using `commit_key`.

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::errors::{LurpaxError, Result};

type HmacSha256 = Hmac<Sha256>;

/// Computes `HMAC-SHA256(commit_key, base_nonce)`.
pub fn commitment_hmac(commit_key: &[u8; 32], base_nonce: &[u8; 24]) -> Result<[u8; 32]> {
    // AUDIT: commit_key is HKDF-separated from enc_key; compromise of one reveals nothing about the other
    let mut mac = HmacSha256::new_from_slice(commit_key)
        .map_err(|_| LurpaxError::Crypto("hmac key".into()))?;
    mac.update(base_nonce);
    let out = mac.finalize().into_bytes();
    Ok(out.into())
}

/// Constant-time verification of stored commitment.
pub fn verify_commitment(
    commit_key: &[u8; 32],
    base_nonce: &[u8; 24],
    expected: &[u8; 32],
) -> Result<()> {
    let got = commitment_hmac(commit_key, base_nonce)?;
    let mut diff = 0u8;
    // AUDIT: constant-time comparison prevents timing side-channel on key commitment
    for (a, b) in got.iter().zip(expected.iter()) {
        diff |= a ^ b;
    }
    if diff != 0 {
        return Err(LurpaxError::DecryptAuthFailed);
    }
    Ok(())
}
