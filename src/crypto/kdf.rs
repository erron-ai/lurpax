//! Argon2id master key derivation and HKDF subkey separation.

use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::constants::{
    ARGON2_OUTPUT_LEN, HKDF_INFO_COMMIT, HKDF_INFO_ENC, MAX_PASSWORD_LEN, MIN_PASSWORD_LEN,
    YUBI_CHALLENGE_WRAP_ITERATIONS, YUBI_CHALLENGE_WRAP_MEM_KIB, YUBI_CHALLENGE_WRAP_PARALLELISM,
};
use crate::errors::{LurpaxError, Result};

/// HKDF-derived AEAD key and key-commitment subkey; both zeroed on drop.
pub type DerivedSubkeys = (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>);

/// Builds length-prefixed input keying material for Argon2id.
pub fn compose_ikm(password: &[u8], yubi_response: Option<&[u8]>) -> Result<Zeroizing<Vec<u8>>> {
    // AUDIT: reject empty and oversized passwords before KDF work
    if !(MIN_PASSWORD_LEN..=MAX_PASSWORD_LEN).contains(&password.len()) {
        return Err(LurpaxError::Password(
            "password must be 1..=8192 bytes".into(),
        ));
    }
    let mut v = Vec::new();
    let pl = u32::try_from(password.len()).map_err(|_| LurpaxError::Overflow)?;
    v.extend_from_slice(&pl.to_le_bytes());
    v.extend_from_slice(password);
    if let Some(r) = yubi_response {
        let rl = u32::try_from(r.len()).map_err(|_| LurpaxError::Overflow)?;
        v.extend_from_slice(&rl.to_le_bytes());
        v.extend_from_slice(r);
    }
    Ok(Zeroizing::new(v))
}

/// Derives 64-byte master secret with Argon2id into `master_out`.
pub fn argon2_derive_master(
    ikm: &[u8],
    salt: &[u8; 32],
    mem_kib: u32,
    iterations: u32,
    parallelism: u32,
    master_out: &mut [u8],
) -> Result<()> {
    if master_out.len() != ARGON2_OUTPUT_LEN {
        return Err(LurpaxError::Crypto("invalid master buffer length".into()));
    }
    let params = Params::new(mem_kib, iterations, parallelism, Some(ARGON2_OUTPUT_LEN))
        .map_err(|e| LurpaxError::Crypto(format!("argon2 params: {e}")))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    // AUDIT: 64-byte master output is never used directly as a key
    argon2
        .hash_password_into(ikm, salt, master_out)
        .map_err(|e: argon2::Error| LurpaxError::Crypto(format!("argon2: {e}")))?;
    Ok(())
}

/// Derives a 32-byte XChaCha20-Poly1305 key for password-wrapped YubiKey challenge bytes (header v2).
pub fn argon2_derive_wrap_key(ikm: &[u8], salt: &[u8; 32], key_out: &mut [u8; 32]) -> Result<()> {
    let params = Params::new(
        YUBI_CHALLENGE_WRAP_MEM_KIB,
        YUBI_CHALLENGE_WRAP_ITERATIONS,
        YUBI_CHALLENGE_WRAP_PARALLELISM,
        Some(32),
    )
    .map_err(|e| LurpaxError::Crypto(format!("argon2 wrap params: {e}")))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    argon2
        .hash_password_into(ikm, salt, &mut key_out[..])
        .map_err(|e: argon2::Error| LurpaxError::Crypto(format!("argon2 wrap: {e}")))?;
    Ok(())
}

/// HKDF expands `master` into AEAD and commitment subkeys; caller must zeroize `master` after.
///
/// Subkeys are [`Zeroizing`] so they are cleared on drop even when callers return early via `?`.
pub fn derive_subkeys(master: &[u8]) -> Result<DerivedSubkeys> {
    if master.len() != ARGON2_OUTPUT_LEN {
        return Err(LurpaxError::Crypto("invalid master length".into()));
    }
    let hk = Hkdf::<Sha256>::new(None, master);
    let mut enc = [0u8; 32];
    let mut commit = [0u8; 32];
    // AUDIT: domain-separated info strings guarantee enc_key ≠ commit_key
    hk.expand(HKDF_INFO_ENC, &mut enc)
        .map_err(|_| LurpaxError::Crypto("hkdf enc".into()))?;
    hk.expand(HKDF_INFO_COMMIT, &mut commit)
        .map_err(|_| LurpaxError::Crypto("hkdf commit".into()))?;
    Ok((Zeroizing::new(enc), Zeroizing::new(commit)))
}

/// Zeroizes the Argon2 master buffer.
pub fn zeroize_master(master: &mut [u8]) {
    master.zeroize();
}
