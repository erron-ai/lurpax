//! High-level create / open / verify orchestration.

use std::fs::File;
use std::io::{Seek, SeekFrom};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use std::ops::Deref;

use zeroize::Zeroizing;

use crate::archive::{ArchiveLimits, extract_tar, tar_input};
use crate::constants::{
    CHUNK_PLAINTEXT_SIZE, HEADER_VERSION_V1, KDF_ARGON2ID, RS_DATA_SHARDS_PER_GROUP,
    RS_PARITY_SHARDS_PER_GROUP,
};
use crate::crypto::{
    DerivedSubkeys, commitment_hmac, compose_ikm, decrypt_single_chunk, derive_subkeys,
    encrypt_all_chunks, verify_commitment, zeroize_master,
};
use crate::errors::{LurpaxError, Result, VerifyHealth, check_interrupted};
use crate::hardware::YubiKeyPort;
use crate::recovery::checksum::damaged_from_table;
use crate::recovery::fec::repair_group;
use crate::vault::container::{self, layout_shards_with_rs, write_atomic};
use crate::vault::header::{self, Header};

fn zstd_compress(data: &[u8]) -> Result<Vec<u8>> {
    zstd::encode_all(data, 3).map_err(|e| LurpaxError::Crypto(format!("zstd: {e}")))
}

fn zstd_streaming_reader(data: &[u8]) -> Result<impl std::io::Read + '_> {
    zstd::stream::read::Decoder::new(data)
        .map_err(|e| LurpaxError::Crypto(format!("zstd init: {e}")))
}

fn random32() -> Result<[u8; 32]> {
    let mut b = [0u8; 32];
    getrandom::getrandom(&mut b).map_err(|_| LurpaxError::RandomUnavailable)?;
    Ok(b)
}

fn random24() -> Result<[u8; 24]> {
    let mut b = [0u8; 24];
    getrandom::getrandom(&mut b).map_err(|_| LurpaxError::RandomUnavailable)?;
    Ok(b)
}

fn chunk_count_for_compressed(len: u64) -> u64 {
    let full = u64::from(CHUNK_PLAINTEXT_SIZE);
    if len == 0 {
        return 1;
    }
    len.div_ceil(full)
}

fn try_mlock_secret(buf: &mut [u8]) {
    if buf.is_empty() {
        return;
    }
    // SAFETY: `buf` is a live mutable slice for the duration of the call.
    unsafe {
        let _ = memsec::mlock(buf.as_mut_ptr(), buf.len());
    }
}

fn derive_keys_from_password(
    header: &Header,
    password: &[u8],
    yubi: Option<&[u8]>,
) -> Result<DerivedSubkeys> {
    let ikm = compose_ikm(password, yubi)?;
    let mut master = Zeroizing::new([0u8; 64]);
    crate::crypto::kdf::argon2_derive_master(
        &ikm,
        &header.salt,
        header.argon2_mem_kib,
        header.argon2_iterations,
        header.argon2_parallelism,
        master.as_mut(),
    )?;
    try_mlock_secret(master.as_mut());
    let (mut enc, mut commit) = derive_subkeys(master.as_ref())?;
    zeroize_master(master.as_mut());
    // AUDIT: mlock subkeys to prevent swap exposure.
    try_mlock_secret(enc.as_mut());
    try_mlock_secret(commit.as_mut());
    Ok((enc, commit))
}

fn collect_data_shards(shards: &[Vec<u8>], header: &Header) -> Result<Vec<Zeroizing<Vec<u8>>>> {
    let d = header.rs_data_shards_per_group as usize;
    let p = header.rs_parity_shards_per_group as usize;
    let n = usize::try_from(header.chunk_count).map_err(|_| LurpaxError::Overflow)?;
    let mut out = Vec::with_capacity(n);
    let mut idx = 0usize;
    let mut pos = 0usize;
    while idx < n {
        let k = (n - idx).min(d);
        let group_len = k + p;
        if pos + group_len > shards.len() {
            return Err(LurpaxError::InvalidVault("shard layout".into()));
        }
        for j in 0..k {
            out.push(Zeroizing::new(shards[pos + j].clone()));
        }
        pos += group_len;
        idx += k;
    }
    Ok(out)
}

fn repair_all_groups(shards: &mut [Vec<u8>], header: &Header, damaged: &[bool]) -> Result<usize> {
    let d = header.rs_data_shards_per_group as usize;
    let p = header.rs_parity_shards_per_group as usize;
    let n = usize::try_from(header.chunk_count).map_err(|_| LurpaxError::Overflow)?;
    let mut pos = 0usize;
    let mut idx = 0usize;
    let mut repaired = 0usize;
    while idx < n {
        let k = (n - idx).min(d);
        let group_len = k + p;
        let gdam = damaged
            .get(pos..pos + group_len)
            .ok_or(LurpaxError::InvalidVault("damage map".into()))?;
        if gdam.iter().any(|x| *x) {
            let mut gshards: Vec<Vec<u8>> = shards[pos..pos + group_len].to_vec();
            repair_group(&mut gshards, k, p, gdam)?;
            for i in 0..group_len {
                if gdam[i] {
                    repaired += gshards[i].len();
                }
                shards[pos + i] = gshards[i].clone();
            }
        }
        pos += group_len;
        idx += k;
    }
    Ok(repaired)
}

/// Maps a data-shard index (chunk_index) to the flat shard-array index.
fn chunk_to_shard_index(chunk_index: usize, header: &Header) -> usize {
    let d = header.rs_data_shards_per_group as usize;
    let p = header.rs_parity_shards_per_group as usize;
    let group = chunk_index / d;
    let within = chunk_index % d;
    group * (d + p) + within
}

/// Maps a flat shard-array index to the group it belongs to (group_start_shard_idx, data_count, parity_count).
fn shard_group_range(shard_index: usize, header: &Header) -> Result<(usize, usize, usize)> {
    let d = header.rs_data_shards_per_group as usize;
    let p = header.rs_parity_shards_per_group as usize;
    let n = usize::try_from(header.chunk_count).map_err(|_| LurpaxError::Overflow)?;
    let mut pos = 0usize;
    let mut idx = 0usize;
    while idx < n {
        let k = (n - idx).min(d);
        let group_len = k + p;
        if shard_index < pos + group_len {
            return Ok((pos, k, p));
        }
        pos += group_len;
        idx += k;
    }
    Err(LurpaxError::InvalidVault(
        "shard index out of layout".into(),
    ))
}

/// Copies data shards for the flat group starting at `gstart` into `data_shards` at the
/// corresponding chunk indices (matches `collect_data_shards` layout).
fn sync_data_shards_after_group_repair(
    shards: &[Vec<u8>],
    header: &Header,
    gstart: usize,
    gdata: usize,
    data_shards: &mut [Zeroizing<Vec<u8>>],
) -> Result<()> {
    let d = header.rs_data_shards_per_group as usize;
    let p = header.rs_parity_shards_per_group as usize;
    let n = usize::try_from(header.chunk_count).map_err(|_| LurpaxError::Overflow)?;
    let mut pos = 0usize;
    let mut idx = 0usize;
    while idx < n {
        let k = (n - idx).min(d);
        let group_len = k + p;
        if pos == gstart {
            if gdata != k {
                return Err(LurpaxError::InvalidVault("RS group layout".into()));
            }
            for j in 0..k {
                data_shards[idx + j] = Zeroizing::new(shards[pos + j].clone());
            }
            return Ok(());
        }
        pos += group_len;
        idx += k;
    }
    Err(LurpaxError::InvalidVault("gstart not in layout".into()))
}

/// Vault operations entry point.
pub struct VaultService;

impl VaultService {
    /// Creates a new `.lurpax` vault at `output` from `input`.
    pub fn create(
        output: &Path,
        input: &Path,
        password: &[u8],
        yubi: Option<&dyn YubiKeyPort>,
        yubi_slot: Option<u8>,
        limits: ArchiveLimits,
        term: Option<Arc<AtomicBool>>,
    ) -> Result<()> {
        if output.exists() {
            return Err(LurpaxError::OutputExists);
        }
        let partial = output.with_extension("lurpax.partial");
        if partial.exists() {
            eprintln!("warning: removing stale partial vault file from interrupted create");
            std::fs::remove_file(&partial)?;
        }
        check_interrupted(term.as_ref())?;
        let tar = tar_input(input, &limits)?;
        check_interrupted(term.as_ref())?;
        let compressed = zstd_compress(&tar)?;
        let comp_len = compressed.len() as u64;
        const LARGE_VAULT_WARN_BYTES: u64 = 2 * 1024 * 1024 * 1024;
        if comp_len > LARGE_VAULT_WARN_BYTES {
            eprintln!(
                "warning: compressed payload is {} GiB; opening this vault will require significant RAM",
                comp_len / (1024 * 1024 * 1024)
            );
        }
        let chunk_count = chunk_count_for_compressed(comp_len);
        let salt = random32()?;
        let base_nonce_arr: [u8; 24] = random24()?;
        let yubi_required = yubi_slot.is_some();
        let slot = yubi_slot.unwrap_or(0);
        let mut yubi_challenge = [0u8; 32];
        let yubi_resp: Option<Zeroizing<Vec<u8>>> = if yubi_required {
            getrandom::getrandom(&mut yubi_challenge)
                .map_err(|_| LurpaxError::RandomUnavailable)?;
            let y =
                yubi.ok_or_else(|| LurpaxError::YubiKey("internal: missing yubi port".into()))?;
            let r = y.otp_calculate(slot, &yubi_challenge)?;
            Some(Zeroizing::new(Vec::from(*r)))
        } else {
            None
        };
        let yubi_slice = yubi_resp.as_ref().map(|b| b.as_slice());
        let (mem, it, par) = Header::default_argon2_params();
        let mut header = Header {
            version: HEADER_VERSION_V1,
            kdf_algorithm: KDF_ARGON2ID,
            argon2_mem_kib: mem,
            argon2_iterations: it,
            argon2_parallelism: par,
            salt,
            base_nonce: base_nonce_arr,
            key_commitment: [0u8; 32],
            chunk_plaintext_size: CHUNK_PLAINTEXT_SIZE,
            chunk_count,
            compressed_payload_size: comp_len,
            rs_data_shards_per_group: RS_DATA_SHARDS_PER_GROUP,
            rs_parity_shards_per_group: RS_PARITY_SHARDS_PER_GROUP,
            yubi_required,
            yubi_slot: slot,
            yubi_challenge,
        };
        header.validate_schema()?;
        let ikm = compose_ikm(password, yubi_slice)?;
        let mut master = Zeroizing::new([0u8; 64]);
        crate::crypto::kdf::argon2_derive_master(
            &ikm,
            &header.salt,
            header.argon2_mem_kib,
            header.argon2_iterations,
            header.argon2_parallelism,
            master.as_mut(),
        )?;
        try_mlock_secret(master.as_mut());
        let (enc_key, commit_key) = derive_subkeys(master.as_ref())?;
        zeroize_master(master.as_mut());
        // AUDIT: key commitment computed with domain-separated commit_key.
        header.key_commitment = commitment_hmac(commit_key.deref(), &header.base_nonce)?;
        drop(commit_key);
        let header_body = header.to_bytes();
        check_interrupted(term.as_ref())?;
        let enc_shards = encrypt_all_chunks(&header, &header_body, &compressed, enc_key.deref())?;
        drop(enc_key);
        let plain_shards: Vec<Vec<u8>> = enc_shards.into_iter().map(|z| (*z).clone()).collect();
        check_interrupted(term.as_ref())?;
        let disk_shards = layout_shards_with_rs(plain_shards, &header)?;
        let crc = crate::recovery::checksum::build_checksum_table(&disk_shards);
        write_atomic(output, &header, &header_body, &disk_shards, &crc)?;
        Ok(())
    }

    /// Opens a vault into `out_dir`.
    ///
    /// Canonical flow: CRC precheck → RS repair → key derivation → AEAD decrypt
    /// with fallback pass (CRC false-negative handling). If any shard bytes were
    /// repaired, the vault file at `vault_path` is atomically rewritten after a
    /// successful extract so the on-disk copy matches the recovered ciphertext.
    pub fn open(
        vault_path: &Path,
        out_dir: &Path,
        password: &[u8],
        yubi: Option<&dyn YubiKeyPort>,
        limits: ArchiveLimits,
        term: Option<Arc<AtomicBool>>,
    ) -> Result<usize> {
        let extracted_dest = out_dir.join("extracted");
        if extracted_dest.exists() {
            return Err(LurpaxError::OutputExists);
        }
        let mut file = File::open(vault_path)?;
        let (header, header_body) = container::read_header_any(&mut file)?;
        let layout = container::read_payload(&mut file, &header, header_body.clone())?;
        let total =
            usize::try_from(header::total_shards(&header)?).map_err(|_| LurpaxError::Overflow)?;
        let crc_expected = total.checked_mul(4).ok_or(LurpaxError::Overflow)?;
        let mut shards = layout.shards;

        // CRC precheck: mark mismatched shards as damaged.
        let mut damaged: Vec<bool> =
            if layout.crc_table_valid && layout.crc_table.len() == crc_expected {
                damaged_from_table(&shards, &layout.crc_table)?
            } else {
                // AUDIT: CRC table corrupt/missing → skip precheck, rely on AEAD tags.
                vec![false; total]
            };

        // RS repair pass 1: fix CRC-detected damage.
        let mut repaired = repair_all_groups(&mut shards, &header, &damaged)?;
        // AUDIT: repaired shards are clean; stale `true` entries would overcount damage on AEAD retry.
        damaged.fill(false);
        check_interrupted(term.as_ref())?;

        // Key derivation (after RS, before AEAD).
        let yubi_bytes: Option<Zeroizing<Vec<u8>>> = if header.yubi_required {
            let y =
                yubi.ok_or_else(|| LurpaxError::YubiKey("YubiKey required for this vault".into()))?;
            let r = y.otp_calculate(header.yubi_slot, &header.yubi_challenge)?;
            Some(Zeroizing::new(Vec::from(*r)))
        } else {
            None
        };
        let yubi_slice = yubi_bytes.as_ref().map(|b| b.as_slice());
        let (enc_key, commit_key) = derive_keys_from_password(&header, password, yubi_slice)?;
        // AUDIT: key commitment verified before any AEAD decryption for fast wrong-password rejection.
        verify_commitment(
            commit_key.deref(),
            &header.base_nonce,
            &header.key_commitment,
        )?;
        drop(commit_key);

        // Per-chunk AEAD decryption with fallback pass for CRC false negatives.
        // AUDIT: one logical data-shard view; refresh only the RS group touched on AEAD retry
        // (avoids O(n²) reclones from calling collect_data_shards every chunk — required at 100GB+).
        let n = usize::try_from(header.chunk_count).map_err(|_| LurpaxError::Overflow)?;
        let mut data_shards = collect_data_shards(&shards, &header)?;
        let mut plain: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());
        for chunk_idx in 0..n {
            check_interrupted(term.as_ref())?;
            let shard_data = data_shards[chunk_idx].as_slice();
            match decrypt_single_chunk(
                &header,
                &header_body,
                shard_data,
                chunk_idx,
                enc_key.deref(),
            ) {
                Ok(pt) => plain.extend_from_slice(&pt),
                Err(LurpaxError::DecryptAuthFailed) => {
                    // AUDIT: AEAD failure on CRC-clean shard = CRC false negative.
                    // Re-mark the data shard as damaged and re-RS its group.
                    let shard_idx = chunk_to_shard_index(chunk_idx, &header);
                    damaged[shard_idx] = true;
                    let (gstart, gdata, gparity) = shard_group_range(shard_idx, &header)?;
                    let group_len = gdata + gparity;
                    let gdam = &damaged[gstart..gstart + group_len];
                    let mut gshards: Vec<Vec<u8>> = shards[gstart..gstart + group_len].to_vec();
                    repair_group(&mut gshards, gdata, gparity, gdam)?;
                    for i in 0..group_len {
                        if damaged[gstart + i] {
                            repaired += gshards[i].len();
                        }
                        shards[gstart + i] = gshards[i].clone();
                    }
                    sync_data_shards_after_group_repair(
                        &shards,
                        &header,
                        gstart,
                        gdata,
                        &mut data_shards,
                    )?;
                    let pt = decrypt_single_chunk(
                        &header,
                        &header_body,
                        data_shards[chunk_idx].as_slice(),
                        chunk_idx,
                        enc_key.deref(),
                    )?;
                    plain.extend_from_slice(&pt);
                }
                Err(e) => return Err(e),
            }
        }
        drop(enc_key);

        if plain.len() as u64 != header.compressed_payload_size {
            return Err(LurpaxError::DecryptAuthFailed);
        }

        check_interrupted(term.as_ref())?;
        // AUDIT: streaming zstd → tar avoids buffering the entire decompressed payload.
        let zstd_reader = zstd_streaming_reader(plain.as_slice())?;
        extract_tar(zstd_reader, out_dir, &limits, term.as_ref())?;
        if repaired > 0 {
            drop(file);
            check_interrupted(term.as_ref())?;
            let crc = crate::recovery::checksum::build_checksum_table(&shards);
            write_atomic(vault_path, &header, &header_body, &shards, &crc)?;
        }
        Ok(repaired)
    }

    /// Structural + RS health check without password.
    pub fn verify(vault_path: &Path) -> Result<VerifyHealth> {
        let mut file = File::open(vault_path)?;
        let len = file.metadata()?.len();
        file.seek(SeekFrom::Start(0))?;
        let primary = container::read_primary_header(&mut file);
        let tail = container::read_tail_header(&mut file, len);
        let (header, body) = match (&primary, &tail) {
            (Ok(a), Ok(b)) => {
                if a.0 != b.0 || a.1 != b.1 {
                    return Ok(VerifyHealth::Unreadable);
                }
                (a.0.clone(), a.1.clone())
            }
            (Ok(a), Err(_)) => (a.0.clone(), a.1.clone()),
            (Err(_), Ok(b)) => (b.0.clone(), b.1.clone()),
            (Err(_), Err(_)) => return Ok(VerifyHealth::Unreadable),
        };
        let exp = header::expected_file_len(&header, body.len() as u32)?;
        if exp != len {
            return Ok(VerifyHealth::Unreadable);
        }
        file.seek(SeekFrom::Start(0))?;
        let _ = container::read_header_any(&mut file)?;
        let layout = container::read_payload(&mut file, &header, body)?;
        let ts =
            usize::try_from(header::total_shards(&header)?).map_err(|_| LurpaxError::Overflow)?;
        let crc_len = ts.checked_mul(4).ok_or(LurpaxError::Overflow)?;
        if !layout.crc_table_valid || layout.crc_table.len() != crc_len {
            return Ok(VerifyHealth::Unreadable);
        }
        let damaged = match damaged_from_table(&layout.shards, &layout.crc_table) {
            Ok(d) => d,
            Err(_) => return Ok(VerifyHealth::Unreadable),
        };
        if !damaged.iter().any(|x| *x) {
            return Ok(VerifyHealth::Healthy);
        }
        let d = header.rs_data_shards_per_group as usize;
        let p = header.rs_parity_shards_per_group as usize;
        let n = usize::try_from(header.chunk_count).map_err(|_| LurpaxError::Overflow)?;
        let mut pos = 0usize;
        let mut idx = 0usize;
        while idx < n {
            let k = (n - idx).min(d);
            let group_len = k + p;
            let gdam = &damaged[pos..pos + group_len];
            let bad = gdam.iter().filter(|x| **x).count();
            if bad > p {
                return Ok(VerifyHealth::Unrecoverable);
            }
            pos += group_len;
            idx += k;
        }
        Ok(VerifyHealth::Repairable)
    }
}

#[cfg(test)]
mod shard_layout_tests {
    use proptest::prelude::*;

    use super::{Header, chunk_to_shard_index, collect_data_shards, shard_group_range};
    use crate::constants::{
        CHUNK_PLAINTEXT_SIZE, HEADER_VERSION_V1, KDF_ARGON2ID, RS_DATA_SHARDS_PER_GROUP,
        RS_PARITY_SHARDS_PER_GROUP,
    };

    fn minimal_header(chunk_count: u64) -> Header {
        let full = u64::from(CHUNK_PLAINTEXT_SIZE);
        let compressed_payload_size = if chunk_count == 1 {
            1u64
        } else {
            full.saturating_mul(chunk_count - 1).saturating_add(1)
        };
        Header {
            version: HEADER_VERSION_V1,
            kdf_algorithm: KDF_ARGON2ID,
            argon2_mem_kib: crate::constants::DEFAULT_ARGON2_MEM_KIB,
            argon2_iterations: crate::constants::DEFAULT_ARGON2_ITERATIONS,
            argon2_parallelism: crate::constants::DEFAULT_ARGON2_PARALLELISM,
            salt: [0u8; 32],
            base_nonce: [0u8; 24],
            key_commitment: [0u8; 32],
            chunk_plaintext_size: CHUNK_PLAINTEXT_SIZE,
            chunk_count,
            compressed_payload_size,
            rs_data_shards_per_group: RS_DATA_SHARDS_PER_GROUP,
            rs_parity_shards_per_group: RS_PARITY_SHARDS_PER_GROUP,
            yubi_required: false,
            yubi_slot: 0,
            yubi_challenge: [0u8; 32],
        }
    }

    proptest! {
        #[test]
        fn shard_index_helpers_agree(chunk_count in 1u64..=512u64) {
            let h = minimal_header(chunk_count);
            h.validate_schema().map_err(|_| TestCaseError::reject("invalid header"))?;
            let ts = crate::vault::header::total_shards(&h).map_err(|_| TestCaseError::reject("total_shards"))?;
            let ts = usize::try_from(ts).map_err(|_| TestCaseError::reject("usize"))?;
            let shards: Vec<Vec<u8>> = (0..ts).map(|i| vec![i as u8; 1]).collect();
            let data = collect_data_shards(&shards, &h).map_err(|e| TestCaseError::fail(format!("{e:?}")))?;
            let n = usize::try_from(h.chunk_count).unwrap();
            prop_assert_eq!(data.len(), n);
            for (i, chunk) in data.iter().enumerate() {
                let flat = chunk_to_shard_index(i, &h);
                prop_assert_eq!(chunk.as_slice(), shards[flat].as_slice());
                let (gstart, gdata, gparity) = shard_group_range(flat, &h).map_err(|e| TestCaseError::fail(format!("{e:?}")))?;
                prop_assert!(flat >= gstart && flat < gstart + gdata + gparity);
                prop_assert!(flat < gstart + gdata);
            }
        }
    }
}
