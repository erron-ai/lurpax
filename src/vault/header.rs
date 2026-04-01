//! Hand-rolled little-endian header serialization (no bincode).

use crate::constants::{
    CHUNK_PLAINTEXT_SIZE, HEADER_VERSION_V1, HEADER_VERSION_V2, KDF_ARGON2ID,
    MAX_ARGON2_ITERATIONS, MAX_ARGON2_MEM_KIB, MAX_ARGON2_PARALLELISM, MAX_HEADER_BODY_LEN,
    MIN_ARGON2_ITERATIONS, MIN_ARGON2_MEM_KIB, MIN_ARGON2_PARALLELISM, RS_DATA_SHARDS_PER_GROUP,
    RS_PARITY_SHARDS_PER_GROUP,
};
use crate::errors::{LurpaxError, Result};

/// On-disk header fields for v1 and v2 (see `docs/FORMAT.md`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// Format version (`1` for v1).
    pub version: u16,
    /// KDF identifier (`1` = Argon2id).
    pub kdf_algorithm: u8,
    /// Argon2id memory cost (KiB).
    pub argon2_mem_kib: u32,
    /// Argon2id time cost.
    pub argon2_iterations: u32,
    /// Argon2id parallelism.
    pub argon2_parallelism: u32,
    /// Argon2id salt.
    pub salt: [u8; 32],
    /// Base nonce for STREAM (24 bytes).
    pub base_nonce: [u8; 24],
    /// HMAC-SHA256(commit_key, base_nonce).
    pub key_commitment: [u8; 32],
    /// Uncompressed chunk size of compressed stream (v1 fixed).
    pub chunk_plaintext_size: u32,
    /// Number of plaintext chunks (equals data shards).
    pub chunk_count: u64,
    /// Total compressed tar payload bytes before chunking.
    pub compressed_payload_size: u64,
    /// Data shards per RS group.
    pub rs_data_shards_per_group: u16,
    /// Parity shards per RS group.
    pub rs_parity_shards_per_group: u16,
    /// Whether YubiKey response was mixed into KDF input.
    pub yubi_required: bool,
    /// YubiKey slot (`1` or `2`) when `yubi_required`.
    pub yubi_slot: u8,
    /// Stored challenge for YubiKey on **v1** Yubi vaults only; must be zero on v2.
    pub yubi_challenge: [u8; 32],
    /// Argon2id salt for password-only wrap of the YubiKey challenge (**v2** Yubi vaults).
    pub yubi_wrap_salt: [u8; 32],
    /// XChaCha20-Poly1305 nonce for the wrapped challenge (**v2**).
    pub yubi_chal_nonce: [u8; 24],
    /// Ciphertext + tag for the 32-byte challenge (**v2**).
    pub yubi_chal_ciphertext: [u8; 48],
}

impl Header {
    /// Default Argon2id parameters for newly created vaults.
    pub fn default_argon2_params() -> (u32, u32, u32) {
        use crate::constants::{
            DEFAULT_ARGON2_ITERATIONS, DEFAULT_ARGON2_MEM_KIB, DEFAULT_ARGON2_PARALLELISM,
        };
        (
            DEFAULT_ARGON2_MEM_KIB,
            DEFAULT_ARGON2_ITERATIONS,
            DEFAULT_ARGON2_PARALLELISM,
        )
    }

    /// Serializes the header body to little-endian bytes (field order is normative).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(256);
        v.extend_from_slice(&self.version.to_le_bytes());
        v.push(self.kdf_algorithm);
        v.extend_from_slice(&self.argon2_mem_kib.to_le_bytes());
        v.extend_from_slice(&self.argon2_iterations.to_le_bytes());
        v.extend_from_slice(&self.argon2_parallelism.to_le_bytes());
        v.extend_from_slice(&self.salt);
        v.extend_from_slice(&self.base_nonce);
        v.extend_from_slice(&self.key_commitment);
        v.extend_from_slice(&self.chunk_plaintext_size.to_le_bytes());
        v.extend_from_slice(&self.chunk_count.to_le_bytes());
        v.extend_from_slice(&self.compressed_payload_size.to_le_bytes());
        v.extend_from_slice(&self.rs_data_shards_per_group.to_le_bytes());
        v.extend_from_slice(&self.rs_parity_shards_per_group.to_le_bytes());
        v.push(u8::from(self.yubi_required));
        v.push(self.yubi_slot);
        if self.version == HEADER_VERSION_V1 {
            v.extend_from_slice(&self.yubi_challenge);
        } else if self.version == HEADER_VERSION_V2 {
            v.extend_from_slice(&self.yubi_wrap_salt);
            v.extend_from_slice(&self.yubi_chal_nonce);
            v.extend_from_slice(&self.yubi_chal_ciphertext);
        } else {
            v.extend_from_slice(&self.yubi_challenge);
        }
        v
    }

    /// Parses header body; rejects trailing bytes and oversize payloads.
    pub fn from_bytes_exact(buf: &[u8]) -> Result<Self> {
        let mut off = 0usize;
        macro_rules! take {
            ($n:expr) => {{
                let n = $n;
                let end = off.checked_add(n).ok_or(LurpaxError::Overflow)?;
                if end > buf.len() {
                    return Err(LurpaxError::InvalidVault("truncated header".into()));
                }
                let s = &buf[off..end];
                off = end;
                s
            }};
        }

        let ver = u16::from_le_bytes(
            take!(2)
                .try_into()
                .map_err(|_| LurpaxError::InvalidVault("version".into()))?,
        );
        if ver != HEADER_VERSION_V1 && ver != HEADER_VERSION_V2 {
            return Err(LurpaxError::InvalidVault(format!(
                "unsupported version {ver}"
            )));
        }
        let kdf = *take!(1)
            .first()
            .ok_or_else(|| LurpaxError::InvalidVault("kdf".into()))?;
        let mem = u32::from_le_bytes(
            take!(4)
                .try_into()
                .map_err(|_| LurpaxError::InvalidVault("argon mem".into()))?,
        );
        let iters = u32::from_le_bytes(
            take!(4)
                .try_into()
                .map_err(|_| LurpaxError::InvalidVault("argon iters".into()))?,
        );
        let par = u32::from_le_bytes(
            take!(4)
                .try_into()
                .map_err(|_| LurpaxError::InvalidVault("argon par".into()))?,
        );
        let salt: [u8; 32] = take!(32)
            .try_into()
            .map_err(|_| LurpaxError::InvalidVault("salt".into()))?;
        let base_nonce: [u8; 24] = take!(24)
            .try_into()
            .map_err(|_| LurpaxError::InvalidVault("base_nonce".into()))?;
        let key_commitment: [u8; 32] = take!(32)
            .try_into()
            .map_err(|_| LurpaxError::InvalidVault("key_commitment".into()))?;
        let cps = u32::from_le_bytes(
            take!(4)
                .try_into()
                .map_err(|_| LurpaxError::InvalidVault("chunk_plaintext_size".into()))?,
        );
        let chunk_count = u64::from_le_bytes(
            take!(8)
                .try_into()
                .map_err(|_| LurpaxError::InvalidVault("chunk_count".into()))?,
        );
        let comp_size = u64::from_le_bytes(
            take!(8)
                .try_into()
                .map_err(|_| LurpaxError::InvalidVault("compressed_payload_size".into()))?,
        );
        let rs_d = u16::from_le_bytes(
            take!(2)
                .try_into()
                .map_err(|_| LurpaxError::InvalidVault("rs_data".into()))?,
        );
        let rs_p = u16::from_le_bytes(
            take!(2)
                .try_into()
                .map_err(|_| LurpaxError::InvalidVault("rs_parity".into()))?,
        );
        let yubi_req = *take!(1)
            .first()
            .ok_or_else(|| LurpaxError::InvalidVault("yubi_required".into()))?;
        let yubi_slot = *take!(1)
            .first()
            .ok_or_else(|| LurpaxError::InvalidVault("yubi_slot".into()))?;
        let (yubi_challenge, yubi_wrap_salt, yubi_chal_nonce, yubi_chal_ciphertext) =
            if ver == HEADER_VERSION_V1 {
                let c: [u8; 32] = take!(32)
                    .try_into()
                    .map_err(|_| LurpaxError::InvalidVault("yubi_challenge".into()))?;
                (c, [0u8; 32], [0u8; 24], [0u8; 48])
            } else {
                let ws: [u8; 32] = take!(32)
                    .try_into()
                    .map_err(|_| LurpaxError::InvalidVault("yubi_wrap_salt".into()))?;
                let nn: [u8; 24] = take!(24)
                    .try_into()
                    .map_err(|_| LurpaxError::InvalidVault("yubi_chal_nonce".into()))?;
                let ct: [u8; 48] = take!(48)
                    .try_into()
                    .map_err(|_| LurpaxError::InvalidVault("yubi_chal_ciphertext".into()))?;
                ([0u8; 32], ws, nn, ct)
            };

        // AUDIT: exact consumption prevents parser confusion from appended data
        if off != buf.len() {
            return Err(LurpaxError::InvalidVault(
                "trailing bytes after header".into(),
            ));
        }

        let h = Header {
            version: ver,
            kdf_algorithm: kdf,
            argon2_mem_kib: mem,
            argon2_iterations: iters,
            argon2_parallelism: par,
            salt,
            base_nonce,
            key_commitment,
            chunk_plaintext_size: cps,
            chunk_count,
            compressed_payload_size: comp_size,
            rs_data_shards_per_group: rs_d,
            rs_parity_shards_per_group: rs_p,
            yubi_required: yubi_req != 0,
            yubi_slot,
            yubi_challenge,
            yubi_wrap_salt,
            yubi_chal_nonce,
            yubi_chal_ciphertext,
        };
        h.validate_schema()?;
        Ok(h)
    }

    /// Validates version-1 wire schema and policy bounds for `open` / `verify`.
    pub fn validate_schema(&self) -> Result<()> {
        if self.version != HEADER_VERSION_V1 && self.version != HEADER_VERSION_V2 {
            return Err(LurpaxError::InvalidVault(format!(
                "unsupported version {}",
                self.version
            )));
        }
        if self.kdf_algorithm != KDF_ARGON2ID {
            return Err(LurpaxError::InvalidVault("unsupported KDF".into()));
        }
        // AUDIT: reject out-of-policy KDF params to prevent downgrade and DoS
        if !(MIN_ARGON2_MEM_KIB..=MAX_ARGON2_MEM_KIB).contains(&self.argon2_mem_kib) {
            return Err(LurpaxError::InvalidVault(
                "argon2 memory out of policy".into(),
            ));
        }
        if !(MIN_ARGON2_ITERATIONS..=MAX_ARGON2_ITERATIONS).contains(&self.argon2_iterations) {
            return Err(LurpaxError::InvalidVault(
                "argon2 iterations out of policy".into(),
            ));
        }
        if !(MIN_ARGON2_PARALLELISM..=MAX_ARGON2_PARALLELISM).contains(&self.argon2_parallelism) {
            return Err(LurpaxError::InvalidVault(
                "argon2 parallelism out of policy".into(),
            ));
        }
        if self.chunk_plaintext_size != CHUNK_PLAINTEXT_SIZE {
            return Err(LurpaxError::InvalidVault("chunk size mismatch".into()));
        }
        if self.rs_data_shards_per_group != RS_DATA_SHARDS_PER_GROUP
            || self.rs_parity_shards_per_group != RS_PARITY_SHARDS_PER_GROUP
        {
            return Err(LurpaxError::InvalidVault("RS parameters mismatch".into()));
        }
        if self.chunk_count == 0 {
            return Err(LurpaxError::InvalidVault("chunk_count is zero".into()));
        }
        let _chunk_count_usize =
            usize::try_from(self.chunk_count).map_err(|_| LurpaxError::Overflow)?;
        if self.yubi_required {
            if self.yubi_slot != 1 && self.yubi_slot != 2 {
                return Err(LurpaxError::InvalidVault("invalid yubi_slot".into()));
            }
        } else {
            if self.yubi_slot != 0 {
                return Err(LurpaxError::InvalidVault("yubi_slot must be 0".into()));
            }
            if self.yubi_challenge != [0u8; 32] {
                return Err(LurpaxError::InvalidVault(
                    "yubi_challenge must be zeroed".into(),
                ));
            }
        }
        match self.version {
            HEADER_VERSION_V1 => {
                if self.yubi_wrap_salt != [0u8; 32]
                    || self.yubi_chal_nonce != [0u8; 24]
                    || self.yubi_chal_ciphertext != [0u8; 48]
                {
                    return Err(LurpaxError::InvalidVault(
                        "v1 header must zero yubi wrap fields".into(),
                    ));
                }
            }
            HEADER_VERSION_V2 => {
                if !self.yubi_required {
                    return Err(LurpaxError::InvalidVault(
                        "header v2 requires YubiKey".into(),
                    ));
                }
                if self.yubi_challenge != [0u8; 32] {
                    return Err(LurpaxError::InvalidVault(
                        "v2 must not store plaintext yubi_challenge".into(),
                    ));
                }
                if self.yubi_wrap_salt == [0u8; 32] {
                    return Err(LurpaxError::InvalidVault(
                        "v2 yubi wrap salt invalid".into(),
                    ));
                }
            }
            _ => {}
        }
        let last = last_chunk_plaintext_size(self)?;
        let full = u64::from(self.chunk_plaintext_size);
        if last > full {
            return Err(LurpaxError::InvalidVault(
                "compressed size vs chunks".into(),
            ));
        }
        if self.chunk_count > 1 && last == 0 {
            return Err(LurpaxError::InvalidVault(
                "compressed size vs chunks".into(),
            ));
        }
        Ok(())
    }
}

/// `shard_size = chunk_plaintext_size + 16` (Poly1305 tag).
pub fn shard_cipher_size(header: &Header) -> Result<u64> {
    u64::from(header.chunk_plaintext_size)
        .checked_add(16)
        .ok_or(LurpaxError::Overflow)
}

/// Number of RS groups for this vault.
pub fn group_count(header: &Header) -> Result<u64> {
    let d = u64::from(header.rs_data_shards_per_group);
    let c = header.chunk_count;
    let g = c.div_ceil(d);
    if g == 0 {
        return Err(LurpaxError::InvalidVault("group count zero".into()));
    }
    Ok(g)
}

/// Total shards (data + parity) on disk.
pub fn total_shards(header: &Header) -> Result<u64> {
    let g = group_count(header)?;
    let p = u64::from(header.rs_parity_shards_per_group);
    header
        .chunk_count
        .checked_add(g.checked_mul(p).ok_or(LurpaxError::Overflow)?)
        .ok_or(LurpaxError::Overflow)
}

/// Plaintext size of the last chunk inside the compressed stream.
pub fn last_chunk_plaintext_size(header: &Header) -> Result<u64> {
    let c = header.chunk_count;
    let full = u64::from(header.chunk_plaintext_size);
    let total = header.compressed_payload_size;
    if c == 1 {
        if total > full {
            return Err(LurpaxError::InvalidVault("compressed size".into()));
        }
        return Ok(total);
    }
    let prefix = full.checked_mul(c - 1).ok_or(LurpaxError::Overflow)?;
    if total < prefix {
        return Err(LurpaxError::InvalidVault("compressed size".into()));
    }
    let last = total - prefix;
    if last == 0 || last > full {
        return Err(LurpaxError::InvalidVault("last chunk size".into()));
    }
    Ok(last)
}

/// Expected vault file size from a parsed header.
pub fn expected_file_len(header: &Header, header_body_len: u32) -> Result<u64> {
    let h = u64::from(header_body_len);
    let prefix = 5u64
        .checked_add(4)
        .and_then(|x| x.checked_add(h))
        .ok_or(LurpaxError::Overflow)?;
    let ss = shard_cipher_size(header)?;
    let ts = total_shards(header)?;
    let shards = ss.checked_mul(ts).ok_or(LurpaxError::Overflow)?;
    let crc = ts.checked_mul(4).ok_or(LurpaxError::Overflow)?;
    let tail = h
        .checked_add(4)
        .and_then(|x| x.checked_add(5))
        .ok_or(LurpaxError::Overflow)?;
    prefix
        .checked_add(shards)
        .and_then(|x| x.checked_add(crc))
        .and_then(|x| x.checked_add(tail))
        .ok_or(LurpaxError::Overflow)
}

/// Reads `u32` header length after magic; ensures `<= MAX_HEADER_BODY_LEN`.
pub fn read_header_len_prefix<R: std::io::Read>(r: &mut R) -> Result<u32> {
    let mut u = [0u8; 4];
    r.read_exact(&mut u)?;
    let n = u32::from_le_bytes(u);
    // AUDIT: bounded allocation prevents DoS via oversized header claim
    if n == 0 || n > MAX_HEADER_BODY_LEN {
        return Err(LurpaxError::InvalidVault("header length".into()));
    }
    Ok(n)
}
