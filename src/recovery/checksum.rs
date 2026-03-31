//! CRC-32C checksum table (non-cryptographic; accidental bit-flip detection).

use crate::errors::{LurpaxError, Result};

/// Builds little-endian CRC table for all shards in order.
pub fn build_checksum_table(shards: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::with_capacity(shards.len() * 4);
    for s in shards {
        // AUDIT: CRC-32C is non-cryptographic — detects accidental corruption only, not tampering
        let c = crc32c::crc32c(s);
        out.extend_from_slice(&c.to_le_bytes());
    }
    out
}

/// Returns `Ok(true)` if table matches shards, `Ok(false)` if table length/format wrong.
pub fn verify_checksum_table(shards: &[Vec<u8>], table: &[u8]) -> Result<bool> {
    let expected = shards.len().checked_mul(4).ok_or(LurpaxError::Overflow)?;
    if table.len() != expected {
        return Ok(false);
    }
    let mut off = 0usize;
    for s in shards {
        let c = u32::from_le_bytes(
            table[off..off + 4]
                .try_into()
                .map_err(|_| LurpaxError::InvalidVault("crc entry".into()))?,
        );
        off += 4;
        if crc32c::crc32c(s) != c {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Marks shards whose CRC does not match the table; if table short, returns `Err` for verify path.
pub fn damaged_from_table(shards: &[Vec<u8>], table: &[u8]) -> Result<Vec<bool>> {
    let expected = shards.len().checked_mul(4).ok_or(LurpaxError::Overflow)?;
    if table.len() != expected {
        return Err(LurpaxError::StructurallyUnreadable);
    }
    let mut damaged = vec![false; shards.len()];
    let mut off = 0usize;
    for (i, s) in shards.iter().enumerate() {
        let c = u32::from_le_bytes(
            table[off..off + 4]
                .try_into()
                .map_err(|_| LurpaxError::InvalidVault("crc entry".into()))?,
        );
        off += 4;
        if crc32c::crc32c(s) != c {
            damaged[i] = true;
        }
    }
    Ok(damaged)
}
