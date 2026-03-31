//! Reed–Solomon encoding and reconstruction over fixed-size shards.

use reed_solomon_erasure::galois_8::ReedSolomon;

use crate::errors::{LurpaxError, Result};

/// Computes parity shards for one group; returns `k + p` shards (data then parity on wire layout).
pub fn encode_rs_group(data_shards: &[Vec<u8>], parity_count: usize) -> Result<Vec<Vec<u8>>> {
    if data_shards.is_empty() {
        return Err(LurpaxError::InvalidVault("empty RS group".into()));
    }
    let k = data_shards.len();
    let shard_len = data_shards[0].len();
    for s in data_shards {
        if s.len() != shard_len {
            return Err(LurpaxError::InvalidVault("shard length mismatch".into()));
        }
    }
    let rs = ReedSolomon::new(k, parity_count)
        .map_err(|e| LurpaxError::InvalidVault(format!("reed-solomon: {e}")))?;
    let mut shards: Vec<Vec<u8>> = data_shards.to_vec();
    shards.extend((0..parity_count).map(|_| vec![0u8; shard_len]));
    rs.encode(&mut shards)
        .map_err(|e| LurpaxError::InvalidVault(format!("reed-solomon encode: {e}")))?;
    Ok(shards)
}

/// Replaces known-bad shards using RS; `damaged` true means treat as missing.
pub fn repair_group(
    shards: &mut [Vec<u8>],
    data_count: usize,
    parity_count: usize,
    damaged: &[bool],
) -> Result<()> {
    if shards.len() != data_count + parity_count {
        return Err(LurpaxError::InvalidVault("RS shard count".into()));
    }
    if damaged.len() != shards.len() {
        return Err(LurpaxError::InvalidVault("damage map len".into()));
    }
    let rs = ReedSolomon::new(data_count, parity_count)
        .map_err(|e| LurpaxError::UnrecoverableDamage(format!("reed-solomon: {e}")))?;
    let mut opts: Vec<Option<Vec<u8>>> = shards
        .iter()
        .zip(damaged.iter())
        .map(|(s, bad)| if *bad { None } else { Some(s.clone()) })
        .collect();
    rs.reconstruct(&mut opts)
        .map_err(|e| LurpaxError::UnrecoverableDamage(format!("reed-solomon reconstruct: {e}")))?;
    for (i, o) in opts.into_iter().enumerate() {
        if let Some(v) = o {
            shards[i] = v;
        } else {
            return Err(LurpaxError::UnrecoverableDamage(
                "missing shard after reconstruct".into(),
            ));
        }
    }
    Ok(())
}
