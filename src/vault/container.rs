//! On-disk `.lurpax` layout: magic, header, shards, CRC table, tail.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use crate::constants::MAGIC;
use crate::errors::{LurpaxError, Result};
use crate::vault::header::{
    expected_file_len, read_header_len_prefix, shard_cipher_size, total_shards, Header,
};

/// Parsed vault layout references.
pub struct VaultLayout {
    /// Parsed header.
    pub header: Header,
    /// Exact serialized header body bytes (for AEAD AAD).
    pub header_body: Vec<u8>,
    /// All shards in on-disk order (data+parity per groups).
    pub shards: Vec<Vec<u8>>,
    /// CRC-32C table (may be empty if unreadable).
    pub crc_table: Vec<u8>,
    /// Whether CRC table matched shard count.
    pub crc_table_valid: bool,
}

fn read_magic<R: Read>(r: &mut R) -> Result<()> {
    let mut m = [0u8; 5];
    r.read_exact(&mut m)?;
    if &m != MAGIC {
        return Err(LurpaxError::InvalidVault("bad magic".into()));
    }
    Ok(())
}

/// Reads primary header from the start of `file`.
pub fn read_primary_header(file: &mut File) -> Result<(Header, Vec<u8>)> {
    read_magic(file)?;
    let n = read_header_len_prefix(file)?;
    let mut body = vec![0u8; n as usize];
    file.read_exact(&mut body)?;
    let h = Header::from_bytes_exact(&body)?;
    Ok((h, body))
}

/// Attempts tail header recovery (last 9 bytes: `len` + `LURPX`).
pub fn read_tail_header(file: &mut File, file_len: u64) -> Result<(Header, Vec<u8>)> {
    if file_len < 9 {
        return Err(LurpaxError::InvalidVault("file too small for tail".into()));
    }
    file.seek(SeekFrom::Start(file_len - 5))?;
    let mut tail_magic = [0u8; 5];
    file.read_exact(&mut tail_magic)?;
    if &tail_magic != MAGIC {
        return Err(LurpaxError::InvalidVault("bad tail magic".into()));
    }
    file.seek(SeekFrom::Start(file_len - 9))?;
    let mut tl = [0u8; 4];
    file.read_exact(&mut tl)?;
    let n = u32::from_le_bytes(tl);
    if n == 0 || n > crate::constants::MAX_HEADER_BODY_LEN {
        return Err(LurpaxError::InvalidVault("bad tail header length".into()));
    }
    let start = file_len
        .checked_sub(9 + u64::from(n))
        .ok_or(LurpaxError::InvalidVault("tail offset".into()))?;
    file.seek(SeekFrom::Start(start))?;
    let mut body = vec![0u8; n as usize];
    file.read_exact(&mut body)?;
    let h = Header::from_bytes_exact(&body)?;
    Ok((h, body))
}

/// Reads header (primary, else tail) and validates file length.
pub fn read_header_any(file: &mut File) -> Result<(Header, Vec<u8>)> {
    let len = file.metadata()?.len();
    let primary = (|| -> Result<(Header, Vec<u8>)> {
        file.seek(SeekFrom::Start(0))?;
        read_primary_header(file)
    })();
    match primary {
        Ok(v) => {
            let exp = expected_file_len(&v.0, v.1.len() as u32)?;
            if exp != len {
                return Err(LurpaxError::InvalidVault("file size mismatch".into()));
            }
            Ok(v)
        }
        Err(_) => {
            let v = read_tail_header(file, len)?;
            let exp = expected_file_len(&v.0, v.1.len() as u32)?;
            if exp != len {
                return Err(LurpaxError::InvalidVault(
                    "file size mismatch (tail)".into(),
                ));
            }
            Ok(v)
        }
    }
}

/// Loads shards and CRC table after the header prefix.
///
/// `reader` must be seekable from the start of the vault file; this function seeks to the first
/// shard byte (`9 + header_body.len()` from the beginning).
pub fn read_payload<R: Read + Seek>(
    reader: &mut R,
    header: &Header,
    header_body: Vec<u8>,
) -> Result<VaultLayout> {
    let h = Header::from_bytes_exact(&header_body)?;
    if h != *header {
        return Err(LurpaxError::InvalidVault("header re-parse mismatch".into()));
    }
    let off = 9u64
        .checked_add(header_body.len() as u64)
        .ok_or(LurpaxError::Overflow)?;
    reader.seek(SeekFrom::Start(off))?;
    let ss = usize::try_from(shard_cipher_size(header)?).map_err(|_| LurpaxError::Overflow)?;
    let ts = usize::try_from(total_shards(header)?).map_err(|_| LurpaxError::Overflow)?;
    let _shard_bytes = ss.checked_mul(ts).ok_or(LurpaxError::Overflow)?;
    let mut shards = Vec::with_capacity(ts);
    for _ in 0..ts {
        let mut s = vec![0u8; ss];
        reader.read_exact(&mut s)?;
        shards.push(s);
    }
    let crc_len = ts.checked_mul(4).ok_or(LurpaxError::Overflow)?;
    let mut crc_table = vec![0u8; crc_len];
    let crc_read = reader.read(&mut crc_table)?;
    let crc_table_valid = crc_read == crc_len;
    if !crc_table_valid {
        crc_table.truncate(crc_read);
    }
    Ok(VaultLayout {
        header: h,
        header_body,
        shards,
        crc_table,
        crc_table_valid,
    })
}

/// Writes a complete vault atomically via temp file + rename.
pub fn write_atomic(
    path: &Path,
    header: &Header,
    header_body: &[u8],
    shards: &[Vec<u8>],
    crc_table: &[u8],
) -> Result<()> {
    if header_body != header.to_bytes().as_slice() {
        return Err(LurpaxError::Crypto("header body mismatch".into()));
    }
    let tmp = path.with_extension("lurpax.partial");
    // AUDIT: temp file with 0600 + fsync + rename provides atomic, permission-safe writes
    let mut oo = OpenOptions::new();
    oo.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        oo.mode(0o600);
    }
    let mut f = oo.open(&tmp)?;
    let n = u32::try_from(header_body.len()).map_err(|_| LurpaxError::Overflow)?;
    let write_body = (|| -> Result<()> {
        f.write_all(MAGIC)?;
        f.write_all(&n.to_le_bytes())?;
        f.write_all(header_body)?;
        for s in shards {
            f.write_all(s)?;
        }
        f.write_all(crc_table)?;
        // AUDIT: identical header copy at tail enables recovery from primary header corruption
        f.write_all(header_body)?;
        f.write_all(&n.to_le_bytes())?;
        f.write_all(MAGIC)?;
        Ok(())
    })();
    if let Err(e) = write_body {
        drop(f);
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    if let Err(e) = f.sync_all() {
        drop(f);
        let _ = std::fs::remove_file(&tmp);
        return Err(e.into());
    }
    drop(f);
    // AUDIT: after fsync, keep `tmp` if rename fails so operators can recover manually.
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Expands flat `data_shards` into on-disk shard list with RS parity per group.
pub fn layout_shards_with_rs(data_shards: Vec<Vec<u8>>, header: &Header) -> Result<Vec<Vec<u8>>> {
    use crate::recovery::fec::encode_rs_group;

    let d = header.rs_data_shards_per_group as usize;
    let p = header.rs_parity_shards_per_group as usize;
    let n = usize::try_from(header.chunk_count).map_err(|_| LurpaxError::Overflow)?;
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < n {
        let k = (n - i).min(d);
        let group: Vec<Vec<u8>> = data_shards[i..i + k].to_vec();
        let enc = encode_rs_group(&group, p)?;
        out.extend(enc);
        i += k;
    }
    Ok(out)
}
