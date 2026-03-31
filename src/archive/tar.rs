//! Bounded tar pack/unpack with path safety checks.

use std::fmt::Write;
use std::fs::{self, File, OpenOptions};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use tar::Archive;

use crate::constants::{
    DEFAULT_MAX_DECOMPRESSED_BYTES, DEFAULT_MAX_FILE_SIZE, DEFAULT_MAX_FILES,
    DEFAULT_MAX_INPUT_BYTES,
};
use crate::errors::{LurpaxError, Result, check_interrupted};

/// Limits for `create` (source tree) and `open` (extracted output).
#[derive(Debug, Clone)]
pub struct ArchiveLimits {
    /// Max total logical bytes read from input tree.
    pub max_input_bytes: u64,
    /// Max entries when archiving a directory.
    pub max_files: u64,
    /// Max single file size.
    pub max_file_size: u64,
    /// Max total decompressed / extracted bytes.
    pub max_output_bytes: u64,
}

impl Default for ArchiveLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: DEFAULT_MAX_INPUT_BYTES,
            max_files: DEFAULT_MAX_FILES,
            max_file_size: DEFAULT_MAX_FILE_SIZE,
            max_output_bytes: DEFAULT_MAX_DECOMPRESSED_BYTES,
        }
    }
}

fn safe_relative_path(path: &Path) -> Result<PathBuf> {
    let mut out = PathBuf::new();
    for c in path.components() {
        match c {
            Component::Normal(p) => out.push(p),
            Component::CurDir => {}
            Component::Prefix(_) | Component::RootDir | Component::ParentDir => {
                return Err(LurpaxError::UnsafeArchive("invalid path component".into()));
            }
        }
    }
    Ok(out)
}

/// Builds an uncompressed tar archive for one file or directory.
pub fn tar_input(input: &Path, limits: &ArchiveLimits) -> Result<Vec<u8>> {
    if !input.exists() {
        return Err(LurpaxError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "input not found",
        )));
    }
    let mut acc_files: u64 = 0;
    let mut acc_bytes: u64 = 0;
    let mut buf = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut buf);
        builder.mode(tar::HeaderMode::Deterministic);
        if input.is_file() {
            let meta = fs::metadata(input)?;
            let len = meta.len();
            if len > limits.max_file_size {
                return Err(LurpaxError::LimitExceeded("file too large".into()));
            }
            acc_bytes = acc_bytes.saturating_add(len);
            if acc_bytes > limits.max_input_bytes {
                return Err(LurpaxError::LimitExceeded("total input too large".into()));
            }
            let name = input
                .file_name()
                .and_then(|s| s.to_str())
                .ok_or_else(|| LurpaxError::UnsafeArchive("bad file name".into()))?;
            let mut f = File::open(input)?;
            builder.append_file(name, &mut f)?;
        } else if input.is_dir() {
            walk_append_dir(
                &mut builder,
                input,
                input,
                limits,
                &mut acc_files,
                &mut acc_bytes,
            )?;
        } else {
            return Err(LurpaxError::UnsafeArchive(
                "only files and directories supported".into(),
            ));
        }
        builder.finish()?;
    }
    Ok(buf)
}

fn walk_append_dir(
    builder: &mut tar::Builder<&mut Vec<u8>>,
    root: &Path,
    dir: &Path,
    limits: &ArchiveLimits,
    acc_files: &mut u64,
    acc_bytes: &mut u64,
) -> Result<()> {
    for ent in fs::read_dir(dir)? {
        let ent = ent?;
        let p = ent.path();
        let ft = ent.file_type()?;
        if ft.is_symlink() {
            return Err(LurpaxError::UnsafeArchive("symlink in source tree".into()));
        }
        let rel = p
            .strip_prefix(root)
            .map_err(|_| LurpaxError::UnsafeArchive("strip prefix".into()))?;
        let rel_s = rel.to_string_lossy();
        if ft.is_dir() {
            builder.append_dir(rel_s.as_ref(), &p)?;
            walk_append_dir(builder, root, &p, limits, acc_files, acc_bytes)?;
        } else if ft.is_file() {
            *acc_files = acc_files.saturating_add(1);
            if *acc_files > limits.max_files {
                return Err(LurpaxError::LimitExceeded("too many files".into()));
            }
            let len = ent.metadata()?.len();
            if len > limits.max_file_size {
                return Err(LurpaxError::LimitExceeded("file too large".into()));
            }
            *acc_bytes = acc_bytes.saturating_add(len);
            if *acc_bytes > limits.max_input_bytes {
                return Err(LurpaxError::LimitExceeded("total input too large".into()));
            }
            let mut f = File::open(&p)?;
            builder.append_file(rel_s.as_ref(), &mut f)?;
        } else {
            return Err(LurpaxError::UnsafeArchive(
                "special file type not supported".into(),
            ));
        }
    }
    Ok(())
}

/// Extracts an uncompressed tar into `dest_dir` using a temp subdirectory.
///
/// Extraction proceeds into a unique temp directory. On success the temp dir is
/// atomically renamed to `<dest_dir>/extracted`. On any failure the temp dir is
/// cleaned up to prevent partial attacker-controlled content on disk.
pub fn extract_tar(
    data: impl std::io::Read,
    dest_dir: &Path,
    limits: &ArchiveLimits,
    term: Option<&Arc<AtomicBool>>,
) -> Result<()> {
    fs::create_dir_all(dest_dir)?;
    let base = fs::canonicalize(dest_dir)?;
    let tmp_name = format!(".lurpax-extracting-{}", random_hex_32()?);
    let tmp = base.join(&tmp_name);
    if tmp.exists() {
        return Err(LurpaxError::Io(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "temp dir exists",
        )));
    }
    fs::create_dir(&tmp)?;
    // AUDIT: all extraction targets live under `tmp`; we verify path containment
    // and set safe permissions (0600 files, 0700 dirs) to prevent suid/sgid restore.
    let res = extract_into_dir(data, &tmp, &base, limits, term);
    if res.is_err() {
        let _ = fs::remove_dir_all(&tmp);
        return res;
    }
    if let Err(e) = normalize_permissions_recursive(&tmp) {
        let _ = fs::remove_dir_all(&tmp);
        return Err(e);
    }
    // Atomic rename of the entire temp dir to final destination.
    let final_dest = base.join("extracted");
    if final_dest.exists() {
        let _ = fs::remove_dir_all(&tmp);
        return Err(LurpaxError::Io(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "destination 'extracted' already exists in output directory",
        )));
    }
    if let Err(e) = fs::rename(&tmp, &final_dest) {
        let _ = fs::remove_dir_all(&tmp);
        return Err(e.into());
    }
    Ok(())
}

fn extract_into_dir(
    data: impl std::io::Read,
    tmp: &Path,
    _base: &Path,
    limits: &ArchiveLimits,
    term: Option<&Arc<AtomicBool>>,
) -> Result<()> {
    let mut archive = Archive::new(data);
    let mut written: u64 = 0;
    let mut files: u64 = 0;
    for entry in archive.entries()? {
        check_interrupted(term)?;
        let mut entry = entry?;
        // AUDIT: strict allowlist — only regular files and directories accepted
        if !entry.header().entry_type().is_file() && !entry.header().entry_type().is_dir() {
            return Err(LurpaxError::UnsafeArchive("unsupported entry type".into()));
        }
        let path = entry.path()?;
        let safe = safe_relative_path(Path::new(path.as_ref()))?;
        let target = tmp.join(&safe);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        if entry.header().entry_type().is_dir() {
            files = files.saturating_add(1);
            if files > limits.max_files {
                return Err(LurpaxError::LimitExceeded("too many entries".into()));
            }
            fs::create_dir_all(&target)?;
            continue;
        }
        files = files.saturating_add(1);
        if files > limits.max_files {
            return Err(LurpaxError::LimitExceeded("too many entries".into()));
        }
        let size = entry.header().size()?;
        if size > limits.max_file_size {
            return Err(LurpaxError::LimitExceeded("entry too large".into()));
        }
        written = written.checked_add(size).ok_or(LurpaxError::Overflow)?;
        if written > limits.max_output_bytes {
            return Err(LurpaxError::LimitExceeded("decompressed too large".into()));
        }
        if let Some(parent) = target.parent() {
            let canon_parent = fs::canonicalize(parent)?;
            // AUDIT: canonicalize + prefix check prevents path traversal
            if !canon_parent.starts_with(fs::canonicalize(tmp)?) {
                return Err(LurpaxError::UnsafeArchive("path escape".into()));
            }
        }
        let mut f = {
            let mut oo = OpenOptions::new();
            oo.write(true).create_new(true);
            // AUDIT: O_EXCL semantics prevent overwriting existing files
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                oo.mode(0o600);
            }
            oo.open(&target)?
        };
        let n = std::io::copy(&mut entry, &mut f)?;
        if n != size {
            return Err(LurpaxError::InvalidVault("short tar read".into()));
        }
    }
    Ok(())
}

/// Recursively set safe permissions: files 0600, directories 0700.
#[cfg(unix)]
fn normalize_permissions_recursive(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let ft = entry.file_type()?;
        let p = entry.path();
        if ft.is_dir() {
            fs::set_permissions(&p, fs::Permissions::from_mode(0o700))?;
            normalize_permissions_recursive(&p)?;
        } else if ft.is_file() {
            fs::set_permissions(&p, fs::Permissions::from_mode(0o600))?;
        }
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn normalize_permissions_recursive(_path: &Path) -> Result<()> {
    Ok(())
}

fn random_hex_32() -> Result<String> {
    // AUDIT: CSPRNG failure is a hard fatal error — never fall back.
    let mut b = [0u8; 16];
    getrandom::getrandom(&mut b).map_err(|_| LurpaxError::RandomUnavailable)?;
    Ok(b.iter().fold(String::with_capacity(32), |mut acc, &x| {
        let _ = write!(acc, "{x:02x}");
        acc
    }))
}
