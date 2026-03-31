//! Hardened `ykman otp calculate` invocation (challenge on stdin).

use std::fs;
use std::io::Write;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::constants::{
    ENV_YKMAN_PATH, YKMAN_CANDIDATE_PATHS, YUBI_RESPONSE_HEX_LEN,
};
use crate::errors::{LurpaxError, Result};

/// Computes the 20-byte YubiKey response for a stored challenge.
pub trait YubiKeyPort {
    /// Runs challenge-response for OTP slot `1` or `2`.
    fn otp_calculate(&self, slot: u8, challenge: &[u8; 32]) -> Result<[u8; 20]>;
}

fn is_world_writable(mode: u32) -> bool {
    (mode & 0o002) != 0
}

fn validate_ykman_path(path: &Path) -> Result<()> {
    // AUDIT: lstat (symlink_metadata) to detect symlinks without following them.
    let meta = fs::symlink_metadata(path)?;
    if meta.is_symlink() {
        return Err(LurpaxError::YubiKey(
            "ykman path must not be a symlink".into(),
        ));
    }
    if !meta.is_file() {
        return Err(LurpaxError::YubiKey("ykman is not a regular file".into()));
    }
    let mode = meta.mode();
    if is_world_writable(mode) {
        return Err(LurpaxError::YubiKey("ykman must not be world-writable".into()));
    }
    #[cfg(unix)]
    {
        let uid = unsafe { libc::getuid() };
        let st_uid = meta.uid();
        if st_uid != 0 && st_uid != uid {
            return Err(LurpaxError::YubiKey(
                "ykman must be owned by root or the current user".into(),
            ));
        }
    }
    if let Some(parent) = path.parent() {
        for anc in parent.ancestors() {
            if anc.as_os_str().is_empty() {
                break;
            }
            if let Ok(m) = fs::metadata(anc) {
                if is_world_writable(m.mode()) {
                    return Err(LurpaxError::YubiKey(
                        "ykman parent directory must not be world-writable".into(),
                    ));
                }
            }
        }
    }
    Ok(())
}

fn resolve_ykman_path() -> Result<PathBuf> {
    if let Ok(p) = std::env::var(ENV_YKMAN_PATH) {
        // AUDIT: env-override bypasses the standard search list; warn the user.
        eprintln!(
            "warning: using ykman from {} (env override bypasses standard path search)",
            ENV_YKMAN_PATH,
        );
        let pb = PathBuf::from(p);
        validate_ykman_path(&pb)?;
        return Ok(pb);
    }
    for c in YKMAN_CANDIDATE_PATHS {
        let pb = PathBuf::from(c);
        if pb.is_file() {
            validate_ykman_path(&pb)?;
            return Ok(pb);
        }
    }
    Err(LurpaxError::YubiKey(
        "ykman not found (install YubiKey Manager CLI)".into(),
    ))
}

fn sanitize_stderr(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control() || *c == '\n')
        .take(256)
        .collect()
}

/// Production `ykman` backend.
pub struct RealYubiKey;

impl YubiKeyPort for RealYubiKey {
    fn otp_calculate(&self, slot: u8, challenge: &[u8; 32]) -> Result<[u8; 20]> {
        if slot != 1 && slot != 2 {
            return Err(LurpaxError::YubiKey("slot must be 1 or 2".into()));
        }
        let ykman = resolve_ykman_path()?;
        let mut child = Command::new(&ykman)
            .args(["otp", "calculate", &slot.to_string()])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| LurpaxError::YubiKey(format!("spawn ykman: {e}")))?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(challenge)
                .map_err(|e| LurpaxError::YubiKey(format!("stdin: {e}")))?;
        }
        let out = child
            .wait_with_output()
            .map_err(|e| LurpaxError::YubiKey(format!("ykman: {e}")))?;
        if !out.status.success() {
            let msg = sanitize_stderr(&String::from_utf8_lossy(&out.stderr));
            return Err(LurpaxError::YubiKey(format!(
                "ykman failed (see logs): {msg}"
            )));
        }
        let text = String::from_utf8_lossy(&out.stdout);
        let hex_line = text
            .lines()
            .map(str::trim)
            .find(|l| !l.is_empty())
            .ok_or_else(|| LurpaxError::YubiKey("empty ykman output".into()))?;
        let hex_clean: String = hex_line.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        if hex_clean.len() != YUBI_RESPONSE_HEX_LEN {
            return Err(LurpaxError::YubiKey("invalid ykman response length".into()));
        }
        let mut outb = [0u8; 20];
        for (i, chunk) in hex_clean.as_bytes().chunks(2).enumerate() {
            if i >= 20 {
                break;
            }
            let s = std::str::from_utf8(chunk).map_err(|_| LurpaxError::YubiKey("hex utf8".into()))?;
            outb[i] = u8::from_str_radix(s, 16).map_err(|_| LurpaxError::YubiKey("hex parse".into()))?;
        }
        Ok(outb)
    }
}
