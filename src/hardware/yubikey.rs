//! Hardened `ykman otp calculate` invocation (challenge as **hex** on stdin; see Yubico docs).

use std::fs;
use std::io::Write;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use zeroize::Zeroizing;

use crate::constants::{ENV_YKMAN_PATH, YKMAN_CANDIDATE_PATHS, YUBI_RESPONSE_HEX_LEN};
use crate::errors::{LurpaxError, Result};

const YKMAN_WAIT_TIMEOUT: Duration = Duration::from_secs(30);

/// Computes the 20-byte YubiKey response for a stored challenge.
pub trait YubiKeyPort {
    /// Runs challenge-response for OTP slot `1` or `2`.
    fn otp_calculate(&self, slot: u8, challenge: &[u8; 32]) -> Result<Zeroizing<[u8; 20]>>;
}

fn is_world_writable(mode: u32) -> bool {
    (mode & 0o002) != 0
}

fn validate_ykman_path(path: &Path) -> Result<()> {
    // AUDIT: lstat (symlink_metadata) to detect symlinks without following them.
    let meta = fs::symlink_metadata(path)?;
    if meta.is_symlink() {
        return Err(LurpaxError::YubiKey(format!(
            "ykman path must not be a symlink. Package managers (e.g. Homebrew) symlink `bin/ykman`; lurpax only executes a regular file.\n\
             Set {ENV_YKMAN_PATH} to the symlink target. Hint: `ls -l \"$(which ykman)\"` shows it; on Linux `readlink -f \"$(which ykman)\"` prints the path.\n\
             See README (YubiKey Setup)."
        )));
    }
    if !meta.is_file() {
        return Err(LurpaxError::YubiKey("ykman is not a regular file".into()));
    }
    let mode = meta.mode();
    if is_world_writable(mode) {
        return Err(LurpaxError::YubiKey(
            "ykman must not be world-writable".into(),
        ));
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
            if let Ok(m) = fs::metadata(anc)
                && is_world_writable(m.mode())
            {
                return Err(LurpaxError::YubiKey(
                    "ykman parent directory must not be world-writable".into(),
                ));
            }
        }
    }
    Ok(())
}

fn resolve_ykman_path() -> Result<PathBuf> {
    if let Ok(p) = std::env::var(ENV_YKMAN_PATH) {
        // AUDIT: env-override bypasses the standard search list; warn the user.
        eprintln!(
            "warning: using ykman from {ENV_YKMAN_PATH} (env override bypasses standard path search)"
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

/// 32-byte challenge as 64 lowercase hex ASCII bytes + newline (`ykman` expects hex, not raw binary).
fn challenge_hex_line(challenge: &[u8; 32]) -> [u8; 65] {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = [0u8; 65];
    for (i, &b) in challenge.iter().enumerate() {
        out[i * 2] = HEX[usize::from(b >> 4)];
        out[i * 2 + 1] = HEX[usize::from(b & 0xf)];
    }
    out[64] = b'\n';
    out
}

fn sanitize_stderr(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control() || *c == '\n')
        .take(256)
        .collect()
}

fn ykman_minimal_env() -> Vec<(String, String)> {
    let path = std::env::var("PATH")
        .unwrap_or_else(|_| "/usr/bin:/usr/local/bin:/opt/homebrew/bin".to_string());
    let mut out = vec![("PATH".to_string(), path)];
    if let Ok(h) = std::env::var("HOME") {
        out.push(("HOME".to_string(), h));
    }
    if let Ok(u) = std::env::var("USER") {
        out.push(("USER".to_string(), u));
    }
    out
}

#[cfg(unix)]
fn kill_ykman_child(pid: u32) {
    // SAFETY: `kill` is a POSIX API; SIGKILL terminates the stuck `ykman` process.
    unsafe {
        let _ = libc::kill(pid as libc::pid_t, libc::SIGKILL);
    }
}

#[cfg(not(unix))]
fn kill_ykman_child(_pid: u32) {}

/// Production `ykman` backend.
pub struct RealYubiKey;

impl YubiKeyPort for RealYubiKey {
    fn otp_calculate(&self, slot: u8, challenge: &[u8; 32]) -> Result<Zeroizing<[u8; 20]>> {
        if slot != 1 && slot != 2 {
            return Err(LurpaxError::YubiKey("slot must be 1 or 2".into()));
        }
        let ykman = resolve_ykman_path()?;
        eprintln!(
            "YubiKey: touch the key now if it flashes or blinks (challenge-response, slot {slot})."
        );
        let mut cmd = Command::new(&ykman);
        cmd.args(["otp", "calculate", &slot.to_string()])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .env_clear();
        for (k, v) in ykman_minimal_env() {
            cmd.env(k, v);
        }
        let mut child = cmd
            .spawn()
            .map_err(|e| LurpaxError::YubiKey(format!("spawn ykman: {e}")))?;
        let pid = child.id();
        if let Some(mut stdin) = child.stdin.take() {
            let line = challenge_hex_line(challenge);
            stdin
                .write_all(&line)
                .map_err(|e| LurpaxError::YubiKey(format!("stdin: {e}")))?;
        }
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let _ = tx.send(child.wait_with_output());
        });
        let out = match rx.recv_timeout(YKMAN_WAIT_TIMEOUT) {
            Ok(Ok(out)) => out,
            Ok(Err(e)) => {
                return Err(LurpaxError::YubiKey(format!("ykman: {e}")));
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                kill_ykman_child(pid);
                return Err(LurpaxError::YubiKey("ykman timed out".into()));
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err(LurpaxError::YubiKey("ykman wait failed".into()));
            }
        };
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
        let hex_clean = Zeroizing::new(
            hex_line
                .chars()
                .filter(|c| c.is_ascii_hexdigit())
                .collect::<String>(),
        );
        if hex_clean.len() != YUBI_RESPONSE_HEX_LEN {
            return Err(LurpaxError::YubiKey("invalid ykman response length".into()));
        }
        let mut outb = Zeroizing::new([0u8; 20]);
        for (i, chunk) in hex_clean.as_bytes().chunks(2).enumerate() {
            if i >= 20 {
                break;
            }
            let s =
                std::str::from_utf8(chunk).map_err(|_| LurpaxError::YubiKey("hex utf8".into()))?;
            outb[i] =
                u8::from_str_radix(s, 16).map_err(|_| LurpaxError::YubiKey("hex parse".into()))?;
        }
        Ok(outb)
    }
}

#[cfg(test)]
mod tests {
    use super::challenge_hex_line;

    #[test]
    fn challenge_hex_line_lowercase_and_newline() {
        let mut c = [0u8; 32];
        c[0] = 0;
        c[1] = 1;
        c[2] = 0xff;
        c[3] = 0xa1;
        let line = challenge_hex_line(&c);
        assert_eq!(&line[..6], b"0001ff");
        assert_eq!(line[6..8], *b"a1");
        assert_eq!(line[64], b'\n');
    }
}
