//! Typed errors — no sensitive material in `Display` output.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use thiserror::Error;

/// Library result alias.
pub type Result<T> = std::result::Result<T, LurpaxError>;

/// Top-level error for Lurpax operations.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum LurpaxError {
    /// I/O failure.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// User cancelled or mismatched password.
    #[error("password error: {0}")]
    Password(String),

    /// Output path already exists on create.
    #[error("output file already exists — delete it first")]
    OutputExists,

    /// Vault metadata could not be parsed or validated.
    #[error("invalid vault: {0}")]
    InvalidVault(String),

    /// Wrong password, tampering, or AEAD failure (user-indistinguishable cases).
    #[error("decryption/authentication failed")]
    DecryptAuthFailed,

    /// Internal crypto operation failed (distinct from wrong password).
    #[error("cryptographic error: {0}")]
    Crypto(String),

    /// Reed–Solomon capacity exceeded — data unrecoverable.
    #[error("unrecoverable vault damage: {0}")]
    UnrecoverableDamage(String),

    /// Archive policy violation (path traversal, symlink, etc.).
    #[error("unsafe archive entry: {0}")]
    UnsafeArchive(String),

    /// Resource limit exceeded (size, file count, etc.).
    #[error("resource limit exceeded: {0}")]
    LimitExceeded(String),

    /// YubiKey / `ykman` integration failure.
    #[error("YubiKey error: {0}")]
    YubiKey(String),

    /// Random number generator unavailable.
    #[error("system random number generator unavailable")]
    RandomUnavailable,

    /// Operation interrupted by signal.
    #[error("interrupted")]
    Interrupted,

    /// Verify-only: vault structurally unreadable (exit code 3 mapping).
    #[error("vault structurally unreadable")]
    StructurallyUnreadable,

    /// Numeric overflow when computing sizes.
    #[error("size arithmetic overflow")]
    Overflow,
}

/// Cooperative shutdown check (e.g. SIGINT mapped to `AtomicBool`).
pub fn check_interrupted(term: Option<&Arc<AtomicBool>>) -> Result<()> {
    if let Some(t) = term
        && t.load(Ordering::Relaxed)
    {
        return Err(LurpaxError::Interrupted);
    }
    Ok(())
}

/// Verify health classification for reporting (not an error until mapped to exit code).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VerifyHealth {
    /// No CRC mismatches.
    Healthy,
    /// Damage present but RS can repair within each group.
    Repairable,
    /// RS capacity exceeded somewhere.
    Unrecoverable,
    /// Header, tail, or checksum table unusable.
    Unreadable,
}

impl VerifyHealth {
    /// Exit code for `lurpax verify`.
    pub fn exit_code(self) -> i32 {
        match self {
            VerifyHealth::Healthy => 0,
            VerifyHealth::Repairable => 1,
            VerifyHealth::Unrecoverable => 2,
            VerifyHealth::Unreadable => 3,
        }
    }
}
