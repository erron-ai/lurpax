//! Command-line interface (`clap`). Only this module and `main` print to the terminal.

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use zeroize::Zeroizing;

use crate::archive::ArchiveLimits;
use crate::errors::{LurpaxError, Result, VerifyHealth};
use crate::hardware::{RealYubiKey, YubiKeyPort};
use crate::vault::VaultService;

/// Lurpax — encrypted snapshot vault (Erron.ai).
#[derive(Parser, Debug)]
#[command(name = "lurpax", version, about)]
pub struct Cli {
    /// Subcommand to execute.
    #[command(subcommand)]
    pub command: Commands,
}

/// Available subcommands.
#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Create a new `.lurpax` vault (refuses to overwrite).
    Create {
        /// Output `.lurpax` vault path.
        #[arg(long)]
        output: PathBuf,
        /// Input file or directory to archive.
        #[arg(long)]
        input: PathBuf,
        /// Read password from file (non-interactive).
        #[arg(long)]
        password_file: Option<PathBuf>,
        /// YubiKey OTP slot (1 or 2).
        #[arg(long)]
        yubikey_slot: Option<u8>,
        /// Maximum total input bytes.
        #[arg(long)]
        max_input_size: Option<u64>,
        /// Maximum number of input files.
        #[arg(long)]
        max_files: Option<u64>,
        /// Maximum single input file size.
        #[arg(long)]
        max_file_size: Option<u64>,
    },
    /// Decrypt and extract a vault.
    Open {
        /// Path to the `.lurpax` vault file.
        #[arg(long)]
        vault: PathBuf,
        /// Directory to extract contents into.
        #[arg(long)]
        out_dir: PathBuf,
        /// Read password from file (non-interactive).
        #[arg(long)]
        password_file: Option<PathBuf>,
        /// Maximum total extracted size.
        #[arg(long)]
        max_size: Option<u64>,
        /// Maximum number of extracted files.
        #[arg(long)]
        max_files: Option<u64>,
        /// Maximum single extracted file size.
        #[arg(long)]
        max_file_size: Option<u64>,
    },
    /// Check shard CRC / RS health (no password).
    Verify {
        /// Path to the `.lurpax` vault file.
        #[arg(long)]
        vault: PathBuf,
    },
}

fn read_password_file(path: &std::path::Path) -> Result<Zeroizing<Vec<u8>>> {
    let meta = fs::symlink_metadata(path)?;
    if meta.file_type().is_symlink() {
        return Err(LurpaxError::Password(
            "password file must not be a symlink".into(),
        ));
    }
    let raw = fs::read(path)?;
    if raw.is_empty() {
        return Err(LurpaxError::Password(
            "password must not be empty".into(),
        ));
    }
    let mut s = raw;
    if s.ends_with(b"\r\n") {
        s.truncate(s.len() - 2);
    } else if s.ends_with(b"\n") {
        s.truncate(s.len() - 1);
    }
    if s.is_empty() || s.len() > crate::constants::MAX_PASSWORD_LEN {
        return Err(LurpaxError::Password("password length invalid".into()));
    }
    Ok(Zeroizing::new(s))
}

fn read_password_interactive(confirm: bool) -> Result<Zeroizing<Vec<u8>>> {
    use crate::constants::{MAX_PASSWORD_LEN, MIN_PASSWORD_LEN};
    for _ in 0..3 {
        let p = rpassword::prompt_password("Password: ")
            .map_err(|e| LurpaxError::Password(format!("tty: {e}")))?;
        let bytes = p.into_bytes();
        if !(MIN_PASSWORD_LEN..=MAX_PASSWORD_LEN).contains(&bytes.len()) {
            eprintln!("password must be 1..=8192 bytes");
            continue;
        }
        if confirm {
            let p2 = rpassword::prompt_password("Confirm password: ")
                .map_err(|e| LurpaxError::Password(format!("tty: {e}")))?;
            if p2.into_bytes() != bytes {
                eprintln!("passwords do not match");
                continue;
            }
        }
        return Ok(Zeroizing::new(bytes));
    }
    Err(LurpaxError::Password(
        "too many failed password attempts".into(),
    ))
}

fn resolve_password(path: Option<PathBuf>, confirm: bool) -> Result<Zeroizing<Vec<u8>>> {
    match path {
        Some(p) => read_password_file(&p),
        None => read_password_interactive(confirm),
    }
}

fn mk_limits(
    max_input_size: Option<u64>,
    max_files: Option<u64>,
    max_file_size: Option<u64>,
    max_out: Option<u64>,
) -> ArchiveLimits {
    let mut l = ArchiveLimits::default();
    if let Some(x) = max_input_size {
        l.max_input_bytes = x;
    }
    if let Some(x) = max_files {
        l.max_files = x;
    }
    if let Some(x) = max_file_size {
        l.max_file_size = x;
    }
    if let Some(x) = max_out {
        l.max_output_bytes = x;
    }
    l
}

/// Runs the CLI; returns a process exit code.
///
/// The `term` flag is checked between processing steps for cooperative shutdown.
pub fn run(cli: Cli, term: Arc<AtomicBool>) -> i32 {
    match run_inner(cli, term) {
        Ok(RunOutcome::Success) => 0,
        Ok(RunOutcome::Verify(code)) => code,
        Err(e) => {
            eprintln!("{e}");
            1
        }
    }
}

enum RunOutcome {
    Success,
    Verify(i32),
}

fn run_inner(cli: Cli, term: Arc<AtomicBool>) -> Result<RunOutcome> {
    match cli.command {
        Commands::Create {
            output,
            input,
            password_file,
            yubikey_slot,
            max_input_size,
            max_files,
            max_file_size,
        } => {
            if let Some(s) = yubikey_slot {
                if s != 1 && s != 2 {
                    return Err(crate::errors::LurpaxError::YubiKey(
                        "--yubikey-slot must be 1 or 2".into(),
                    ));
                }
            }
            let pwd = resolve_password(password_file, true)?;
            let limits = mk_limits(max_input_size, max_files, max_file_size, None);
            let y: Option<RealYubiKey> = yubikey_slot.map(|_| RealYubiKey);
            let y_ref: Option<&dyn YubiKeyPort> = y.as_ref().map(|r| r as &dyn YubiKeyPort);
            VaultService::create(
                &output,
                &input,
                pwd.as_slice(),
                y_ref,
                yubikey_slot,
                limits,
                Some(term),
            )?;
            Ok(RunOutcome::Success)
        }
        Commands::Open {
            vault,
            out_dir,
            password_file,
            max_size,
            max_files,
            max_file_size,
        } => {
            let pwd = resolve_password(password_file, false)?;
            let limits = mk_limits(None, max_files, max_file_size, max_size);
            let y = RealYubiKey;
            let y_ref: &dyn YubiKeyPort = &y;
            let repaired = VaultService::open(
                &vault,
                &out_dir,
                pwd.as_slice(),
                Some(y_ref),
                limits,
                Some(term),
            )?;
            if repaired > 0 {
                eprintln!(
                    "warning: repaired approximately {repaired} bytes in corrupted shards"
                );
            }
            Ok(RunOutcome::Success)
        }
        Commands::Verify { vault } => {
            let h = VaultService::verify(&vault)?;
            let code = h.exit_code();
            match h {
                VerifyHealth::Healthy => {
                    println!("✓ vault OK — no corruption detected");
                }
                VerifyHealth::Repairable => {
                    println!("⚠ vault damaged but repairable by Reed–Solomon when opened");
                }
                VerifyHealth::Unrecoverable => {
                    println!("✗ vault has damage beyond RS capacity in at least one group");
                }
                VerifyHealth::Unreadable => {
                    println!("✗ vault structurally unreadable");
                }
            }
            Ok(RunOutcome::Verify(code))
        }
    }
}
