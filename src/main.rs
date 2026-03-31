//! Binary entry: process hardening and CLI dispatch.

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use clap::Parser;
#[cfg(unix)]
use libc::{rlimit, setrlimit, RLIMIT_CORE, RLIM_INFINITY};
#[cfg(target_os = "linux")]
use libc::c_int;
use lurpax::cli::{run, Cli};
use signal_hook::consts::{SIGHUP, SIGINT, SIGTERM};
use signal_hook::flag;

#[cfg(unix)]
fn set_core_limit_zero() {
    let lim = rlimit {
        rlim_cur: 0,
        rlim_max: RLIM_INFINITY,
    };
    // SAFETY: `setrlimit` is a POSIX API; `lim` is a valid stack value.
    unsafe {
        // AUDIT: prevent core dumps from writing key material to disk
        let _ = setrlimit(RLIMIT_CORE, &lim);
    }
}

#[cfg(not(unix))]
fn set_core_limit_zero() {}

#[cfg(target_os = "linux")]
fn set_no_dump() {
    const PR_SET_DUMPABLE: c_int = 4;
    // SAFETY: `prctl` is a Linux syscall; constant is defined by the kernel ABI.
    unsafe {
        // AUDIT: prevent ptrace attachment on Linux
        libc::prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
    }
}

#[cfg(not(target_os = "linux"))]
fn set_no_dump() {}

fn main() -> io::Result<()> {
    set_core_limit_zero();
    set_no_dump();

    let term = Arc::new(AtomicBool::new(false));
    flag::register(SIGTERM, Arc::clone(&term))?;
    flag::register(SIGINT, Arc::clone(&term))?;
    flag::register(SIGHUP, Arc::clone(&term))?;

    let cli = Cli::parse();
    if term.load(Ordering::Relaxed) {
        std::process::exit(130);
    }
    let code = run(cli, term);
    std::process::exit(code);
}
