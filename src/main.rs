//! Binary entry: process hardening and CLI dispatch.

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use clap::Parser;
#[cfg(target_os = "linux")]
use libc::c_int;
#[cfg(unix)]
use libc::{RLIMIT_CORE, rlimit, setrlimit};
use lurpax::cli::{Cli, run};
use signal_hook::consts::{SIGHUP, SIGINT, SIGTERM};
use signal_hook::flag;

#[cfg(unix)]
fn set_core_limit_zero() {
    let lim = rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `setrlimit` is a POSIX API; `lim` is a valid stack value.
    unsafe {
        // AUDIT: prevent core dumps from writing key material to disk
        if setrlimit(RLIMIT_CORE, &lim) != 0 {
            eprintln!("warning: failed to restrict core dump size (setrlimit)");
        }
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
        if libc::prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 {
            eprintln!("warning: failed to set PR_SET_DUMPABLE");
        }
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
