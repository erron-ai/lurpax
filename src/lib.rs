//! Lurpax — encrypted snapshot vault tool (Erron.ai).
//!
//! Creates `.lurpax` files: zstd-compressed tar payloads split into
//! independently authenticated chunks (XChaCha20-Poly1305 STREAM), protected by
//! Argon2id-derived keys with HKDF separation and key commitment, plus
//! Reed–Solomon parity for transparent repair of limited corruption.
//!
//! **Threat model (summary):** Protects confidentiality and integrity against
//! offline attackers who obtain the vault file but not the password (and
//! optional YubiKey response). Plaintext header fields are visible without the
//! password — see [`SECURITY.md`](../../SECURITY.md). Local malware with full
//! memory access is out of scope for v1.
//!
//! **Feature flags:** No `#[cfg(feature)]` may weaken crypto or parsing checks.

#![warn(missing_docs)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

pub mod archive;
pub mod cli;
pub mod constants;
pub mod crypto;
pub mod errors;
pub mod hardware;
pub mod recovery;
pub mod vault;

pub use errors::LurpaxError;
pub use errors::Result;
