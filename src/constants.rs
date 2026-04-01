//! Named constants for format, policy, and cryptography.
//!
//! Numeric literals with security or wire-format meaning belong here — not inlined.

/// Five-byte on-disk magic identifying a Lurpax vault (ASCII `LURPX`).
pub const MAGIC: &[u8; 5] = b"LURPX";

/// Format `version` field in the header (v1 wire layout).
pub const HEADER_VERSION_V1: u16 = 1;

/// Header format with password-wrapped YubiKey challenge (no plaintext challenge on disk).
pub const HEADER_VERSION_V2: u16 = 2;

/// `kdf_algorithm` value for Argon2id (only supported KDF in v1).
pub const KDF_ARGON2ID: u8 = 1;

/// Default Argon2id memory cost in KiB (256 MiB).
pub const DEFAULT_ARGON2_MEM_KIB: u32 = 262_144;

/// Default Argon2id time cost (iterations).
pub const DEFAULT_ARGON2_ITERATIONS: u32 = 3;

/// Default Argon2id parallelism lanes.
pub const DEFAULT_ARGON2_PARALLELISM: u32 = 4;

/// Minimum Argon2id memory (KiB) accepted on open (256 MiB).
pub const MIN_ARGON2_MEM_KIB: u32 = 262_144;

/// Maximum Argon2id memory (KiB) accepted on open (256 MiB; same as the default).
///
/// Capped at that value so a malicious header cannot force a larger Argon2 allocation
/// before key-commitment verification (CWE-770).
pub const MAX_ARGON2_MEM_KIB: u32 = 262_144;

/// Minimum Argon2id time cost accepted on open.
pub const MIN_ARGON2_ITERATIONS: u32 = 3;

/// Maximum Argon2id time cost accepted on open.
pub const MAX_ARGON2_ITERATIONS: u32 = 10;

/// Minimum Argon2id parallelism accepted on open.
pub const MIN_ARGON2_PARALLELISM: u32 = 1;

/// Maximum Argon2id parallelism accepted on open.
pub const MAX_ARGON2_PARALLELISM: u32 = 16;

/// Argon2id output size feeding HKDF (never used directly as AEAD key).
pub const ARGON2_OUTPUT_LEN: usize = 64;

/// Argon2id parameters for the YubiKey challenge wrap subkey (password-only IKM).
pub const YUBI_CHALLENGE_WRAP_MEM_KIB: u32 = 65_536;

/// Time cost for YubiKey challenge wrap Argon2id.
pub const YUBI_CHALLENGE_WRAP_ITERATIONS: u32 = 2;

/// Parallelism for YubiKey challenge wrap Argon2id.
pub const YUBI_CHALLENGE_WRAP_PARALLELISM: u32 = 4;

/// Plaintext chunk size for STREAM (compressed payload); v1 fixed size.
pub const CHUNK_PLAINTEXT_SIZE: u32 = 65_536;

/// Default Reed–Solomon data shards per group.
pub const RS_DATA_SHARDS_PER_GROUP: u16 = 19;

/// Default Reed–Solomon parity shards per group (~15.8% overhead).
pub const RS_PARITY_SHARDS_PER_GROUP: u16 = 3;

/// Maximum serialized header body size before allocation (anti-DoS).
pub const MAX_HEADER_BODY_LEN: u32 = 4096;

/// Minimum password length in bytes (empty rejected).
pub const MIN_PASSWORD_LEN: usize = 1;

/// Maximum password length in bytes (interactive and `--password-file`).
pub const MAX_PASSWORD_LEN: usize = 8 * 1024;

/// HKDF-SHA256 `info` for the AEAD subkey.
pub const HKDF_INFO_ENC: &[u8] = b"lurpax-enc-v1";

/// HKDF-SHA256 `info` for the key-commitment subkey.
pub const HKDF_INFO_COMMIT: &[u8] = b"lurpax-commit-v1";

/// Default maximum decompressed extraction size (4 GiB).
pub const DEFAULT_MAX_DECOMPRESSED_BYTES: u64 = 4 * 1024 * 1024 * 1024;

/// Default maximum total input size for `create` (4 GiB).
pub const DEFAULT_MAX_INPUT_BYTES: u64 = 4 * 1024 * 1024 * 1024;

/// Default maximum number of files archived from a directory tree.
pub const DEFAULT_MAX_FILES: u64 = 100_000;

/// Default maximum single file size accepted for archive input.
pub const DEFAULT_MAX_FILE_SIZE: u64 = 4 * 1024 * 1024 * 1024;

/// YubiKey response length accepted from `ykman` stdout (40 hex chars → 20 bytes).
pub const YUBI_RESPONSE_HEX_LEN: usize = 40;

/// Environment variable overriding `ykman` path (high-risk; emits warning).
pub const ENV_YKMAN_PATH: &str = "LURPAX_YKMAN_PATH";

/// Known `ykman` install locations searched before `PATH`.
pub const YKMAN_CANDIDATE_PATHS: &[&str] = &[
    "/usr/bin/ykman",
    "/usr/local/bin/ykman",
    "/opt/homebrew/bin/ykman",
];
