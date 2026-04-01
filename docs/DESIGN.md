# Lurpax design notes

## Module dependency graph (text)

Edges read as “caller → callee” (crate-internal modules only).

```text
main
  → cli, vault::VaultService, errors, signal / hardening hooks

cli
  → vault::VaultService, archive::ArchiveLimits, hardware::YubiKeyPort, errors

vault::service (orchestration)
  → archive (tar_input, extract_tar)
  → crypto (kdf, stream, encryption: derive, encrypt/decrypt, commitment)
  → vault::header, vault::container (layout, read/write, atomic)
  → recovery::fec, recovery::checksum (RS repair, CRC table)
  → hardware::YubiKeyPort (optional)
  → constants, errors

vault::container
  → vault::header, constants, errors

vault::header
  → constants, errors

crypto::stream
  → vault::header (AAD / nonces), constants, errors; uses XChaCha20-Poly1305 via `chacha20poly1305`

crypto::encryption
  → errors (HMAC-SHA256 key commitment; called from `vault::service` alongside stream)

crypto::kdf
  → constants, errors

archive::tar
  → constants, errors

recovery::fec / recovery::checksum
  → constants, errors

hardware::yubikey
  → errors
```

`lib.rs` re-exports `errors` and wires public modules; there is no cyclic dependency between `vault` and `crypto`.

## Trust boundaries

| Boundary | Inside (trusted for purpose) | Outside / untrusted |
|----------|------------------------------|---------------------|
| Password / YubiKey response | User input and optional `ykman` stdout | Hostile process reading TTY, spoofing `ykman` |
| Vault file on disk | Bytes we parse after length checks | Attacker-controlled file; must not cause UB; Argon2 costs bounded in `header::validate_schema` before KDF work |
| Header (plaintext) | Parsed fields drive limits before big allocations | Visible metadata (see `SECURITY.md`) |
| Decrypted payload | Only after commitment + AEAD success | Ciphertext, CRC table, RS shards before verify |
| Extract tree | Output under user-chosen `--out-dir` | Symlinks / paths inside tar; constrained by archive policy |
| Network | None in core vault path | Future features would add a new boundary |

The tool assumes a non-malicious local OS for `mlock`, core-dump limits, and `ykman` execution; malware with full memory access remains out of scope for v1.

## Cryptographic choices (with citations)

| Mechanism | Role in Lurpax | Normative reference |
|-----------|----------------|---------------------|
| **Argon2id** | Password-based key stretching to a 64-byte master secret | [RFC 9106](https://www.rfc-editor.org/rfc/rfc9106) (Argon2 memory-hard function) |
| **HKDF-SHA256** | Derive separate `enc_key` and `commit_key` from the master output (domain-separated `info` strings) | [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869) |
| **HMAC-SHA256** | Key commitment over `base_nonce` using `commit_key` | RFC 5869 (HKDF); HMAC-SHA256 as in FIPS/NIST and `hmac` crate usage |
| **STREAM-style chunked AEAD** | Independent chunk tags with nonce/AAD binding so chunks cannot be reordered, truncated, or duplicated across the stream | Hoang, Reyhanitabar, Rogaway, Vizár, *A Concrete Security Treatment of Symmetric Encryption*, **2015** (STREAM construction); implementation follows the same binding discipline per chunk |
| **XChaCha20-Poly1305** | Per-chunk authenticated encryption | [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439) defines ChaCha20-Poly1305; **XChaCha20-Poly1305** uses the extended 192-bit nonce variant (subkey derivation from nonce prefix + ChaCha20 as in the XChaCha construction, commonly specified alongside RFC 8439 family) — see also Bernstein’s eSTREAM design goals for longer nonces |

## Platform matrix: extraction safety

| Platform | Target / ideal | Current implementation |
|----------|----------------|------------------------|
| **Linux** | `openat2` with `RESOLVE_BENEATH` / `RESOLVE_NO_SYMLINKS` (or equivalent) so every create opens relative to a pinned directory fd and refuses escapes | Planned for parity with strict TOCTOU-resistant extraction; not yet the primary path in tree |
| **Linux / POSIX fallback** | `openat` + `O_NOFOLLOW` / `O_CREAT \| O_EXCL` semantics where available | Conservative path: canonical base dir, relative path normalization, extraction under a dedicated temp subdirectory, `create_new` where applicable |
| **macOS** | No `openat2`; rely on `O_NOFOLLOW`, `fstatat`-style checks, and same high-level path policy as fallback | **macOS uses the same fallback-style policy as non-openat2 Linux** — symlink and traversal checks + temp extract root |

The matrix is about **path confinement and symlink/TOCTOU policy**, not about crypto (which is OS-agnostic).

## Streaming memory strategy

- **Reed–Solomon repair:** `repair_all_groups` walks the vault **one RS group at a time** (data + parity shards for that group). Only the current group’s shard buffers are repaired and written back before advancing. This avoids holding repair state for the entire file at once beyond the flat shard vector already loaded from disk.
- **Shard container:** `container::read_payload` builds a vector of per-shard `Vec<u8>` sized from header-derived counts (bounded by format limits). Peak memory scales with **total ciphertext size**, not a second full copy for RS beyond the repair temporaries.
- **Decrypt path:** Chunks are decrypted sequentially into a growing plaintext buffer for the **full zstd-compressed stream**, then `zstd::decode_all` and tar extraction run on that buffer. So the dominant peak is **compressed payload + decompressed tar** subject to `ArchiveLimits`, not “whole disk image times N.”
- **Create path:** Input is tar’d, compressed, then encrypted into shards; layout adds parity and writes atomically — memory is bounded by the same logical limits on input/compressed size, not by loading multiple vault-sized images.

When tests and optional streaming refactors land, the RS group iteration remains the primary lever for **not** loading redundant parity math state for all groups simultaneously.

## Data flow

### Create (detailed)

1. **CLI / `VaultService::create`** — Validate output path does not exist; apply interrupt flag checks. Stale **`*.lurpax.partial`** siblings are **not** removed preemptively: `container::write_atomic` opens the temp path with **`create_new`**, so an interrupted run leaves a file that must be deleted manually (avoids check/remove races).
2. **`archive::tar_input`** — Walk file or directory with `ArchiveLimits` (max files, bytes, per-file size); build deterministic tar in memory.
3. **`zstd_compress`** — Whole-stream compression (level 3) before any encryption.
4. **Header seeding** — Random salt, `base_nonce`, optional YubiKey challenge/response via `YubiKeyPort`; fill Argon2 parameters and RS layout constants.
5. **`compose_ikm` + `argon2_derive_master` + `derive_subkeys`** — Argon2id → 64 B master (then zeroized) → HKDF → `enc_key` / `commit_key`; `commit_key` used for `commitment_hmac` over `base_nonce`, then zeroized.
6. **`header.to_bytes` + `encrypt_all_chunks`** — Per-chunk STREAM AEAD over compressed bytes with per-chunk AAD and nonce derivation (`crypto::stream`).
7. **`layout_shards_with_rs`** — Interleave parity shards per group for on-disk layout.
8. **`recovery::checksum::build_checksum_table`** — CRC-32C per shard (accidental damage hint only).
9. **`container::write_atomic`** — Temp file (`*.lurpax.partial`) created exclusively (**`create_new`**, mode **0600** on Unix), full payload + fsync, then **`rename`** to the final path.

### Open (detailed)

1. **`File::open` + `container::read_header_any`** — Prefer primary header; fall back to tail copy if needed.
2. **`container::read_payload`** — Map file regions to shard `Vec`s and CRC table; record whether CRC table is usable.
3. **CRC precheck** — If table valid and sized correctly, `damaged_from_table` marks inconsistent shards; else treat all as undamaged and rely on AEAD (`// AUDIT` in `service.rs`).
4. **`repair_all_groups`** — RS repair per group using marked damage; count repaired bytes.
5. **`derive_keys_from_password`** — Same KDF path as create; `mlock` on sensitive buffers where supported.
6. **`verify_commitment`** — Constant-time check before any chunk decrypt (wrong password fails fast without decrypting).
7. **Per-chunk `decrypt_single_chunk`** — On `DecryptAuthFailed`, optional second pass: mark shard damaged, RS-repair that group only, retry (CRC false-negative path).
8. **Length check** — Reassembled plaintext length vs `compressed_payload_size`.
9. **`zstd_decompress` + `extract_tar`** — Decompress to tar stream; extract with path/symlink policy under `out_dir`.

### Verify (detailed)

1. **Dual header read** — Primary and tail; compare for consistency when both good.
2. **`expected_file_len` vs actual file size** — Reject truncated/padded files.
3. **`read_header_any` + `read_payload` again** — Structural parse must succeed.
4. **CRC table mandatory** — Unlike `open`, verify requires a valid CRC table length and content to classify health.
5. **`damaged_from_table`** — Shard-level damage bitmap without password.
6. **Per-group RS capacity** — If damaged shards in a group exceed parity count → `Unrecoverable`; else if any damage → `Repairable`; else `Healthy`.

## STREAM / AAD

Per-chunk AAD = `MAGIC || header_len || header_body || chunk_index || is_final`.

Per-chunk nonce: first 16 bytes of `base_nonce` unchanged; last 8 bytes XORed (as `u64` LE) with `chunk_index`.

## Platform notes (runtime hardening)

- **Extraction:** Canonical base dir + relative path checks + temp subdirectory; see **Platform matrix** above for `openat2` vs `O_NOFOLLOW` / macOS fallback.
- **Hardening:** On Unix, `RLIMIT_CORE` is set to 0; on Linux, `PR_SET_DUMPABLE` is cleared. Cooperative shutdown uses `signal-hook` flags (no heavy work in the handler).

## References

- **Argon2:** RFC 9106.
- **HKDF:** RFC 5869.
- **STREAM-style chunking:** Hoang, Reyhanitabar, Rogaway, Vizár (2015).
- **ChaCha20-Poly1305:** RFC 8439; XChaCha20-Poly1305 extended-nonce variant used by the `chacha20poly1305` crate.
