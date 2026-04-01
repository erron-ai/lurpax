# Auditor guide

## Module map (with line counts)

Line counts are `wc -l` on source as of the last doc refresh; use `wc -l src/**/*.rs tests/*.rs` to re-verify.

| Path | Lines | Notes |
|------|------:|-------|
| `src/vault/service.rs` | 589 | Create / open / verify orchestration |
| `src/vault/header.rs` | 414 | Hand-rolled LE header; schema validation |
| `src/archive/tar.rs` | 300 | Pack input; bounded extract |
| `src/cli.rs` | 294 | Argument surface, limits, YubiKey wiring |
| `src/vault/container.rs` | 237 | On-disk layout, atomic write, payload read |
| `src/crypto/stream.rs` | 155 | Per-chunk nonce, AAD, XChaCha20-Poly1305 |
| `src/hardware/yubikey.rs` | 239 | `ykman` resolution and validation |
| `src/constants.rs` | 106 | Centralized numeric policy |
| `src/errors/mod.rs` | 105 | Typed errors, verify health |
| `src/crypto/kdf.rs` | 96 | Argon2id, HKDF, IKM composition |
| `src/recovery/fec.rs` | 60 | Reed–Solomon repair |
| `src/recovery/checksum.rs` | 57 | CRC-32C table (non-crypto) |
| `src/main.rs` | 64 | Entry, hardening hooks |
| `src/crypto/encryption.rs` | 33 | HMAC key commitment |
| `tests/header_serialization.rs` | 151 | Header round-trip |
| `tests/vault_roundtrip.rs` | 78 | End-to-end vault |
| `tests/rs_group.rs` | 15 | RS grouping |
| `src/lib.rs` | 29 | Crate root, re-exports |
| `src/crypto/mod.rs` | 9 | Crypto submodule facade |
| `src/vault/mod.rs` | 9 | Vault submodule facade |
| `src/archive/mod.rs` | 5 | Archive facade |
| `src/hardware/mod.rs` | 5 | Hardware facade |
| `src/recovery/mod.rs` | 7 | Recovery facade |

## Critical code paths by risk (1–10)

Higher score = more security impact if wrong. Use this to prioritize depth-first review.

| Score | Area | Primary files | Why it matters |
|------:|------|----------------|----------------|
| 10 | Header parse + allocation bounds | `vault/header.rs`, `vault/container.rs` | Malformed input must not panic, over-allocate, or accept downgraded KDF params |
| 10 | Open ordering and decrypt loop | `vault/service.rs` | RS before KDF/AEAD; commitment before decrypt; CRC false-negative fallback must not weaken auth |
| 10 | STREAM chunk AEAD | `crypto/stream.rs` | Nonce uniqueness, AAD binding, final chunk flag — tamper/reorder/truncate resistance |
| 9 | KDF + IKM | `crypto/kdf.rs` | Password/YubiKey mixing; Argon2 params; HKDF domain separation |
| 9 | Key commitment | `crypto/encryption.rs` | Wrong-key decrypt must fail; comparison must be constant-time |
| 9 | Tar extract safety | `archive/tar.rs` | Path traversal, symlinks, file types, size limits |
| 8 | On-disk layout + atomicity | `vault/container.rs` | Shard ordering, tail header, temp permissions, rename atomicity |
| 8 | External `ykman` trust | `hardware/yubikey.rs` | Binary resolution, symlink avoidance, stderr handling |
| 7 | RS repair correctness | `recovery/fec.rs` | Group boundaries vs `service` / `container` layout |
| 6 | CRC precheck semantics | `recovery/checksum.rs`, `service.rs` | Accidental-only corruption; interaction when table missing |
| 5 | CLI policy | `cli.rs` | Limits and flags must match documented threat model |
| 4 | Process hardening | `main.rs` | Core dumps, `PR_SET_DUMPABLE` where applicable |

## `// AUDIT:` markers

Every security-sensitive decision should be tagged. **Auditors:** locate all markers with:

```bash
rg '// AUDIT:' src/
```

Current index (file:line — re-run `rg` before a formal audit):

- `src/main.rs`: 24, 39
- `src/archive/tar.rs`: 172, 212, 244, 252, 293
- `src/crypto/encryption.rs`: 12, 29
- `src/crypto/kdf.rs`: 19, 52, 85
- `src/crypto/stream.rs`: 13, 32, 55
- `src/hardware/yubikey.rs`: 30, 77
- `src/recovery/checksum.rs`: 9
- `src/vault/container.rs`: 158, 184, 201
- `src/vault/header.rs`: 200, 243, 409
- `src/vault/service.rs`: 86, 313, 358, 364, 392, 401, 418, 459

## Running the test suite

From the repository root:

```bash
cargo test --workspace
```

Runs unit tests and integration tests under `tests/`. Use `cargo test --workspace -- --nocapture` for verbose failures.

## Verifying coverage

Install [`cargo-llvm-cov`](https://github.com/taiki-e/cargo-llvm-cov) (e.g. `cargo install cargo-llvm-cov`), ensure the `llvm-tools-preview` component is installed for your toolchain, then:

```bash
./scripts/coverage.sh
```

The script runs `cargo llvm-cov` with **98%** thresholds on lines, functions, and regions (stricter than CI while the suite grows). CI currently uses **70%** line/function gates so the pipeline stays green until coverage approaches the audit target; raise CI thresholds toward 98% as tests land.

## Known areas of elevated complexity

- **`VaultService::open`:** Combines CRC bitmap, RS repair, KDF, commitment, per-chunk decrypt, and a second RS pass on AEAD failure — easy to get ordering or index math wrong; cross-check with `docs/DESIGN.md` data flow.
- **`header.rs` deserialization:** Hand-rolled little-endian parsing with explicit consumption length; any mismatch with `docs/FORMAT.md` is a format-breaking bug.
- **`extract_tar`:** Interaction of canonical paths, temp directory, `OpenOptions`, and entry type allowlists — review alongside platform notes in `docs/DESIGN.md`.
- **RS grouping:** Invariants must match among `constants.rs`, `fec.rs`, `container::layout_shards_with_rs`, and `service::repair_all_groups` / `collect_data_shards`.

## High-risk modules (summary)

1. `src/vault/header.rs` — wire parser; must reject malformed/trailing data.
2. `src/crypto/stream.rs` — nonce + AAD binding for chunked AEAD.
3. `src/crypto/kdf.rs` — Argon2id + HKDF composition; password/YubiKey length-prefix IKM.
4. `src/crypto/encryption.rs` — key commitment compare (constant-time XOR chain).
5. `src/vault/service.rs` — ordering: RS before KDF/AEAD; commitment before decrypt.
6. `src/archive/tar.rs` — path and size limits on extract.
7. `src/hardware/yubikey.rs` — `ykman` resolution and sandboxing assumptions.

## Suggested review order

1. Read `docs/FORMAT.md` and cross-check `header.rs` + `container.rs`.
2. Trace `VaultService::create` and `VaultService::open` end-to-end.
3. Verify RS grouping matches `fec.rs` and `container::layout_shards_with_rs`.
4. Exercise `tests/*.rs` and extend with tamper/corruption cases.

## Coverage (CI)

CI runs eight parallel gates on **macOS** (`macos-latest`): `fmt`, `clippy`, `test`, `doc`, `deny`, `audit`, `msrv` (Rust 1.74 `cargo check`), and `coverage` (`cargo-llvm-cov` at 70% line/function minimum until the suite matures). Local `scripts/coverage.sh` enforces stricter thresholds for pre-release audit prep.

## Release tooling

- **`scripts/push_homebrew_tap.sh`** — Updates the Homebrew tap after a release. It clones the tap over HTTPS with **`GIT_ASKPASS`** (credentials from **`TAP_PUSH_TOKEN`** or **`HOMEBREW_TAP_TOKEN`**) so a PAT is not embedded in the `git clone` URL. Release asset checksums are fetched with **`/usr/bin/curl`** by default (`CURL` override allowed).
