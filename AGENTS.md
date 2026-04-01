# Agent orientation

This file is a **map of the repo** for AI assistants and contributors. For product overview, installation, and usage, see [`README.md`](README.md).

## Root

| Item | Role |
|------|------|
| [`Cargo.toml`](Cargo.toml) / [`Cargo.lock`](Cargo.lock) | Crate manifest and lockfile; binary `lurpax` → `src/main.rs`. |
| [`clippy.toml`](clippy.toml) | Clippy settings. |
| [`install.sh`](install.sh) | Shell installer for releases. |
| [`SECURITY.md`](SECURITY.md) | Security policy and threat-model notes referenced from code. |

## Source (`src/`)

| Path | Contents |
|------|----------|
| [`main.rs`](src/main.rs) | Binary entry: signals, core-dump hardening, CLI dispatch. |
| [`lib.rs`](src/lib.rs) | Library surface: re-exports and module tree. |
| [`cli.rs`](src/cli.rs) | Clap CLI definition and command routing. |
| [`constants.rs`](src/constants.rs) | Shared constants. |
| [`archive/`](src/archive/) | Tar snapshot packing/unpacking (`tar.rs`). |
| [`crypto/`](src/crypto/) | KDF, stream/chunk encryption, Yubi challenge wrapping (`kdf.rs`, `encryption.rs`, `stream.rs`, `yubi_challenge_wrap.rs`). |
| [`vault/`](src/vault/) | Vault container, header, high-level service (`container.rs`, `header.rs`, `service.rs`). |
| [`recovery/`](src/recovery/) | Reed–Solomon and checksum layers (`fec.rs`, `checksum.rs`). |
| [`hardware/`](src/hardware/) | YubiKey integration (`yubikey.rs`). |
| [`errors/`](src/errors/) | Error types (`LurpaxError`, `Result`). |

## Tests

| Location | Role |
|----------|------|
| [`tests/`](tests/) | Integration tests (one file per concern: `e2e_vault`, `corruption_recovery`, `cli_verify`, `kdf_vectors`, `vault_roundtrip`, etc.). |

Run: `cargo test` (and integration tests as needed).

## Fuzzing

| Location | Role |
|----------|------|
| [`fuzz/`](fuzz/) | Separate `cargo-fuzz` workspace; targets in [`fuzz/fuzz_targets/`](fuzz/fuzz_targets/) (`fuzz_header`, `fuzz_payload`). |

## Docs and assets (not the README)

| Path | Role |
|------|------|
| [`docs/DESIGN.md`](docs/DESIGN.md) | Design notes. |
| [`docs/FORMAT.md`](docs/FORMAT.md) | On-disk format. |
| [`docs/AUDIT_GUIDE.md`](docs/AUDIT_GUIDE.md) | Audit-oriented guidance. |
| [`docs/`](docs/) | Demo GIFs and other assets (e.g. `yubikey-demo/`). |

## Examples and scripts

| Path | Role |
|------|------|
| [`example/e2e_corruption_test.sh`](example/e2e_corruption_test.sh) | End-to-end shell example around corruption scenarios. |
| [`scripts/`](scripts/) | Release helpers: Homebrew tap push, SHA256 printing, coverage, formula updates. |

## CI and automation

| Path | Role |
|------|------|
| [`.github/workflows/ci.yml`](.github/workflows/ci.yml) | Main CI. |
| [`.github/workflows/release.yml`](.github/workflows/release.yml) | Release builds. |
| [`.github/workflows/homebrew-tap.yml`](.github/workflows/homebrew-tap.yml) / [`tag-release-on-main.yml`](.github/workflows/tag-release-on-main.yml) | Tap and tagging. |
| [`.github/dependabot.yml`](.github/dependabot.yml) | Dependency updates. |

## Build output

`target/` is Cargo output (ignored in git). Do not treat it as source.
