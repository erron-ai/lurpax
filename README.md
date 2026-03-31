# Lurpax

Encrypted snapshot vault CLI. Turn any file or folder into a single, password-protected `.lurpax` file that is compressed, encrypted, and protected against data corruption.

Built by [Erron.ai](https://erron.ai).

## Features

- **Strong encryption** — XChaCha20-Poly1305 authenticated encryption per chunk, with HMAC key commitment to catch wrong passwords instantly.
- **Password hardening** — Argon2id stretches your password; HKDF-SHA256 derives separate encryption and commitment keys.
- **Corruption recovery** — Reed–Solomon parity shards let you recover data even if parts of the file are damaged.
- **Compression** — Zstd compression before encryption keeps vault files small.
- **Integrity checking** — `verify` command checks vault health without needing your password.
- **YubiKey support** — Optional second factor via HMAC-SHA1 challenge-response (slot 1 or 2).
- **Atomic writes** — Vault files are written via temp file + rename, so a crash can't leave a half-written file.

## Installation

### Homebrew (macOS / Linux)

```bash
brew install erronai/tap/lurpax
```

### Shell installer

```bash
curl -sSf https://raw.githubusercontent.com/erronai/lurpax/main/install.sh | bash
```

Or install a specific version:

```bash
curl -sSf https://raw.githubusercontent.com/erronai/lurpax/main/install.sh | bash -s v0.1.0
```

Set `LURPAX_INSTALL_DIR` to change the install location (default: `/usr/local/bin`).

### Pre-built binaries

Download the latest release for your platform from [GitHub Releases](https://github.com/erronai/lurpax/releases), extract, and move `lurpax` to somewhere on your `PATH`:

```bash
tar xzf lurpax-v0.1.0-aarch64-apple-darwin.tar.gz
cp lurpax-v0.1.0-aarch64-apple-darwin/lurpax /usr/local/bin/
```

Available targets: `x86_64-apple-darwin`, `aarch64-apple-darwin`, `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`.

### Cargo (from source)

Requires **Rust 1.85+**.

```bash
cargo install lurpax
```

Or build from a local checkout:

```bash
cargo build --release
cp target/release/lurpax /usr/local/bin/
```

## Quick Start

### Create a vault

```bash
lurpax create --output backup.lurpax --input ./my-folder
```

You will be prompted to enter and confirm a password.

### Restore from a vault

```bash
lurpax open --vault backup.lurpax --out-dir ./restored
```

If any data shards were damaged and repaired via Reed–Solomon, the vault file is automatically rewritten in place after successful extraction.

### Check vault health (no password needed)

```bash
lurpax verify --vault backup.lurpax
```

## Usage

### `create`

```bash
lurpax create --output <path> --input <file-or-dir> [options]
```

| Option | Description |
|---|---|
| `--output` | Path for the new `.lurpax` file (must not already exist) |
| `--input` | File or directory to archive |
| `--password-file <path>` | Read password from a file instead of the terminal |
| `--yubikey-slot <1\|2>` | Enable YubiKey second factor on the given slot |
| `--max-input-size <bytes>` | Limit total input size |
| `--max-files <count>` | Limit number of input files |
| `--max-file-size <bytes>` | Limit size of any single input file |

### `open`

```bash
lurpax open --vault <path> --out-dir <dir> [options]
```

| Option | Description |
|---|---|
| `--vault` | Path to the `.lurpax` file |
| `--out-dir` | Directory to extract contents into |
| `--password-file <path>` | Read password from a file instead of the terminal |
| `--max-size <bytes>` | Limit total extracted size |
| `--max-files <count>` | Limit number of extracted files |
| `--max-file-size <bytes>` | Limit size of any single extracted file |

If the vault was created with a YubiKey, have the same key inserted — the slot and challenge are stored in the vault header, so no extra flags are needed.

### `verify`

```bash
lurpax verify --vault <path>
```

Returns an exit code indicating vault health:

| Exit code | Meaning |
|---|---|
| 0 | Healthy — no corruption detected |
| 1 | Damaged but repairable via Reed–Solomon |
| 2 | Unrecoverable damage (exceeds RS parity capacity) |
| 3 | Structurally unreadable |

## Non-Interactive Password

For scripts and automation, pass the password via a file:

```bash
lurpax create --output backup.lurpax --input ./data --password-file ./pwd.txt
lurpax open --vault backup.lurpax --out-dir ./out --password-file ./pwd.txt
```

The file must contain a single line with the password. Symlinks are rejected.

## YubiKey Setup

Lurpax supports YubiKey as a second factor via HMAC-SHA1 challenge-response. The YubiKey response is mixed into key derivation alongside your password.

**1. Install YubiKey Manager CLI:**

```bash
brew install ykman              # macOS
sudo apt install yubikey-manager  # Debian / Ubuntu
```

**2. Program a slot for challenge-response:**

```bash
ykman otp chalresp --touch --generate 2
```

Use slot 2 unless slot 1 is free (slot 1 is often used by Yubico OTP).

**3. Create a vault with YubiKey:**

```bash
lurpax create --output vault.lurpax --input ./data --yubikey-slot 2
```

Touch the key when it blinks.

**4. Open — just have the same YubiKey inserted:**

```bash
lurpax open --vault vault.lurpax --out-dir ./restored
```

`ykman` is found at `/usr/bin/ykman`, `/usr/local/bin/ykman`, or `/opt/homebrew/bin/ykman`. Override with the `LURPAX_YKMAN_PATH` environment variable.

## How It Works

```
Input files → tar → zstd compress → chunk → XChaCha20-Poly1305 encrypt → Reed–Solomon parity → .lurpax
```

1. Files are packed into a tar archive.
2. The tar stream is compressed with Zstd.
3. The compressed data is split into 64 KiB chunks, each independently encrypted.
4. Reed–Solomon parity shards are added (19 data + 3 parity per group).
5. CRC-32C checksums are appended for quick corruption detection.
6. Everything is written atomically to a single `.lurpax` file.

Decryption reverses the process, repairing any damaged shards along the way.

## Security Overview

- Argon2id (RFC 9106) for password stretching.
- HKDF-SHA256 (RFC 5869) for key separation (`enc_key` / `commit_key`).
- XChaCha20-Poly1305 (RFC 8439 family) for per-chunk authenticated encryption.
- HMAC-SHA256 key commitment — wrong passwords are rejected before any decryption.
- STREAM-style AAD binding prevents chunk reordering, truncation, or duplication.
- Sensitive memory is zeroized after use; `mlock` and core-dump prevention where supported.

See [SECURITY.md](SECURITY.md) for the full threat model and limitations.

## Documentation

| Document | Description |
|---|---|
| [SECURITY.md](SECURITY.md) | Threat model, cryptographic choices, and limitations |
| [docs/FORMAT.md](docs/FORMAT.md) | Binary format specification |
| [docs/DESIGN.md](docs/DESIGN.md) | Architecture, module graph, and data flow |
| [docs/AUDIT_GUIDE.md](docs/AUDIT_GUIDE.md) | Guide for security auditors |

## License

MIT — see [LICENSE](LICENSE) for the full text.
