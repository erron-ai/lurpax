# Security

## Reporting

Report suspected vulnerabilities to the maintainers of Erron.ai / this repository through a private channel. Do not file public issues for undisclosed security bugs.

## Threat model (summary)

Lurpax targets **confidentiality and integrity** of vault contents against attackers who obtain the `.lurpax` file but not the password (and optional YubiKey response). **Local malware with full memory access** is out of scope for v1.

## Argon2 policy bounds (DoS mitigation)

The header is parsed **before** key-commitment verification, so Argon2 must not accept attacker-chosen costs that allocate far beyond what legitimate lurpax builds use. On `open`, `argon2_mem_kib` must lie in **`[MIN_ARGON2_MEM_KIB, MAX_ARGON2_MEM_KIB]`** (both **262 144** KiB — 256 MiB — as implemented in `src/constants.rs`), with iterations and parallelism similarly bounded. Vaults produced by this tool always use the default memory cost; a malicious file cannot raise memory above that cap.

## Metadata visible without password

The following are stored in plaintext (header + framing) and are readable by anyone with the file:

- Argon2id parameters (memory, iterations, parallelism) — **bounded** as above
- Salt, chunk layout, RS parameters, compressed payload size
- Whether a YubiKey was used and which slot
- **v1 YubiKey vaults:** the challenge bytes appear in the header in plaintext. **v2** (new creates with `--yubikey-slot`): only an Argon2/XChaCha-wrapped ciphertext of the challenge; the raw challenge is not stored on disk (response is never stored)
- Approximate compression ratio via `compressed_payload_size`

This is inherent: the implementation must parse metadata before decryption.

## Cryptographic choices

- **Argon2id** for password stretching; **HKDF-SHA256** for `enc_key` vs `commit_key` separation.
- **XChaCha20-Poly1305** per chunk with STREAM-style AAD (chunk index + final flag).
- **HMAC-SHA256** key commitment over `base_nonce` before AEAD.
- **CRC-32C** is **not** a MAC; `verify` detects accidental corruption only, not tampering. Tampering should fail at AEAD or commitment on `open`.

## YubiKey / `ykman`

The tool invokes `ykman otp calculate <slot>` with the challenge on **stdin** as **lowercase hexadecimal** (64 nybbles + newline), matching `ykman`’s documented challenge format. The resolved `ykman` binary is validated (regular file, ownership, permissions, parent directories). Override path with `LURPAX_YKMAN_PATH` only when necessary; that bypasses the standard search list.

## Atomic writes and interrupted `create`

Vault output is written via a sibling **`.lurpax.partial`** file with **`O_EXCL`**-style creation, then renamed into place. If a previous run left a stale partial file, `create` fails with a clear error; **delete that `.lurpax.partial` manually** and retry (the implementation does not probe-and-remove the path, to avoid symlink races).

## Limitations

- No secure-delete guarantees across filesystems.
- No in-place password rotation; create a new vault to re-key.
