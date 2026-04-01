# Security

## Reporting

Report suspected vulnerabilities to the maintainers of Erron.ai / this repository through a private channel. Do not file public issues for undisclosed security bugs.

## Threat model (summary)

Lurpax targets **confidentiality and integrity** of vault contents against attackers who obtain the `.lurpax` file but not the password (and optional YubiKey response). **Local malware with full memory access** is out of scope for v1.

## Metadata visible without password

The following are stored in plaintext (header + framing) and are readable by anyone with the file:

- Argon2id parameters (memory, iterations, parallelism)
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

## Limitations

- No secure-delete guarantees across filesystems.
- No in-place password rotation; create a new vault to re-key.
