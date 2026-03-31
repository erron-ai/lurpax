# Lurpax

Encrypted snapshot vault CLI by Erron.ai. Produces `.lurpax` files: **zstd-compressed tar**, **chunked XChaCha20-Poly1305**, **Argon2id + HKDF** key separation, **HMAC key commitment**, **Reed–Solomon** parity, **CRC-32C** shard table.

**MSRV:** Rust 1.74+

## Commands

```bash
cargo build --release
# binary: target/release/lurpax

lurpax create --output backup.lurpax --input ./myfolder
lurpax open --vault backup.lurpax --out-dir ./restored
lurpax verify --vault backup.lurpax
```

Optional YubiKey (slot 1 or 2):

```bash
lurpax create --output backup.lurpax --input ./data --yubikey-slot 2
# open reuses challenge + slot from the vault header
lurpax open --vault backup.lurpax --out-dir ./out
```

Non-interactive password:

```bash
lurpax create --output b.lurpax --input ./d --password-file ./pwd.txt
```

## Verify exit codes

| Code | Meaning |
|------|---------|
| 0 | Healthy |
| 1 | Damaged, RS-repairable |
| 2 | Unrecoverable damage |
| 3 | Structurally unreadable |

## Docs

- [SECURITY.md](SECURITY.md)
- [docs/FORMAT.md](docs/FORMAT.md)
- [docs/DESIGN.md](docs/DESIGN.md)
- [docs/AUDIT_GUIDE.md](docs/AUDIT_GUIDE.md)

## Credits

Built by [Erron.ai](https://erron.ai).

## License

MIT OR Apache-2.0
