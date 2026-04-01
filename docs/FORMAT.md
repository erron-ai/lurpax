# Lurpax `.lurpax` binary format (v1 / v2 header)

Multi-byte integers are **little-endian**. Magic: ASCII `LURPX` (5 bytes).

## Layout

| Offset | Field | Size |
|--------|--------|------|
| 0 | Magic | 5 |
| 5 | Header body length | `u32` |
| 9 | Header body | `header_len` |
| 9+H | Shards (see below) | variable |
| … | CRC-32C table | `4 × total_shards` |
| … | Tail header body (copy of primary) | `H` |
| EOF−9 | Tail header length | `u32` |
| EOF−5 | Tail magic | 5 (`LURPX`) |

## Header body

Serialized sequentially, no padding. Fields **1–15** are shared; the tail depends on `version`.

1. `version: u16` — `1` (v1) or `2` (v2 YubiKey layout)
2. `kdf_algorithm: u8` — `1` = Argon2id
3. `argon2_mem_kib: u32`
4. `argon2_iterations: u32`
5. `argon2_parallelism: u32`
6. `salt: [u8; 32]`
7. `base_nonce: [u8; 24]`
8. `key_commitment: [u8; 32]`
9. `chunk_plaintext_size: u32` — fixed `65536`
10. `chunk_count: u64`
11. `compressed_payload_size: u64`
12. `rs_data_shards_per_group: u16` — fixed `19`
13. `rs_parity_shards_per_group: u16` — fixed `3`
14. `yubi_required: u8` — `0` or `1`
15. `yubi_slot: u8` — `0`, `1`, or `2`

### Policy bounds (validated on `open`)

Implementations **must** reject headers outside these ranges (see `src/constants.rs`):

| Field | Allowed values |
|--------|----------------|
| `argon2_mem_kib` | **262 144** KiB only (256 MiB; min and max coincide) |
| `argon2_iterations` | **3–10** |
| `argon2_parallelism` | **1–16** |

### Tail (version-specific)

- **`version == 1`:** `yubi_challenge: [u8; 32]` — plaintext challenge when `yubi_required`; otherwise zero. Header body length **161** bytes.
- **`version == 2`:** YubiKey vaults only. `yubi_wrap_salt: [u8; 32]`, `yubi_chal_nonce: [u8; 24]`, `yubi_chal_ciphertext: [u8; 48]` (XChaCha20-Poly1305 of the 32-byte challenge; key from password-only Argon2id with `yubi_wrap_salt`). Plaintext challenge is **not** stored. Header body length **233** bytes.

## Shards

- `shard_size = chunk_plaintext_size + 16` (ciphertext + Poly1305 tag).
- Data shards are grouped: **19 data + 3 parity** per group (last group may have fewer data shards).
- On-disk order per group: data shards `0..k`, then parity shards `0..3`.
- Global order: group 0, then group 1, …

## CRC table

For each shard in global on-disk order, `u32` **CRC-32C** (little-endian) of the raw shard bytes. Not cryptographically authenticated.

## Derived values

- `total_shards = chunk_count + ceil(chunk_count / 19) × 3`
- Expected file size = `9 + header_len + total_shards × shard_size + 4 × total_shards + header_len + 4 + 5`
