#!/usr/bin/env bash
# End-to-end: 20 large files → encrypt → corrupt shard bytes → decrypt → verify.
# Run from repo root: ./example/e2e_corruption_test.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export CARGO_TARGET_DIR="${ROOT}/target"

cargo build --release -q
BIN="${ROOT}/target/release/lurpax"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

INDIR="${TMP}/input"
OUTDIR="${TMP}/extracted"
VAULT="${TMP}/test.e2e.lurpax"
PWFILE="${TMP}/pw"

mkdir -p "$INDIR"
printf '%s' 'e2e-corruption-test-password' > "$PWFILE"

for i in $(seq -f '%02g' 1 20); do
  dd if=/dev/urandom of="${INDIR}/large_${i}.bin" bs=1024 count=256 status=none
done

echo "== create vault (20 × 256 KiB files) =="
"${BIN}" create --output "${VAULT}" --input "${INDIR}" --password-file "${PWFILE}"

echo "== corrupt a few regions inside ciphertext shards (not header) =="
python3 - "${VAULT}" <<'PY'
import struct
import sys

path = sys.argv[1]
shard_sz = 65536 + 16

with open(path, "r+b") as f:
    data = f.read()
    hl = struct.unpack_from("<I", data, 5)[0]
    shard0 = 9 + hl

    def xor_span(off: int, length: int, mask: int) -> None:
        f.seek(off)
        buf = bytearray(f.read(length))
        for i in range(len(buf)):
            buf[i] ^= mask
        f.seek(off)
        f.write(buf)

    xor_span(shard0 + 200, 120, 0x5A)
    xor_span(shard0 + 40000, 64, 0x3C)
    xor_span(shard0 + 2 * shard_sz + 8192, 200, 0xA7)

print("corruption done")
PY

echo "== open / decrypt =="
mkdir -p "${OUTDIR}"
"${BIN}" open --vault "${VAULT}" --out-dir "${OUTDIR}" --password-file "${PWFILE}"

echo "== verify all 20 files byte-identical =="
diff -rq "${INDIR}" "${OUTDIR}/extracted" || {
  echo "FAILED: extracted tree differs from input" >&2
  exit 1
}

for i in $(seq -f '%02g' 1 20); do
  cmp -s "${INDIR}/large_${i}.bin" "${OUTDIR}/extracted/large_${i}.bin" || {
    echo "FAILED: large_${i}.bin mismatch" >&2
    exit 1
  }
done

echo "OK: e2e create → corrupt → open → 20 files verified"
