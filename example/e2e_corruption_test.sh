#!/usr/bin/env bash
# End-to-end: 100 nested files (≥10 MiB, mixed formats) → encrypt → corrupt shards → decrypt → verify.
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

echo "== populate input tree (100 files, nested dirs, ≥10 MiB each) =="
python3 - "$INDIR" <<'PY'
import os
import sys
import zlib

root = os.path.abspath(sys.argv[1])

MIN_BYTES = 10 * 1024 * 1024  # 10 MiB
N = 100

# Nested directory slots (relative paths under root).
SUBDIRS = [
    "photos/raw",
    "photos/raw/2024",
    "docs/legal",
    "docs/legal/attachments",
    "data/exports/csv",
    "data/exports/json",
    "data/bin",
    "archive/tarballs",
    "media/video/frames",
    "media/audio/wav",
    "build/obj/release",
    "build/obj/debug/deps",
    "src/vendor/pkg",
    "logs/app",
    "logs/app/rotated",
    "cache/l1",
    "cache/l2/a",
    "cache/l2/b/c",
    "tmp/scratch",
    "nested/one/two/three/four",
]

EXTS = [
    ".bin",
    ".dat",
    ".raw",
    ".txt",
    ".log",
    ".json",
    ".csv",
    ".xml",
    ".md",
    ".html",
    ".tsv",
    ".ndjson",
    ".hex",
    ".blob",
    ".img",
    ".pcm",
    ".sqlite",
    ".yaml",
    ".toml",
    ".cfg",
]


def write_binary(path: str, n: int) -> None:
    with open(path, "wb") as f:
        remaining = n
        while remaining > 0:
            chunk = min(remaining, 1 << 20)
            f.write(os.urandom(chunk))
            remaining -= chunk


def write_text(path: str, n: int, line: str) -> None:
    line_b = (line + "\n").encode()
    with open(path, "wb") as f:
        while f.tell() < n:
            need = n - f.tell()
            if need >= len(line_b):
                f.write(line_b)
            else:
                f.write(line_b[:need])
                break


def write_jsonish(path: str, n: int) -> None:
    pad = "x" * 64
    with open(path, "w", encoding="utf-8") as f:
        f.write("[")
        first = True
        while f.tell() < n:
            if not first:
                f.write(",")
            chunk = '{"i":%d,"p":"%s"}' % (f.tell(), pad)
            f.write(chunk)
            first = False
        f.write("]")


def write_csv_rows(path: str, n: int) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write("id,value,note\n")
        i = 0
        while f.tell() < n:
            f.write("%d,%d,row-data-padding-abcdef\n" % (i, i * 7))
            i += 1


def write_hex_lines(path: str, n: int) -> None:
    with open(path, "w", encoding="utf-8") as f:
        while f.tell() < n:
            b = os.urandom(16)
            f.write(b.hex() + "\n")


def write_zlib_blob(path: str, n: int) -> None:
    raw = os.urandom(min(n + 1000, 2 * 1024 * 1024))
    compressed = zlib.compress(raw, level=6)
    with open(path, "wb") as f:
        f.write(compressed)
    # pad to at least n by appending
    with open(path, "ab") as f:
        pad = n - f.tell()
        if pad > 0:
            f.write(b"\x00" * pad)


def write_sparse(path: str, n: int) -> None:
    with open(path, "wb") as f:
        f.seek(n - 1)
        f.write(b"\n")


writers = [
    lambda p, n: write_binary(p, n),
    lambda p, n: write_text(p, n, "lorem ipsum dolor sit amet " * 10),
    lambda p, n: write_jsonish(p, n),
    lambda p, n: write_csv_rows(p, n),
    lambda p, n: write_hex_lines(p, n),
    lambda p, n: write_zlib_blob(p, n),
    lambda p, n: write_sparse(p, n),
    lambda p, n: write_text(p, n, "# " + "y" * 120),
]

paths_written = []
for i in range(1, N + 1):
    sub = SUBDIRS[(i - 1) % len(SUBDIRS)]
    ext = EXTS[(i - 1) % len(EXTS)]
    d = os.path.join(root, sub)
    os.makedirs(d, exist_ok=True)
    fname = "asset_%03d%s" % (i, ext)
    rel = os.path.join(sub, fname)
    full = os.path.join(root, sub, fname)
    size = MIN_BYTES + (i * 9973) % (512 * 1024)  # 10 MiB … ~10.5 MiB
    w = writers[(i - 1) % len(writers)]
    w(full, size)
    paths_written.append(rel)

manifest = os.path.join(root, "MANIFEST_E2E.txt")
with open(manifest, "w", encoding="utf-8") as f:
    for p in sorted(paths_written):
        f.write(p + "\n")

print("wrote %d data files + manifest under %s" % (N, root))
PY

echo "== create vault (100 files, nested) =="
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

echo "== verify tree and byte identity =="
INPUT_COUNT=$(find "$INDIR" -type f ! -name 'MANIFEST_E2E.txt' | wc -l | tr -d ' ')
if [ "$INPUT_COUNT" -ne 100 ]; then
  echo "FAILED: expected 100 data files, got $INPUT_COUNT" >&2
  exit 1
fi

diff -rq "$INDIR" "${OUTDIR}/extracted" || {
  echo "FAILED: extracted tree differs from input" >&2
  exit 1
}

while IFS= read -r rel; do
  [ -z "$rel" ] && continue
  cmp -s "${INDIR}/${rel}" "${OUTDIR}/extracted/${rel}" || {
    echo "FAILED: mismatch ${rel}" >&2
    exit 1
  }
done < <(python3 - "$INDIR" <<'PY'
import os
import sys

root = sys.argv[1]
for dirpath, _, files in os.walk(root):
    for name in sorted(files):
        if name == "MANIFEST_E2E.txt":
            continue
        full = os.path.join(dirpath, name)
        print(os.path.relpath(full, root))
PY
)

echo "OK: e2e create → corrupt → open → 100 nested files verified"
