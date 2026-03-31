#!/usr/bin/env python3
"""Randomly corrupt ~1% of bytes in the shard region of a .lurpax vault file."""

import os
import random
import struct
import sys

MAGIC = b"LURPX"
HEADER_LEN_SIZE = 4

def main():
    src = sys.argv[1]
    dst = sys.argv[2]
    pct = float(sys.argv[3]) if len(sys.argv) > 3 else 1.0

    data = bytearray(open(src, "rb").read())
    file_len = len(data)

    assert data[:5] == MAGIC, "Not a lurpax file"
    header_body_len = struct.unpack_from("<I", data, 5)[0]
    shard_start = 9 + header_body_len

    tail_magic = data[-5:]
    assert tail_magic == MAGIC, "Tail magic missing"
    tail_header_len = struct.unpack_from("<I", data, file_len - 9)[0]
    tail_region_size = tail_header_len + 4 + 5  # tail header body + u32 + magic
    shard_end = file_len - tail_region_size

    shard_region_size = shard_end - shard_start
    num_corrupt = max(1, int(shard_region_size * pct / 100.0))

    positions = random.sample(range(shard_start, shard_end), num_corrupt)
    for pos in positions:
        orig = data[pos]
        flip = orig ^ random.randint(1, 255)
        data[pos] = flip

    open(dst, "wb").write(data)
    print(f"Corrupted {num_corrupt} bytes out of {shard_region_size} "
          f"shard bytes ({num_corrupt/shard_region_size*100:.2f}%)")
    print(f"Shard region: offset {shard_start} .. {shard_end}")
    print(f"File size: {file_len} bytes")

if __name__ == "__main__":
    main()
