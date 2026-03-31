#!/usr/bin/env python3
"""Corrupt random shards in a .lurpax vault, staying within RS repair capacity.

RS layout: 19 data + 3 parity per group. We can damage up to 3 shards per group.
This script corrupts `max_per_group` random shards per RS group by flipping
several random bytes within each chosen shard.
"""

import os
import random
import struct
import sys

MAGIC = b"LURPX"
SHARD_SIZE = 65536 + 16  # chunk_plaintext_size + poly1305 tag
DATA_PER_GROUP = 19
PARITY_PER_GROUP = 3
SHARDS_PER_GROUP = DATA_PER_GROUP + PARITY_PER_GROUP


def main():
    src = sys.argv[1]
    dst = sys.argv[2]
    max_per_group = int(sys.argv[3]) if len(sys.argv) > 3 else 2

    data = bytearray(open(src, "rb").read())
    file_len = len(data)

    header_body_len = struct.unpack_from("<I", data, 5)[0]
    shard_start = 9 + header_body_len

    tail_header_len = struct.unpack_from("<I", data, file_len - 9)[0]
    tail_region_size = tail_header_len + 4 + 5
    shard_end = file_len - tail_region_size

    shard_region_size = shard_end - shard_start
    total_shards = shard_region_size // SHARD_SIZE
    num_groups = (total_shards + SHARDS_PER_GROUP - 1) // SHARDS_PER_GROUP

    total_corrupted_shards = 0
    total_corrupted_bytes = 0

    for g in range(num_groups):
        group_start_idx = g * SHARDS_PER_GROUP
        group_end_idx = min(group_start_idx + SHARDS_PER_GROUP, total_shards)
        group_size = group_end_idx - group_start_idx

        n_corrupt = min(max_per_group, group_size)
        chosen = random.sample(range(group_start_idx, group_end_idx), n_corrupt)

        for shard_idx in chosen:
            shard_offset = shard_start + shard_idx * SHARD_SIZE
            n_bytes = random.randint(10, 100)
            for _ in range(n_bytes):
                byte_off = shard_offset + random.randint(0, SHARD_SIZE - 1)
                if byte_off < shard_end:
                    data[byte_off] ^= random.randint(1, 255)
                    total_corrupted_bytes += 1
            total_corrupted_shards += 1

    open(dst, "wb").write(data)
    print(f"Total shards: {total_shards}, groups: {num_groups}")
    print(f"Corrupted {total_corrupted_shards} shards "
          f"(max {max_per_group}/group, RS can repair up to {PARITY_PER_GROUP}/group)")
    print(f"Corrupted {total_corrupted_bytes} bytes total "
          f"({total_corrupted_bytes/shard_region_size*100:.4f}% of shard region)")


if __name__ == "__main__":
    main()
