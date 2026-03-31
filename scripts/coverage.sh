#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if ! command -v cargo-llvm-cov >/dev/null 2>&1; then
  echo "install: cargo install cargo-llvm-cov" >&2
  exit 1
fi
cargo llvm-cov clean --workspace
cargo llvm-cov --workspace --all-features --tests --summary-only \
  --fail-under-lines 98 --fail-under-functions 98 --fail-under-regions 98
