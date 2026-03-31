#!/usr/bin/env bash
# Print SHA256 hex digests from GitHub release .sha256 sidecars (for Homebrew tap updates).
# Usage: ./scripts/print-release-sha256s.sh v0.1.0
# Optional: REPO=owner/name ./scripts/print-release-sha256s.sh v0.1.0
set -euo pipefail

REPO="${REPO:-erronai/lurpax}"
TAG="${1:?usage: $0 v0.1.0}"

targets=(
  x86_64-apple-darwin
  aarch64-apple-darwin
  x86_64-unknown-linux-musl
  aarch64-unknown-linux-musl
)

for t in "${targets[@]}"; do
  url="https://github.com/${REPO}/releases/download/${TAG}/lurpax-${TAG}-${t}.tar.gz.sha256"
  sum="$(curl -fsSL "$url" | awk '{print $1}')"
  printf '%s\t%s\n' "$t" "$sum"
done
