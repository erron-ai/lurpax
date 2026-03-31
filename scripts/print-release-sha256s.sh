#!/usr/bin/env bash
# Print SHA256 hex digests from GitHub release .sha256 sidecars (for Homebrew tap updates).
# Usage: ./scripts/print-release-sha256s.sh v0.1.0
# Optional: REPO=owner/name ./scripts/print-release-sha256s.sh v0.1.0
# Private repos: export GITHUB_TOKEN or GH_TOKEN with read access to REPO.
set -euo pipefail

REPO="${REPO:-erron-ai/lurpax}"
TAG="${1:?usage: $0 v0.1.0}"
AUTH_TOKEN="${GITHUB_TOKEN:-${GH_TOKEN:-}}"

targets=(
  x86_64-apple-darwin
  aarch64-apple-darwin
  x86_64-unknown-linux-musl
  aarch64-unknown-linux-musl
)

for t in "${targets[@]}"; do
  url="https://github.com/${REPO}/releases/download/${TAG}/lurpax-${TAG}-${t}.tar.gz.sha256"
  if [ -n "${AUTH_TOKEN}" ]; then
    sum="$(curl -fsSL -H "Authorization: Bearer ${AUTH_TOKEN}" "$url" | awk '{print $1}')"
  else
    sum="$(curl -fsSL "$url" | awk '{print $1}')"
  fi
  printf '%s\t%s\n' "$t" "$sum"
done
