#!/usr/bin/env bash
# Updates the Homebrew formula SHA256 hashes after a release.
# Usage: ./update-formula.sh v0.1.0
set -euo pipefail

TAG="${1:?usage: $0 <tag>  e.g. v0.1.0}"
REPO="erron-ai/lurpax"
FORMULA="$(dirname "$0")/lurpax.rb"

targets=(
    x86_64-apple-darwin
    aarch64-apple-darwin
    x86_64-unknown-linux-musl
    aarch64-unknown-linux-musl
)

for target in "${targets[@]}"; do
    url="https://github.com/${REPO}/releases/download/${TAG}/lurpax-${TAG}-${target}.tar.gz"
    sha="$(curl -fsSL "$url" | shasum -a 256 | awk '{print $1}')"
    printf '%-40s %s\n' "$target" "$sha"

    # Replace the placeholder or existing sha256 for this target's URL
    # The sha256 line immediately follows the url line for each target
    sed -i.bak "/${target}/{ n; s/sha256 \".*\"/sha256 \"${sha}\"/; }" "$FORMULA"
done

rm -f "${FORMULA}.bak"
# Also update the version
sed -i.bak "s/version \".*\"/version \"${TAG#v}\"/" "$FORMULA"
rm -f "${FORMULA}.bak"

echo "Formula updated for ${TAG}"
