#!/usr/bin/env bash
# Update and push Homebrew tap after a lurpax GitHub release exists for TAG.
# macOS / Linux. Requires: git, curl, awk, python3.
#
# Env:
#   TAP_PUSH_TOKEN or HOMEBREW_TAP_TOKEN — PAT with contents:write on the tap repo
#   GITHUB_TOKEN — optional; in Actions, used to fetch checksums when LURPAX_SLUG matches
#     GITHUB_REPOSITORY (private release assets)
#   LURPAX_REPO — owner/name (default: GITHUB_REPOSITORY or origin remote)
#   HOMEBREW_TAP_REPO or TAP_REPO — tap owner/name (default: <lurpax-owner>/homebrew-tap)
set -euo pipefail

TAG="${1:?usage: $0 v0.1.0}"
if [[ ! "${TAG}" =~ ^v[0-9] ]]; then
  printf 'error: TAG must be a release tag like v0.7.0 (got %q); branch refs such as main are invalid\n' "${TAG}" >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

TOKEN="${TAP_PUSH_TOKEN:-${HOMEBREW_TAP_TOKEN:-}}"
if [ -z "${TOKEN}" ]; then
  printf 'error: set TAP_PUSH_TOKEN or HOMEBREW_TAP_TOKEN (PAT with push access to the tap)\n' >&2
  exit 1
fi

resolve_lurpax_repo() {
  if [ -n "${LURPAX_REPO:-}" ]; then
    printf '%s\n' "${LURPAX_REPO}"
    return
  fi
  if [ -n "${GITHUB_REPOSITORY:-}" ]; then
    printf '%s\n' "${GITHUB_REPOSITORY}"
    return
  fi
  local url
  url="$(git -C "${REPO_ROOT}" remote get-url origin 2>/dev/null || true)"
  if [[ "${url}" =~ github\.com[:/]([^/]+)/([^/.]+)(\.git)?$ ]]; then
    printf '%s/%s\n' "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}"
    return
  fi
  printf 'error: set LURPAX_REPO or add a github.com origin remote\n' >&2
  exit 1
}

LURPAX_SLUG="$(resolve_lurpax_repo)"
OWNER="${LURPAX_SLUG%%/*}"
TAP_SLUG="${HOMEBREW_TAP_REPO:-${TAP_REPO:-${OWNER}/homebrew-tap}}"

VER="${TAG#v}"
BASE="https://github.com/${LURPAX_SLUG}/releases/download/${TAG}"

RELEASE_FETCH_TOKEN="${TOKEN}"
if [ -n "${GITHUB_TOKEN:-}" ] && [ -n "${GITHUB_REPOSITORY:-}" ]; then
  _l="$(printf '%s\n' "${LURPAX_SLUG}" | tr '[:upper:]' '[:lower:]')"
  _g="$(printf '%s\n' "${GITHUB_REPOSITORY}" | tr '[:upper:]' '[:lower:]')"
  if [ "${_l}" = "${_g}" ]; then
    RELEASE_FETCH_TOKEN="${GITHUB_TOKEN}"
  fi
fi
unset _l _g

curl_release_asset() {
  curl -fsSL -H "Authorization: Bearer ${RELEASE_FETCH_TOKEN}" "$1"
}

targets=(
  x86_64-apple-darwin
  aarch64-apple-darwin
  x86_64-unknown-linux-musl
  aarch64-unknown-linux-musl
)
shas=()
for t in "${targets[@]}"; do
  url="${BASE}/lurpax-${TAG}-${t}.tar.gz.sha256"
  if ! sum="$(curl_release_asset "${url}" | awk '{print $1}')"; then
    printf 'error: failed to fetch checksum (private repo? wrong tag? missing asset?): %s\n' "${url}" >&2
    exit 22
  fi
  shas+=("${sum}")
done

for s in "${shas[@]}"; do
  if [ "${#s}" -ne 64 ]; then
    printf 'error: bad checksum from %s (expected 64 hex chars, got %s)\n' "${BASE}" "${#s}" >&2
    exit 1
  fi
done

tmpdir="$(mktemp -d)"
cleanup() { rm -rf "${tmpdir}"; }
trap cleanup EXIT

git clone --depth 1 "https://x-access-token:${TOKEN}@github.com/${TAP_SLUG}.git" "${tmpdir}/tap"

python3 "${REPO_ROOT}/scripts/update_homebrew_formula.py" "${tmpdir}/tap/Formula/lurpax.rb" \
  --version "${VER}" \
  --sha "${shas[0]}" --sha "${shas[1]}" --sha "${shas[2]}" --sha "${shas[3]}" \
  --github-slug "${LURPAX_SLUG}"

cd "${tmpdir}/tap"
git config user.email "41898282+github-actions[bot]@users.noreply.github.com"
git config user.name "github-actions[bot]"
git add Formula/lurpax.rb
if git diff --cached --quiet; then
  printf 'No formula changes to commit.\n'
  exit 0
fi
git commit -m "lurpax ${VER}"
git push origin HEAD

printf 'Pushed %s to %s\n' "${VER}" "${TAP_SLUG}"
