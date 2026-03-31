#!/usr/bin/env bash
set -euo pipefail

REPO="${LURPAX_REPO:-erron-ai/lurpax}"
INSTALL_DIR="${LURPAX_INSTALL_DIR:-/usr/local/bin}"

info()  { printf '\033[1;34m%s\033[0m\n' "$*"; }
err()   { printf '\033[1;31merror: %s\033[0m\n' "$*" >&2; exit 1; }

detect_target() {
    local os arch
    os="$(uname -s)"
    arch="$(uname -m)"

    case "$os" in
        Darwin) os="apple-darwin" ;;
        Linux)  os="unknown-linux-musl" ;;
        *)      err "unsupported OS: $os" ;;
    esac

    case "$arch" in
        x86_64|amd64)  arch="x86_64" ;;
        arm64|aarch64) arch="aarch64" ;;
        *)             err "unsupported architecture: $arch" ;;
    esac

    echo "${arch}-${os}"
}

get_latest_tag() {
    local response http_code body tag
    response="$(
        curl -sS -w $'\n%{http_code}' \
            "https://api.github.com/repos/${REPO}/releases/latest"
    )" || err "failed to contact GitHub (network or TLS error). Try again or install from source (see README)."
    http_code="${response##*$'\n'}"
    body="${response%$'\n'${http_code}}"
    case "$http_code" in
        200) ;;
        404)
            err "no GitHub release for ${REPO}: repo missing/private/unpublished, or no releases yet. Tag v* and run the release workflow, set LURPAX_REPO=owner/repo for a fork, or use: cargo build --release"
            ;;
        *)
            err "GitHub API HTTP ${http_code} for ${REPO}/releases/latest"
            ;;
    esac
    tag="$(printf '%s\n' "$body" | grep '"tag_name"' | head -1 | cut -d'"' -f4)"
    [ -n "$tag" ] || err "could not parse latest release tag from API response"
    echo "$tag"
}

main() {
    local target tag name url tmpdir

    target="$(detect_target)"
    tag="${1:-$(get_latest_tag)}"
    name="lurpax-${tag}-${target}"
    url="https://github.com/${REPO}/releases/download/${tag}/${name}.tar.gz"

    info "downloading lurpax ${tag} for ${target}..."
    tmpdir="$(mktemp -d)"
    trap 'rm -rf "$tmpdir"' EXIT

    curl -fsSL "$url" -o "${tmpdir}/${name}.tar.gz"
    tar xzf "${tmpdir}/${name}.tar.gz" -C "$tmpdir"

    info "installing to ${INSTALL_DIR}/lurpax..."
    mkdir -p "$INSTALL_DIR"
    mv "${tmpdir}/${name}/lurpax" "${INSTALL_DIR}/lurpax"
    chmod +x "${INSTALL_DIR}/lurpax"

    info "lurpax ${tag} installed successfully"
    "${INSTALL_DIR}/lurpax" --version 2>/dev/null || true
}

main "$@"
