#!/usr/bin/env bash
set -euo pipefail

REPO="erronai/lurpax"
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
    local tag
    tag="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
        | grep '"tag_name"' | head -1 | cut -d'"' -f4)"
    [ -n "$tag" ] || err "could not determine latest release"
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
