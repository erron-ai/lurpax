#!/usr/bin/env bash
set -euo pipefail

# Prefer known system paths so a hostile PATH cannot substitute curl/tar/sha tools (CWE-426).
CURL="${CURL:-/usr/bin/curl}"
TAR="${TAR:-/bin/tar}"

REPO="${LURPAX_REPO:-erron-ai/lurpax}"
INSTALL_DIR="${LURPAX_INSTALL_DIR:-/usr/local/bin}"

info()  { printf '\033[1;34m%s\033[0m\n' "$*"; }
err()   { printf '\033[1;31merror: %s\033[0m\n' "$*" >&2; exit 1; }

require_tools() {
    [ -x "$CURL" ] || err "curl not found or not executable at $CURL (set CURL to a trusted path)"
    [ -x "$TAR" ] || err "tar not found or not executable at $TAR (set TAR to a trusted path)"
    if [ -x /usr/bin/sha256sum ]; then
        :
    elif [ -x /usr/sbin/shasum ]; then
        :
    else
        err "need SHA-256 at /usr/bin/sha256sum or /usr/sbin/shasum"
    fi
}

# Print lowercase hex SHA-256 of file $1 (no newline in output).
sha256_hex_file() {
    local f="$1"
    if [ -x /usr/bin/sha256sum ]; then
        /usr/bin/sha256sum "$f" | awk '{print $1}'
    else
        /usr/sbin/shasum -a 256 "$f" | awk '{print $1}'
    fi
}

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
    # Prefer /releases/latest (stable only). GitHub returns 404 when the newest
    # release is a prerelease, or when there are no Release objects at all (git
    # tags alone do not count).
    local response http_code body tag
    response="$(
        "$CURL" -sS -w $'\n%{http_code}' \
            "https://api.github.com/repos/${REPO}/releases/latest"
    )" || err "failed to contact GitHub (network or TLS error). Try again or install from source (see README)."
    http_code="${response##*$'\n'}"
    body="${response%$'\n'${http_code}}"
    case "$http_code" in
        200)
            tag="$(printf '%s\n' "$body" | grep '"tag_name"' | head -1 | cut -d'"' -f4)"
            ;;
        404)
            body="$(
                "$CURL" -sS -w $'\n%{http_code}' \
                    "https://api.github.com/repos/${REPO}/releases?per_page=1"
            )" || err "failed to contact GitHub (network or TLS error). Try again or install from source (see README)."
            http_code="${body##*$'\n'}"
            body="${body%$'\n'${http_code}}"
            case "$http_code" in
                200) ;;
                *) err "GitHub API HTTP ${http_code} for ${REPO}/releases" ;;
            esac
            if printf '%s\n' "$body" | grep -q '"tag_name"'; then
                tag="$(printf '%s\n' "$body" | grep -m1 '"tag_name"' | cut -d'"' -f4)"
            else
                body="$(
                    "$CURL" -sS -w $'\n%{http_code}' \
                        "https://api.github.com/repos/${REPO}/tags?per_page=100"
                )" || err "failed to contact GitHub (network or TLS error). Try again or install from source (see README)."
                http_code="${body##*$'\n'}"
                body="${body%$'\n'${http_code}}"
                case "$http_code" in
                    200) ;;
                    404) err "no such repo ${REPO} (check LURPAX_REPO=owner/repo)" ;;
                    *) err "GitHub API HTTP ${http_code} for ${REPO}/tags" ;;
                esac
                tag="$(
                    printf '%s\n' "$body" \
                        | grep '"name"' \
                        | cut -d'"' -f4 \
                        | grep '^v[0-9]' \
                        | sort -V \
                        | tail -1
                )"
                [ -n "$tag" ] || err "no GitHub Release for ${REPO} (git tags are not releases). Push tag v* and wait for the release workflow to publish assets, set LURPAX_REPO=owner/repo for a fork, or use: cargo build --release"
            fi
            ;;
        *)
            err "GitHub API HTTP ${http_code} for ${REPO}/releases/latest"
            ;;
    esac
    [ -n "$tag" ] || err "could not parse latest release tag from API response"
    echo "$tag"
}

main() {
    local target tag name url tmpdir

    require_tools
    target="$(detect_target)"
    tag="${1:-$(get_latest_tag)}"
    name="lurpax-${tag}-${target}"
    url="https://github.com/${REPO}/releases/download/${tag}/${name}.tar.gz"

    info "downloading lurpax ${tag} for ${target}..."
    tmpdir="$(mktemp -d)"
    trap 'rm -rf "$tmpdir"' EXIT

    "$CURL" -fsSL "$url" -o "${tmpdir}/${name}.tar.gz" \
        || err "failed to download ${url}. If the tag exists but install still fails, the release workflow may not have published binaries yet (GitHub Release + assets), or pick another tag: $0 TAG"

    info "verifying SHA-256 checksum..."
    "$CURL" -fsSL "https://github.com/${REPO}/releases/download/${tag}/${name}.tar.gz.sha256" \
        -o "${tmpdir}/${name}.tar.gz.sha256" \
        || err "failed to download ${name}.tar.gz.sha256 (release assets must include .sha256 sidecars)"
    expected="$(awk '{print $1}' "${tmpdir}/${name}.tar.gz.sha256")"
    [[ -n "${expected}" && "${#expected}" -eq 64 ]] || err "invalid checksum file from release"
    actual="$(sha256_hex_file "${tmpdir}/${name}.tar.gz")"
    [[ "${actual}" == "${expected}" ]] \
        || err "SHA-256 mismatch for ${name}.tar.gz (expected ${expected}, got ${actual})"

    "$TAR" -xzf "${tmpdir}/${name}.tar.gz" -C "$tmpdir"

    info "installing to ${INSTALL_DIR}/lurpax..."
    mkdir -p "$INSTALL_DIR"
    mv "${tmpdir}/${name}/lurpax" "${INSTALL_DIR}/lurpax"
    chmod +x "${INSTALL_DIR}/lurpax"

    info "lurpax ${tag} installed successfully"
    "${INSTALL_DIR}/lurpax" --version 2>/dev/null || true
}

main "$@"
