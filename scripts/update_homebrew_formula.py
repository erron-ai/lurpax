#!/usr/bin/env python3
"""Update Homebrew Formula/lurpax.rb: version, ordered sha256 lines, optional GitHub slug."""

from __future__ import annotations

import argparse
import pathlib
import re
import sys

# Homebrew's CurlDownloadStrategy chdirs into the archive when it contains exactly one
# top-level directory (see brew Library/Homebrew/download_strategy.rb). The binary is
# then ./lurpax, not lurpax-*/lurpax. Support both layouts.
_INSTALL_BLOCK = """  def install
    path = File.exist?("lurpax") ? "lurpax" : Dir["lurpax-*/lurpax"].first
    odie "lurpax binary not found (expected lurpax or lurpax-*/lurpax in archive)" if path.nil?
    bin.install path => "lurpax"
  end"""


def apply_install_block(text: str) -> str:
    """Replace the formula `install` method with the layout-compatible block."""
    text2, n = re.subn(
        r"  def install\n.*?^  end\n",
        _INSTALL_BLOCK + "\n",
        text,
        count=1,
        flags=re.DOTALL | re.MULTILINE,
    )
    if n != 1:
        print("error: could not replace install block", file=sys.stderr)
        sys.exit(1)
    return text2


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("formula", type=pathlib.Path)
    parser.add_argument(
        "--version",
        required=True,
        help="Semver without v prefix (e.g. 0.1.0).",
    )
    parser.add_argument(
        "--sha",
        dest="shas",
        action="append",
        required=True,
        help=(
            "SHA256 hex; pass four times in order: "
            "x86_64-apple-darwin, aarch64-apple-darwin, "
            "x86_64-unknown-linux-musl, aarch64-unknown-linux-musl."
        ),
    )
    parser.add_argument(
        "--github-slug",
        default="",
        help="owner/name — replaces github.com/erron-ai/lurpax in url strings when set.",
    )
    args = parser.parse_args()
    if len(args.shas) != 4:
        print("error: expected exactly four --sha flags", file=sys.stderr)
        sys.exit(1)

    text = args.formula.read_text(encoding="utf-8")
    text, n = re.subn(
        r'version "[^"]+"',
        f'version "{args.version}"',
        text,
        count=1,
    )
    if n != 1:
        print("error: could not find single version line", file=sys.stderr)
        sys.exit(1)

    for sha in args.shas:
        if not re.fullmatch(r"[0-9a-fA-F]{64}", sha):
            print(f"error: invalid sha256: {sha!r}", file=sys.stderr)
            sys.exit(1)

    sha_iter = iter(args.shas)

    def inject_sha256(match: re.Match[str]) -> str:
        sha = next(sha_iter)
        return f'{match.group(1)}sha256 "{sha}"'

    text, c = re.subn(
        r'^(\s*)sha256 "[^"]+"',
        inject_sha256,
        text,
        count=len(args.shas),
        flags=re.MULTILINE,
    )
    if c != len(args.shas):
        print(
            f"error: expected {len(args.shas)} sha256 lines, replaced {c}",
            file=sys.stderr,
        )
        sys.exit(1)

    if args.github_slug:
        text = text.replace(
            "github.com/erron-ai/lurpax",
            f"github.com/{args.github_slug}",
        )

    text = apply_install_block(text)

    args.formula.write_text(text, encoding="utf-8")


if __name__ == "__main__":
    main()
