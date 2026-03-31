#!/usr/bin/env bash
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
chmod +x "$REPO_ROOT/.githooks/pre-commit"
git -C "$REPO_ROOT" config core.hooksPath "$REPO_ROOT/.githooks"
echo "Git hooks enabled: core.hooksPath -> $REPO_ROOT/.githooks"
