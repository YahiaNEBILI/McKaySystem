#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="${1:-.}"
cd "$REPO_ROOT"

# Use non-cone mode because we intentionally include specific root files.
git sparse-checkout init --no-cone
git sparse-checkout set \
  apps \
  docs \
  migrations \
  tests \
  tools \
  AGENTS.md \
  README.md \
  pyproject.toml \
  pytest.ini \
  version.py \
  __init__.py

echo "Backend sparse checkout applied in: $PWD"
