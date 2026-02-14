#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="${1:-.}"
cd "$REPO_ROOT"

# Use non-cone mode because we intentionally include specific root files.
git sparse-checkout init --no-cone
git sparse-checkout set \
  apps/worker \
  apps/backend \
  checks \
  contracts \
  docs \
  infra \
  migrations \
  pipeline \
  services \
  tests \
  tools \
  AGENTS.md \
  README.md \
  pyproject.toml \
  pytest.ini \
  version.py \
  __init__.py

echo "Worker sparse checkout applied in: $PWD"
