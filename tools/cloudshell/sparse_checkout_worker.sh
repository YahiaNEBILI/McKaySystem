#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="${1:-.}"
cd "$REPO_ROOT"

git sparse-checkout init --cone
git sparse-checkout set \
  apps/worker \
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
  db.py \
  db_migrate.py \
  version.py \
  __init__.py

echo "Worker sparse checkout applied in: $PWD"
