#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="${1:-.}"
cd "$REPO_ROOT"

git sparse-checkout init --cone
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
  db.py \
  db_migrate.py \
  version.py \
  __init__.py

echo "Backend sparse checkout applied in: $PWD"
