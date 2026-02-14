#!/usr/bin/env bash
set -euo pipefail

python tools/repo/check_layout.py
python -m compileall -q apps/flask_api db.py db_migrate.py
python -m pytest -q tests/api tests/test_db_migrate.py tests/test_repo_layout_policy.py
