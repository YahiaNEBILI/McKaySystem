#!/usr/bin/env bash
set -euo pipefail

python tools/repo/check_layout.py
python -m compileall -q apps/worker checks contracts infra pipeline services

python -m pytest -q tests -k "not api"
