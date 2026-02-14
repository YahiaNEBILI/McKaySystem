#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 3 ]]; then
  echo "Usage: $0 <repo-url> <target-dir> <worker|backend>"
  exit 1
fi

REPO_URL="$1"
TARGET_DIR="$2"
PROFILE="$3"

git clone --filter=blob:none "$REPO_URL" "$TARGET_DIR"
cd "$TARGET_DIR"

case "$PROFILE" in
  worker)
    bash tools/cloudshell/sparse_checkout_worker.sh .
    ;;
  backend)
    bash tools/cloudshell/sparse_checkout_backend.sh .
    ;;
  *)
    echo "Unknown profile: $PROFILE (expected worker or backend)"
    exit 2
    ;;
esac

echo "Sparse clone complete: $TARGET_DIR ($PROFILE)"
