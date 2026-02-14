# Worker Boundary

This subtree documents worker responsibilities.

Worker entrypoint implementations:
- `apps/worker/runner.py`
- `apps/worker/cli.py`
- `apps/worker/ingest_parquet.py`
- `apps/worker/export_findings.py`

Root scripts still exist as compatibility wrappers for existing automation.

Rules:
- Worker code must stay deterministic and idempotent.
- Worker deploy/runtime is separate from backend deploy/runtime.
- Cloud account execution (CloudShell/cron/Step Functions) should only require worker paths.
