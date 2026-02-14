# Worker Deployment

Deploy target:
- scan/checker and pipeline runtime (`apps/worker/`, `pipeline/`, `checks/`).

Typical runtime:
- AWS CloudShell
- cron/EventBridge/Step Functions runner host

Required env (depends on command):
- AWS credentials/role
- `TENANT_ID`, `WORKSPACE` (or command args)
- `DB_URL` only for ingest/migrate paths

Release check:
- `bash deploy/worker/release_check.sh`

CI workflow:
- `.github/workflows/worker-ci.yml` (path-scoped worker checks)

Do not couple worker release cadence to backend API deployment.
