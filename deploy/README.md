# Deployment Separation

This repository has two deployment units:

1. Backend API
Path/docs:
- `apps/flask_api/`
- `deploy/backend/README.md`

2. Worker runtime (scanner/pipeline)
Path/docs:
- engine paths + `apps/worker/` entrypoints
- `deploy/worker/README.md`

Keep release cadence and runtime environments separate.

CI tracks:
- Backend CI workflow: `.github/workflows/backend-ci.yml`
- Worker CI workflow: `.github/workflows/worker-ci.yml`
- Shared guardrails workflow: `.github/workflows/main.yml`

Local release-check commands:
- `make ci-backend` (or `bash deploy/backend/release_check.sh`)
- `make ci-worker` (or `bash deploy/worker/release_check.sh`)
