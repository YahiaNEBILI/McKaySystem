# Backend Deployment

Deploy target:
- `apps/flask_api/flask_app.py`
- `apps/backend/db.py`
- `apps/backend/db_migrate.py`

Required env:
- `DB_URL`
- `API_BEARER_TOKEN` (recommended in non-local env)

Recommended process:
1. Apply DB migrations (`python -m apps.backend.db_migrate`).
2. Deploy API artifact.
3. Run backend release checks (`bash deploy/backend/release_check.sh`).
4. Run API smoke checks against the deployed service.

CI workflow:
- `.github/workflows/backend-ci.yml` (path-scoped backend checks)

Do not run worker scans in the same deployment process.
