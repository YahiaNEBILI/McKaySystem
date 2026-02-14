# Backend Boundary

This subtree owns SaaS/API-facing code.

Current backend app:
- `apps/flask_api/`
- `apps/backend/db.py`
- `apps/backend/db_migrate.py`

Rules:
- API reads findings from `finding_current` only.
- All DB queries are scoped by `tenant_id` + `workspace`.
- Backend deployment lifecycle is independent from worker runtime.
