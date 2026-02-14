# Backend Boundary

This subtree owns SaaS/API-facing code.

Current backend app:
- `apps/flask_api/`

Rules:
- API reads findings from `finding_current` only.
- All DB queries are scoped by `tenant_id` + `workspace`.
- Backend deployment lifecycle is independent from worker runtime.
