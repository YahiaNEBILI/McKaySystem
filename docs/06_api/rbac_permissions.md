# RBAC Permission Matrix

Status: Canonical  
Last reviewed: 2026-02-22

This document maps API routes to RBAC permissions enforced by `apps/flask_api/auth_middleware.py`.

## Auth methods

- Session token: cookie `session_token` (or `session_token` in query/body for compatibility).
- API key: `Authorization: Bearer <api-key>`.
- Legacy global bearer (`API_BEARER_TOKEN`) may still gate non-public routes, but RBAC permission checks require a resolved RBAC principal.

## Permissions

| Permission | Route coverage |
|---|---|
| `findings:read` | `GET /api/findings`, `GET /api/findings/sla/breached`, `GET /api/findings/aging`, `GET /api/findings/aggregates`, `GET /api/facets`, `GET /api/groups`, `GET /api/groups/{group_key}`, `GET /api/recommendations`, `GET /api/recommendations/composite`, `POST /api/recommendations/estimate`, `POST /api/recommendations/preview`, `GET /api/remediations`, `GET /api/remediations/impact` |
| `findings:update` | `PUT /api/findings/{fingerprint}/owner`, `PUT /api/findings/{fingerprint}/team`, `POST /api/findings/{fingerprint}/sla/extend`, `POST /api/lifecycle/ignore`, `POST /api/lifecycle/resolve`, `POST /api/lifecycle/snooze`, `POST /api/lifecycle/group/ignore`, `POST /api/lifecycle/group/resolve`, `POST /api/lifecycle/group/snooze`, `POST /api/remediations/request`, `POST /api/remediations/approve`, `POST /api/remediations/reject` |
| `runs:read` | `GET /api/runs/latest`, `GET /api/runs/diff/latest` |
| `teams:read` | `GET /api/teams`, `GET /api/teams/{team_id}/members` |
| `teams:create` | `POST /api/teams` |
| `teams:update` | `PUT /api/teams/{team_id}` |
| `teams:delete` | `DELETE /api/teams/{team_id}` |
| `teams:manage_members` | `POST /api/teams/{team_id}/members`, `DELETE /api/teams/{team_id}/members/{user_id}` |
| `sla:read` | `GET /api/sla/policies`, `GET /api/sla/policies/overrides` |
| `sla:create` | `POST /api/sla/policies`, `POST /api/sla/policies/overrides` |
| `sla:update` | `PUT /api/sla/policies/{category}` |
| `users:read` | `GET /api/users`, `GET /api/users/{user_id}` |
| `users:create` | `POST /api/users` |
| `users:update` | `PUT /api/users/{user_id}` |
| `users:delete` | `DELETE /api/users/{user_id}` |
| `users:manage_roles` | `GET /api/users/{user_id}/role`, `PUT /api/users/{user_id}/role`, `PUT /api/users/{user_id}/role/tenant` |
| `api_keys:read` | `GET /api/api-keys` |
| `api_keys:create` | `POST /api/api-keys` |
| `api_keys:revoke` | `DELETE /api/api-keys/{key_id}` |

## Superadmin/Admin override

- `is_superadmin = true` bypasses permission checks.
- `admin:full` permission bypasses permission checks.

## Authenticated-only routes (no explicit permission id)

- `POST /api/auth/logout` requires a valid authenticated RBAC context.
- `GET /api/auth/me` requires a valid authenticated RBAC context and matching scope.

## Public routes (no authentication)

- `GET /health`
- `GET /api/health/db`
- `GET /openapi.json`
- `GET /api/openapi.json`
- `GET /api/v1/openapi.json`
- `GET /api/version`
- `GET /api/v1/version`
