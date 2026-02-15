# API Reference

Status: Derived  
Last reviewed: 2026-02-15

This document describes the HTTP API implemented in the Flask application using a modular Blueprint architecture.

## Architecture

The API is organized into Flask Blueprints, each handling a specific domain:
- `health` - Health checks and liveness probes
- `runs` - Run management and diffs
- `findings` - Finding queries and governance
- `recommendations` - FinOps optimization recommendations
- `remediations` - Remediation action approval and queue views
- `teams` - Team and member management
- `sla_policies` - SLA policy management
- `lifecycle` - Finding lifecycle actions
- `groups` - Finding grouping and aggregation
- `facets` - Filter facets and audit log

Source code:
- Main app: `apps/flask_api/flask_app.py`
- Blueprints: `apps/flask_api/blueprints/`
- Utilities: `apps/flask_api/utils/`

## Base and auth

- Base URL: `http(s)://RootSquirrels.pythonanywhere.com`
- Versioned API base: `/api/v1`
- Legacy compatibility base (still supported): `/api`
- OpenAPI 3.0 spec endpoints:
  - `GET /openapi.json` (public)
  - `GET /api/openapi.json`
  - `GET /api/v1/openapi.json`
- Version metadata endpoint:
  - `GET /api/version` (also available as `/api/v1/version`)
- Public endpoints:
  - `GET /health`
  - `GET /api/health/db`
- All other `/api/*` endpoints require bearer auth when `API_BEARER_TOKEN` is set:
  - Missing `Authorization: Bearer ...` -> `401`
  - Invalid token -> `403`

## Scope rules

- Almost all API routes are tenant/workspace scoped.
- Scope inputs:
  - Query routes: `tenant_id` and `workspace` query params.
  - JSON routes: `tenant_id` and `workspace` in body.
- Missing scope returns `400`.

## Response conventions

- Most routes return:
  - Success: `{"ok": true, ...}`
  - Error: `{"ok": false, "error": "<code>", "message": "<text>"}`
- Legacy lifecycle/group routes return:
  - Success: `{"ok": true}`
  - Error: `{"error": "<text>"}` (HTTP 400)

## Health

| Method | Path | Description |
|---|---|---|
| GET | `/health` | Liveness check |
| GET | `/api/health/db` | DB connectivity check |

## Runs

| Method | Path | Description |
|---|---|---|
| GET | `/api/runs/latest` | Latest run for scope |
| GET | `/api/runs/diff/latest` | Diff between latest 2 ready runs |

Query for both: `tenant_id`, `workspace` (required).

## Findings read model

| Method | Path | Description |
|---|---|---|
| GET | `/api/findings` | Paginated finding list with governance fields |
| GET | `/api/findings/sla/breached` | Findings where `sla_status='breached'` |
| GET | `/api/findings/aging` | Findings by `age_days_open` or `age_days_detected` |
| GET | `/api/findings/aggregates` | Aggregates by effective_state/severity/service |
| GET | `/api/facets` | Filter facets (services/regions/severities/states) |

Common optional filters:
- `state`, `severity`, `service`, `check_id`, `category`, `region`, `account_id`
- Governance filters: `team_id`, `owner_email`, `sla_status`
- Text search: `q` (`title ILIKE`)
- Pagination: `limit`, `offset`

`/api/findings` optional sorting:
- `order=savings_desc|detected_desc`

`/api/findings/aging` required/optional:
- `age_basis=open|detected` (default `open`)
- `min_days` (default `0`)
- `max_days` (optional, must be `>= min_days`)

## Recommendations

| Method | Path | Description |
|---|---|---|
| GET | `/api/recommendations` | Actionable recommendations from findings |
| GET | `/api/recommendations/composite` | Aggregated recommendations by type |
| POST | `/api/recommendations/estimate` | Estimate savings for selected recommendations |
| POST | `/api/recommendations/preview` | Alias for /estimate |

Query/Body params for `/api/recommendations`:
- Scope: `tenant_id`, `workspace` (required)
- Filters: `state`, `severity`, `service`, `check_id`, `category`, `region`, `account_id`
- Search: `q` (title ILIKE)
- Min savings: `min_savings`
- Sorting: `order=savings_desc|detected_desc`
- Pagination: `limit`, `offset`

Query/Body params for `/api/recommendations/composite`:
- Scope: `tenant_id`, `workspace`
- Grouping: `group_by=recommendation_type|service|check_id|category|region`
- Sorting: `order=savings_desc|count_desc`
- Pagination: `limit`, `offset`

Body params for `/api/recommendations/estimate`:
- `tenant_id`, `workspace` required
- `fingerprints` - list of finding fingerprints
- Optional: `limit`, `offset`, `order`, `state`, `severity`, `service`, `check_id`, `category`, `region`, `account_id`, `q`, `min_savings`

## Remediations

| Method | Path | Description |
|---|---|---|
| GET | `/api/remediations` | List remediation actions |
| GET | `/api/remediations/impact` | List remediation impact and realized savings metrics |
| POST | `/api/remediations/request` | Request remediation action creation for a finding |
| POST | `/api/remediations/approve` | Approve one pending remediation action |
| POST | `/api/remediations/reject` | Reject one pending remediation action |

Scope:
- `tenant_id`, `workspace` are required for all remediation routes.

### GET /api/remediations

Optional filters:
- `status`, `action_type`, `check_id`, `fingerprint` (CSV)
- `limit`, `offset`

### GET /api/remediations/impact

Optional filters:
- `action_status`, `verification_status`, `action_type`, `check_id`, `fingerprint`, `action_id` (CSV)
- `limit`, `offset`
- `refresh` (boolean, default `false`) to refresh impact snapshots before listing
- `refresh_limit` (default `500`) max actions refreshed when `refresh=true`

Response:
- `summary.actions_count`: impact rows count in filtered scope
- `summary.baseline_total_monthly_savings`: total baseline estimated monthly savings
- `summary.realized_total_monthly_savings`: total realized monthly savings
- `summary.realization_rate_pct`: realized/baseline percentage when baseline > 0
- `items`: per-action impact rows with verification status and realized savings

### POST /api/remediations/request

Body:
- `tenant_id`, `workspace`, `fingerprint` required
- Optional: `action_id`, `action_type`, `action_payload`, `dry_run`, `auto_approve`, `requested_by`, `reason`

Behavior:
- Creates a remediation action idempotently from a finding in `finding_current`.
- If `action_id` is omitted, a deterministic action id is derived from scope + fingerprint + action type + dry-run.
- If the action already exists with matching identity, returns existing action with `created=false` and `idempotent=true`.

Errors:
- `404` finding missing in scope
- `409` finding is terminal (`resolved`/`ignored`) or `action_id` conflicts with different identity
- `400` invalid payload

### POST /api/remediations/approve

Body:
- `tenant_id`, `workspace`, `action_id`, `approved_by` required
- `reason` optional

Errors:
- `404` action missing in scope
- `409` action is not in `pending_approval`
- `400` invalid payload

### POST /api/remediations/reject

Body:
- `tenant_id`, `workspace`, `action_id`, `rejected_by` required
- `reason` optional

Errors:
- `404` action missing in scope
- `409` action is not in `pending_approval`
- `400` invalid payload

## Finding governance mutation routes

| Method | Path | Description |
|---|---|---|
| PUT | `/api/findings/{fingerprint}/owner` | Assign or clear owner fields |
| PUT | `/api/findings/{fingerprint}/team` | Assign or clear team |
| POST | `/api/findings/{fingerprint}/sla/extend` | Extend SLA by `extend_days` |

Body scope: `tenant_id`, `workspace` (required).

### PUT /api/findings/{fingerprint}/owner

Body:
- One or more of `owner_id`, `owner_email`, `owner_name` (nullable to clear)
- `updated_by` (optional)

Errors:
- `404` if finding missing
- `400` invalid payload

### PUT /api/findings/{fingerprint}/team

Body:
- `team_id` required key (nullable to clear)
- `updated_by` (optional)

Errors:
- `404` if finding/team missing
- `400` invalid payload

### POST /api/findings/{fingerprint}/sla/extend

Body:
- `extend_days` integer > 0
- `reason` (optional)
- `updated_by` (optional)

Errors:
- `404` if finding missing
- `409` if finding state is `resolved` or `ignored`
- `400` if no SLA policy resolved or invalid payload

## Groups

| Method | Path | Description |
|---|---|---|
| GET | `/api/groups` | Grouped findings (`group_key`) |
| GET | `/api/groups/{group_key}` | Group summary + member findings |

Scope query required: `tenant_id`, `workspace`.

`/api/groups` optional:
- filters: `state`, `category`, `service`, `check_id`, `severity`, `q`
- sorting: `order=savings_desc|count_desc`
- pagination: `limit`, `offset`

`/api/groups/{group_key}` optional:
- `state`, `q`, `limit`, `offset`

## Lifecycle mutation routes (legacy payload style)

Finding-level:
- `POST /api/lifecycle/ignore`
- `POST /api/lifecycle/resolve`
- `POST /api/lifecycle/snooze`

Group-level:
- `POST /api/lifecycle/group/ignore`
- `POST /api/lifecycle/group/resolve`
- `POST /api/lifecycle/group/snooze`

Scope body required: `tenant_id`, `workspace`.

Required fields:
- Finding routes: `fingerprint`
- Group routes: `group_key`
- Snooze routes: `snooze_until` (ISO-8601)

Optional: `reason`, `updated_by`

## Audit log

| Method | Path | Description |
|---|---|---|
| GET | `/api/audit` | Paginated audit log query |

Scope query required: `tenant_id`, `workspace`.

Optional filters:
- `entity_type`, `entity_id`, `fingerprint`
- `event_type`, `event_category`
- `actor_email`, `correlation_id`
- `limit`, `offset`

## Teams and team members

Teams:
- `GET /api/teams`
- `POST /api/teams`
- `PUT /api/teams/{team_id}`
- `DELETE /api/teams/{team_id}`

Members:
- `GET /api/teams/{team_id}/members`
- `POST /api/teams/{team_id}/members`
- `DELETE /api/teams/{team_id}/members/{user_id}`

### GET /api/teams

Scope query required: `tenant_id`, `workspace`  
Optional: `q`, `limit`, `offset`

### POST /api/teams

Body:
- `tenant_id`, `workspace` required
- `team_id`, `name` required
- `description`, `parent_team_id`, `updated_by` optional

Errors:
- `409` team exists
- `404` parent team missing

### PUT /api/teams/{team_id}

Body:
- `tenant_id`, `workspace` required
- At least one: `name`, `description`, `parent_team_id`
- `updated_by` optional

Errors:
- `404` team or parent missing
- `400` invalid payload

### DELETE /api/teams/{team_id}

Scope query required: `tenant_id`, `workspace`  
Optional query: `updated_by`

### GET /api/teams/{team_id}/members

Scope query required: `tenant_id`, `workspace`  
Optional: `q`, `limit`, `offset`

### POST /api/teams/{team_id}/members

Body:
- `tenant_id`, `workspace` required
- `user_id`, `user_email` required
- `role` optional (`owner|member|viewer`, default `member`)
- `user_name`, `updated_by` optional

Errors:
- `404` team missing
- `409` member exists

### DELETE /api/teams/{team_id}/members/{user_id}

Scope query required: `tenant_id`, `workspace`  
Optional query: `updated_by`

Errors:
- `404` team or member missing

## SLA policy management

Category policies:
- `GET /api/sla/policies`
- `POST /api/sla/policies`
- `PUT /api/sla/policies/{category}`

Check overrides:
- `GET /api/sla/policies/overrides`
- `POST /api/sla/policies/overrides`

### GET /api/sla/policies

Scope query required: `tenant_id`, `workspace`  
Optional: `limit`, `offset`

### POST /api/sla/policies

Body:
- `tenant_id`, `workspace` required
- `category` required
- `sla_days` integer > 0 required
- `description`, `updated_by` optional

Errors:
- `409` category exists

### PUT /api/sla/policies/{category}

Body:
- `tenant_id`, `workspace` required
- At least one: `sla_days`, `description`
- `updated_by` optional

Errors:
- `404` category missing

### GET /api/sla/policies/overrides

Scope query required: `tenant_id`, `workspace`  
Optional: `check_id` CSV, `limit`, `offset`

### POST /api/sla/policies/overrides

Body:
- `tenant_id`, `workspace` required
- `check_id` required
- `sla_days` integer > 0 required
- `reason`, `updated_by` optional

Errors:
- `409` override exists

## Smoke testing

Use `tests/api/api_smoke.py`:

```bash
python tests/api/api_smoke.py \
  --base-url `http(s)://RootSquirrels.pythonanywhere.com` \
  --tenant-id <tenant> \
  --workspace <workspace> \
  --token <bearer-token>
```

Read-only mode:

```bash
python tests/api/api_smoke.py --skip-mutations ...
```
