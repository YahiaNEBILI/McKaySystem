# Flask API Refactoring Plan

## Overview

The current `flask_app.py` is a monolithic file (~4000 lines, 39 endpoints, 70+ helper functions) that needs to be refactored for scalability, maintainability, and robustness.

## Current State Analysis

- **File**: `apps/flask_api/flask_app.py` (~146KB)
- **Endpoints**: 39 total (GET, POST, PUT, DELETE)
- **Helper functions**: 70+ private functions (`_` prefix)
- **No modular structure**: Single file, no Flask Blueprints

### Endpoint Categories (39 total)

| Category | Count | Endpoints |
|----------|-------|-----------|
| Health/Meta | 5 | `/health`, `/api/health/db`, `/openapi.json`, `/api/openapi.json`, `/api/version` |
| Runs | 2 | `/api/runs/latest`, `/api/runs/diff/latest` |
| Recommendations | 4 | `/api/recommendations`, `/api/recommendations/composite`, `/api/recommendations/estimate`, `/api/recommendations/preview` |
| Findings | 7 | `/api/findings`, `/api/findings/sla/breached`, `/api/findings/aging`, `/api/findings/aggregates`, `/api/findings/<fingerprint>/owner`, `/api/findings/<fingerprint>/team`, `/api/findings/<fingerprint>/sla/extend` |
| Teams | 6 | CRUD + members management |
| SLA Policies | 5 | Policies + overrides management |
| Lifecycle | 6 | Group + individual ignore/resolve/snooze |
| Groups | 2 | `/api/groups`, `/api/groups/<group_key>` |
| Facets/Audit | 2 | `/api/facets`, `/api/audit` |

### Helper Function Categories

1. **Core/Config**: `_resolved_api_version()`, `_canonical_api_path()`, `_rule_to_openapi_path()`
2. **Request/Response**: `_ok()`, `_err()`, `_json()`, `_api_internal_error_response()`
3. **Middleware**: Rate limiting, auth, schema gate, logging
4. **Query Parsing**: `_q()`, `_require_scope_from_query()`, `_parse_int()`, `_parse_csv_list()`
5. **Payload Helpers**: `_as_float()`, `_payload_dict()`, `_coerce_optional_text()`
6. **Recommendations-specific**: `_build_recommendations_where()`, `_build_recommendation_item()`
7. **DB/State**: `_audit_log_event()`, `_upsert_state()`, `_finding_exists()`

---

## Refactoring Approach

**Incremental** - Refactor one module at a time, keeping the app functional throughout.

---

## Phase 1: Shared Utilities Modules

Create a new `utils/` package with focused modules:

```
apps/flask_api/
├── __init__.py
├── flask_app.py           # Main app (to be refactored)
├── utils/
│   ├── __init__.py
│   ├── responses.py        # _ok, _err, _json helpers
│   ├── params.py          # Query param parsing helpers
│   ├── db_utils.py        # DB/state helpers
│   └── openapi.py         # OpenAPI spec generation
└── blueprints/
    ├── __init__.py
    ├── health.py
    ├── runs.py
    ├── findings.py
    ├── recommendations.py
    ├── teams.py
    ├── sla_policies.py
    ├── lifecycle.py
    └── groups.py
```

### 1.1 - utils/responses.py
**Purpose**: Standardized response helpers

**Functions to extract**:
- `_ok()` - Success response with optional data
- `_err()` - Error response with code/message
- `_json()` - Generic JSON response helper
- `_api_internal_error_response()` - Route-specific error mapping

### 1.2 - utils/params.py
**Purpose**: Query and payload parameter parsing

**Functions to extract**:
- `_q()` - Get query param with default
- `_require_scope_from_query()` - Extract tenant_id + workspace
- `_require_scope_from_json()` - Extract from JSON body
- `_parse_int()` - Parse integer with min/max bounds
- `_parse_csv_list()` - Parse comma-separated values
- `_parse_iso8601_dt()` - Parse ISO-8601 timestamps
- `_coerce_optional_text()` - Normalize optional text
- `_payload_optional_text()` - Get normalized payload value
- `_coerce_positive_int()` - Parse required positive integer
- `_safe_scope_from_request()` - Safe scope extraction

### 1.3 - utils/db_utils.py
**Purpose**: Database and state management helpers

**Functions to extract**:
- `_audit_log_event()` - Write audit log entries
- `_audit_lifecycle()` - Audit lifecycle changes
- `_upsert_state()` - Upsert finding state
- `_upsert_group_state()` - Upsert group state
- `_finding_exists()` - Check finding existence
- `_fetch_finding_effective_state()` - Get effective state
- `_fetch_team()` - Get team by ID
- `_fetch_team_member()` - Get team member
- `_team_exists()` - Check team existence
- `_ensure_finding_governance_row()` - Ensure governance row
- `_fetch_governance_owner_team()` - Get owner team
- `_fetch_sla_policy_category()` - Get SLA policy
- `_fetch_sla_policy_override()` - Get SLA override
- `_fetch_governance_sla()` - Get governance SLA
- `_apply_finding_sla_extension()` - Apply SLA extension
- `_update_finding_owner()` - Update finding owner
- `_update_finding_team()` - Update finding team

### 1.4 - utils/openapi.py
**Purpose**: OpenAPI specification generation

**Functions to extract**:
- `_operation_summary_from_view()` - Extract operation summary
- `_openapi_security_for_path()` - Get security requirements
- `_build_openapi_spec()` - Build full OpenAPI spec

---

## Phase 2: Flask Blueprints

Create focused blueprints for each API domain:

### 2.1 - Blueprint: health
**Endpoints**:
- `GET /health` → health()
- `GET /api/health/db` → api_health_db()
- `GET /openapi.json` → api_openapi_public()
- `GET /api/openapi.json` → api_openapi_scoped()
- `GET /api/version` → api_version()

### 2.2 - Blueprint: runs
**Endpoints**:
- `GET /api/runs/latest` → api_runs_latest()
- `GET /api/runs/diff/latest` → api_runs_diff_latest()

### 2.3 - Blueprint: findings
**Endpoints**:
- `GET /api/findings` → api_findings()
- `GET /api/findings/sla/breached` → api_findings_sla_breached()
- `GET /api/findings/aging` → api_findings_aging()
- `GET /api/findings/aggregates` → api_findings_aggregates()
- `PUT /api/findings/<fingerprint>/owner` → api_findings_set_owner()
- `PUT /api/findings/<fingerprint>/team` → api_findings_set_team()
- `POST /api/findings/<fingerprint>/sla/extend` → api_findings_extend_sla()

### 2.4 - Blueprint: recommendations
**Endpoints**:
- `GET /api/recommendations` → api_recommendations()
- `GET /api/recommendations/composite` → api_recommendations_composite()
- `POST /api/recommendations/estimate` → api_recommendations_estimate()
- `POST /api/recommendations/preview` → api_recommendations_estimate()

**Helpers to extract**:
- `_build_recommendations_where_from_values()`
- `_build_recommendations_where()`
- `_recommendation_type_case_sql()`
- `_build_recommendation_item()`
- `_build_estimate_risk_warnings()`

### 2.5 - Blueprint: teams
**Endpoints**:
- `GET /api/teams` → api_teams()
- `POST /api/teams` → api_create_team()
- `PUT /api/teams/<team_id>` → api_update_team()
- `DELETE /api/teams/<team_id>` → api_delete_team()
- `GET /api/teams/<team_id>/members` → api_team_members()
- `POST /api/teams/<team_id>/members` → api_team_member_add()
- `DELETE /api/teams/<team_id>/members/<user_id>` → api_team_member_remove()

### 2.6 - Blueprint: sla_policies
**Endpoints**:
- `GET /api/sla/policies` → api_sla_policies()
- `POST /api/sla/policies` → api_create_sla_policy()
- `PUT /api/sla/policies/<category>` → api_update_sla_policy()
- `GET /api/sla/policies/overrides` → api_sla_overrides()
- `POST /api/sla/policies/overrides` → api_create_sla_override()

### 2.7 - Blueprint: lifecycle
**Endpoints**:
- `POST /api/lifecycle/group/ignore` → api_lifecycle_group_ignore()
- `POST /api/lifecycle/group/resolve` → api_lifecycle_group_resolve()
- `POST /api/lifecycle/group/snooze` → api_lifecycle_group_snooze()
- `POST /api/lifecycle/ignore` → api_lifecycle_ignore()
- `POST /api/lifecycle/resolve` → api_lifecycle_resolve()
- `POST /api/lifecycle/snooze` → api_lifecycle_snooze()

### 2.8 - Blueprint: groups
**Endpoints**:
- `GET /api/groups` → api_groups()
- `GET /api/groups/<group_key>` → api_group_detail()

### 2.9 - Blueprint: facets (or misc)
**Endpoints**:
- `GET /api/facets` → api_facets()
- `GET /api/audit` → api_audit()

---

## Phase 3: Main App Refactoring

### 3.1 - Update flask_app.py
After creating all blueprints, refactor `flask_app.py` to:

1. Import all blueprints from `apps.flask_api.blueprints`
2. Register each blueprint with `app.register_blueprint()`
3. Keep middleware hooks (`before_request`, `after_request`, `errorhandler`) in main app
4. Keep configuration (rate limiting, auth, schema gate)
5. Keep route aliases registration

### 3.2 - Middleware Organization
- **Rate limiting**: Keep in main app (applies globally)
- **Auth**: Keep in main app (applies globally)
- **Schema gate**: Keep in main app (applies globally)
- **Logging**: Keep in main app
- **Timer**: Keep in main app

---

## Phase 4: Testing

### 4.1 - Run existing tests
```bash
pytest tests/ -v
```

### 4.2 - Verify endpoints
- Manual or automated testing of all 39 endpoints

---

## Benefits of Refactoring

1. **Scalability**: New endpoints can be added to specific blueprints
2. **Maintainability**: Each module has focused responsibility
3. **Testability**: Blueprints can be tested in isolation
4. **Readability**: Easier to navigate and understand code
5. **Team collaboration**: Different team members can work on different blueprints
6. **Code reuse**: Shared utilities are properly extracted

---

## Migration Strategy

1. **Start with utilities** - Create `utils/` package first (no breaking changes)
2. **One blueprint at a time** - Create each blueprint, import helpers from utils
3. **Register incrementally** - Add each blueprint to main app as it's ready
4. **Remove from flask_app.py** - After blueprint is registered, remove original code
5. **Test after each change** - Ensure nothing breaks

---

## Files to Create/Modify

### New Files:
- `apps/flask_api/utils/__init__.py`
- `apps/flask_api/utils/responses.py`
- `apps/flask_api/utils/params.py`
- `apps/flask_api/utils/db_utils.py`
- `apps/flask_api/utils/openapi.py`
- `apps/flask_api/blueprints/__init__.py`
- `apps/flask_api/blueprints/health.py`
- `apps/flask_api/blueprints/runs.py`
- `apps/flask_api/blueprints/findings.py`
- `apps/flask_api/blueprints/recommendations.py`
- `apps/flask_api/blueprints/teams.py`
- `apps/flask_api/blueprints/sla_policies.py`
- `apps/flask_api/blueprints/lifecycle.py`
- `apps/flask_api/blueprints/groups.py`
- `apps/flask_api/blueprints/facets.py`

### Modified Files:
- `apps/flask_api/flask_app.py` - Refactor to use blueprints

---

## Estimated Work Items

1. Phase 1 (Utilities): ~4 blueprint files
2. Phase 2 (Blueprints): ~9 blueprint files  
3. Phase 3 (Main app): 1 refactored file
4. Phase 4 (Testing): Validation step

Total: ~14 new files + 1 modified file
