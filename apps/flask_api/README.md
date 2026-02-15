# Flask API

Modular Flask API for McKaySystem FinOps Analyzer.

## Architecture

The API is organized into **Flask Blueprints**, each handling a specific domain. This provides:
- **Modularity**: Each domain can be developed and tested independently
- **Maintainability**: Focused responsibility per module
- **Scalability**: Easy to add new endpoints without touching the main app

## Directory Structure

```
flask_api/
├── flask_app.py          # Main Flask application (registers blueprints)
├── blueprints/           # API endpoint modules
│   ├── __init__.py      # Blueprint imports and registration
│   ├── health.py        # Health check endpoints
│   ├── runs.py          # Run management endpoints
│   ├── findings.py      # Finding query endpoints
│   ├── recommendations.py # FinOps recommendation endpoints
│   ├── teams.py         # Team management endpoints
│   ├── sla_policies.py  # SLA policy endpoints
│   ├── lifecycle.py     # Finding lifecycle action endpoints
│   ├── groups.py        # Finding group endpoints
│   └── facets.py        # Facets and audit endpoints
├── utils/               # Shared utilities
│   ├── __init__.py      # Utility exports
│   ├── responses.py     # HTTP response helpers
│   ├── params.py        # Query/payload parameter parsing
│   └── payload.py       # Payload extraction helpers
└── templates/           # HTML templates (if any)
```

## Blueprints

| Blueprint | Endpoints | Description |
|-----------|-----------|-------------|
| `health` | 5 | Health checks, liveness, DB connectivity |
| `runs` | 2 | Latest run, diff between runs |
| `findings` | 4 | Finding queries, SLA breached, aging, aggregates |
| `recommendations` | 4 | FinOps recommendations, composite, estimate |
| `teams` | 7 | Team CRUD, member management |
| `sla_policies` | 5 | SLA policy category and override management |
| `lifecycle` | 6 | Finding ignore, resolve, snooze actions |
| `groups` | 2 | Finding groups and group detail |
| `facets` | 1 | Filter facets and audit log |

**Total: 39 endpoints across 9 blueprints**

## Running

```bash
# Development
FLASK_APP=flask_app.py flask run --host=0.0.0.0 --port=5000

# Production (with gunicorn)
gunicorn -w 4 -b 0.0.0.0:5000 apps.flask_api.flask_app:app
```

## Environment Variables

- `DB_URL` - PostgreSQL connection string (required)
- `API_VERSION` - API version prefix (default: v1)
- `API_BEARER_TOKEN` - Bearer token for authentication (optional)
- `PORT` - Server port (default: 5000)

## Utilities

### Response Helpers (`utils/responses.py`)
- `_ok(data)` - Return success response
- `_err(code, message, status)` - Return error response  
- `_json(data, status)` - Return JSON response

### Parameter Parsing (`utils/params.py`)
- `_q(name, default)` - Get query parameter
- `_require_scope_from_query()` - Extract tenant_id/workspace
- `_parse_int(value, default, min_v, max_v)` - Parse bounded integer
- `_parse_csv_list(value)` - Parse comma-separated list
- `_coerce_optional_text(value)` - Normalize optional text
- `_coerce_positive_int(value, field_name)` - Parse required positive integer

### Payload Helpers (`utils/payload.py`)
- `_as_float(value, default)` - Safe float conversion
- `_payload_dict(value)` - Normalize finding payload
- `_payload_estimated_confidence(payload)` - Extract confidence from payload
- `_payload_pricing_source(payload)` - Extract pricing source

## Adding a New Blueprint

1. Create `blueprints/new_feature.py`:
```python
from flask import Blueprint

new_feature_bp = Blueprint("new_feature", __name__)

@new_feature_bp.route("/api/new-feature", methods=["GET"])
def api_new_feature():
    return {"ok": True, "data": "..."}
```

2. Import and register in `flask_app.py`:
```python
from apps.flask_api.blueprints.new_feature import new_feature_bp
app.register_blueprint(new_feature_bp)
```

## Testing

```bash
# Import test
python -c "from apps.flask_api.flask_app import app; print('OK')"

# Run tests
pytest tests/ -v
```

## Migration from Monolithic

The original `flask_app.py` contained all endpoints in a single ~4100 line file. The migration to blueprints:

1. **Phase 1**: Created shared utilities in `utils/`
2. **Phase 2**: Created Blueprint structure
3. **Phase 3**: Migrated endpoints domain by domain
4. **Phase 4**: Registered all blueprints in main app

The legacy endpoint definitions remain in `flask_app.py` for backwards compatibility but are duplicated by the Blueprint implementations.
