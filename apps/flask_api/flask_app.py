"""flask_app.py

DB-backed API for McKaySystem (FinOpsAnalyzer).

This version intentionally avoids legacy JSON upload/export endpoints and treats
Postgres as the source of truth. The HTML UI is considered disposable; the API
is the contract.

Core concepts
-------------
- tenant_id + workspace scope every query.
- Read model is the Postgres view: finding_current.
- Lifecycle actions upsert into finding_state_current (workspace-scoped).

Env
---
- DB_URL (required) used by apps.backend.db

Run
---
FLASK_APP=flask_app.py flask run --host=0.0.0.0 --port=5000
"""

from __future__ import annotations

from collections.abc import Iterable
import hmac
import json
import logging
import os
import re
import threading
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from flask import Flask, Response, abort, jsonify, request
from werkzeug.exceptions import BadRequest

from apps.backend.db import (
    db_conn,
    execute_conn,
    fetch_all_dict_conn,
    fetch_one_dict_conn,
)

app = Flask(__name__)
_LOGGER = logging.getLogger(__name__)
_API_VERSION_RE = re.compile(r"^v(?P<major>\d+)$")


def _resolved_api_version() -> str:
    raw = (os.getenv("API_VERSION") or "v1").strip().lower()
    if _API_VERSION_RE.match(raw):
        return raw
    return "v1"


_API_VERSION = _resolved_api_version()
_API_PREFIX = f"/api/{_API_VERSION}"


def _canonical_api_path(path: str) -> str:
    """Normalize versioned API paths to canonical /api/* paths."""
    value = str(path or "")
    if not value.startswith("/api/"):
        return value
    m = re.match(r"^/api/v\d+(?P<rest>/.*|$)", value)
    if not m:
        return value
    rest = m.group("rest") or ""
    if not rest:
        return "/api"
    return f"/api{rest}"


def _rule_to_openapi_path(path: str) -> str:
    """Convert Flask route params (<id>, <int:id>) to OpenAPI style ({id})."""
    return re.sub(r"<(?:[^:>]+:)?([^>]+)>", r"{\1}", str(path or ""))


# --------------------
# Operational hardening
# --------------------
# Logging and rate limiting are intentionally lightweight (no extra deps).
# In hosted environments, prefer adding proper reverse-proxy/WAF rate limiting.

_API_DEBUG_ERRORS = (os.getenv("API_DEBUG_ERRORS") or "").strip() == "1"
_API_LOG_LEVEL = (os.getenv("API_LOG_LEVEL") or "INFO").strip().upper()

_RATE_LIMIT_RPS_RAW = (os.getenv("API_RATE_LIMIT_RPS") or "").strip()
_RATE_LIMIT_BURST_RAW = (os.getenv("API_RATE_LIMIT_BURST") or "").strip()


def _iso_z(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _log(level: str, event: str, fields: Dict[str, Any]) -> None:
    """Emit a single-line JSON log via the standard logging pipeline."""
    level_u = (level or "INFO").upper()
    order = {"ERROR": 3, "WARN": 2, "INFO": 1}
    if order.get(level_u, 1) < order.get(_API_LOG_LEVEL, 1):
        return
    payload: Dict[str, Any] = {"ts": _iso_z(_now_utc()), "level": level_u, "event": event}
    payload.update(fields)
    payload_json = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    if level_u == "ERROR":
        _LOGGER.error("%s", payload_json)
    elif level_u == "WARN":
        _LOGGER.warning("%s", payload_json)
    else:
        _LOGGER.info("%s", payload_json)


def _merge_vary_header(current: Optional[str], token: str) -> str:
    """Return a Vary header value that includes token exactly once."""
    items = [x.strip() for x in str(current or "").split(",") if x.strip()]
    token_norm = token.strip()
    if token_norm and token_norm.lower() not in {x.lower() for x in items}:
        items.append(token_norm)
    return ", ".join(items)


@app.before_request
def _start_timer() -> None:
    request.environ["_mckay_t0"] = time.monotonic()


def _safe_scope_from_request() -> Tuple[Optional[str], Optional[str]]:
    tenant_id = _q("tenant_id") or _q("tenant")
    workspace = _q("workspace")
    if tenant_id and workspace:
        return tenant_id, workspace
    try:
        if request.is_json:
            payload = request.get_json(silent=True) or {}
            t = payload.get("tenant_id") or payload.get("tenant")
            w = payload.get("workspace")
            if t and w:
                return str(t), str(w)
    except (BadRequest, TypeError, ValueError):
        pass
    return None, None


@app.after_request
def _log_request(resp: Response) -> Response:
    try:
        t0 = float(request.environ.get("_mckay_t0") or 0.0)
        ms = int(max(0.0, (time.monotonic() - t0) * 1000.0)) if t0 else None
        tenant_id, workspace = _safe_scope_from_request()
        _log(
            "INFO",
            "http_request",
            {
                "method": request.method,
                "path": request.path,
                "status": int(getattr(resp, "status_code", 0) or 0),
                "ms": ms,
                "ip": request.headers.get("X-Forwarded-For", request.remote_addr),
                "ua": request.headers.get("User-Agent", ""),
                "tenant_id": tenant_id,
                "workspace": workspace,
            },
        )
    except (RuntimeError, TypeError, ValueError) as exc:
        _LOGGER.debug("request logging skipped: %s", exc)

    # Findings/lifecycle data must never be served stale from intermediary caches.
    path = request.path or ""
    if path.startswith("/api/"):
        resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        resp.headers["Pragma"] = "no-cache"
        resp.headers["Expires"] = "0"
        resp.headers["Vary"] = _merge_vary_header(resp.headers.get("Vary"), "Authorization")
    return resp


class _TokenBucket:
    __slots__ = ("capacity", "tokens", "fill_rate", "last")

    def __init__(self, capacity: float, fill_rate: float) -> None:
        self.capacity = float(capacity)
        self.tokens = float(capacity)
        self.fill_rate = float(fill_rate)
        self.last = time.monotonic()

    def allow(self, cost: float = 1.0) -> bool:
        now = time.monotonic()
        elapsed = max(0.0, now - self.last)
        self.last = now
        self.tokens = min(self.capacity, self.tokens + elapsed * self.fill_rate)
        if self.tokens >= cost:
            self.tokens -= cost
            return True
        return False


_rate_lock = threading.Lock()
_rate_buckets: Dict[str, _TokenBucket] = {}
_schema_gate_lock = threading.Lock()
_schema_gate_checked = False
_schema_gate_enabled = (os.getenv("API_ENFORCE_SCHEMA_GATE") or "1").strip() != "0"


def _rate_limits() -> Tuple[Optional[float], Optional[float]]:
    if not _RATE_LIMIT_RPS_RAW:
        return None, None
    try:
        rps = float(_RATE_LIMIT_RPS_RAW)
    except ValueError:
        return None, None
    if rps <= 0:
        return None, None

    burst: Optional[float] = None
    if _RATE_LIMIT_BURST_RAW:
        try:
            burst = float(_RATE_LIMIT_BURST_RAW)
        except ValueError:
            burst = None
    if burst is None:
        burst = max(10.0, rps * 2.0)
    return rps, burst


def _rate_key() -> str:
    ip = request.headers.get("X-Forwarded-For", request.remote_addr) or "unknown"
    path = _canonical_api_path(request.path or "")
    if path.startswith("/api/lifecycle/"):
        group = "/api/lifecycle"
    elif path.startswith("/api/findings"):
        group = "/api/findings"
    elif path.startswith("/api/groups"):
        group = "/api/groups"
    elif path.startswith("/api/runs"):
        group = "/api/runs"
    else:
        group = "/api/other"
    return f"{ip}|{group}"


@app.before_request
def _enforce_rate_limit() -> None:
    path = _canonical_api_path(request.path or "")
    if not path.startswith("/api/"):
        return
    if path in {"/api/health/db"}:
        return

    rps, burst = _rate_limits()
    if rps is None or burst is None:
        return

    key = _rate_key()
    with _rate_lock:
        bucket = _rate_buckets.get(key)
        if bucket is None:
            bucket = _TokenBucket(capacity=burst, fill_rate=rps)
            _rate_buckets[key] = bucket
        allowed = bucket.allow(1.0)

    if not allowed:
        _log("WARN", "rate_limited", {"key": key, "path": path})
        abort(429)


def _ok(data: Optional[Dict[str, Any]] = None, *, status: int = 200) -> Any:
    payload: Dict[str, Any] = {"ok": True}
    if data:
        payload.update(data)
    return jsonify(payload), status


def _err(code: str, message: str, *, status: int, extra: Optional[Dict[str, Any]] = None) -> Any:
    payload: Dict[str, Any] = {"ok": False, "error": code, "message": message}
    if extra:
        payload.update(extra)
    return jsonify(payload), status


def _api_internal_error_response(exc: Exception) -> Any:
    """Map API internal errors to stable, route-specific response shapes."""
    path = _canonical_api_path(request.path or "")
    exc_text = str(exc)

    if path == "/api/health/db":
        if _API_DEBUG_ERRORS:
            return _err("db_unhealthy", "db health check failed", status=500, extra={"detail": exc_text})
        return _err("db_unhealthy", "db health check failed", status=500)

    if path == "/api/findings":
        extra = None
        if _API_DEBUG_ERRORS:
            extra = {"detail": exc_text, "traceback": traceback.format_exc()}
        return _err("internal_error", "internal error", status=500, extra=extra)

    if path in {
        "/api/findings/aggregates",
        "/api/facets",
        "/api/lifecycle/group/ignore",
        "/api/lifecycle/group/resolve",
        "/api/lifecycle/group/snooze",
        "/api/lifecycle/ignore",
        "/api/lifecycle/resolve",
        "/api/lifecycle/snooze",
    }:
        return jsonify({"error": "internal_error", "detail": exc_text}), 500

    if path in {"/api/runs/diff/latest", "/api/groups"} or path.startswith("/api/groups/"):
        return _json({"error": "internal_error", "message": exc_text}, status=500)

    return _err("internal_error", "internal error", status=500)


def _schema_migrations_dir() -> Path:
    """Return the repository-local migrations directory used by schema gate."""
    return Path(__file__).resolve().parents[2] / "migrations"


def _ensure_schema_gate() -> None:
    """Run DB schema gate once per process."""
    global _schema_gate_checked
    if not _schema_gate_enabled or _schema_gate_checked:
        return
    with _schema_gate_lock:
        if _schema_gate_checked:
            return
        from apps.backend.db_migrate import ensure_schema_current

        ensure_schema_current(migrations_dir=_schema_migrations_dir())
        _schema_gate_checked = True


@app.before_request
def _enforce_schema_gate() -> Optional[Any]:
    """Return 503 if the DB schema is behind local code migrations."""
    path = _canonical_api_path(request.path or "")
    if not path.startswith("/api/"):
        return None
    if path in {"/api/health/db"}:
        return None
    try:
        _ensure_schema_gate()
    except RuntimeError as exc:
        _log("ERROR", "schema_gate_failed", {"detail": str(exc)})
        return _err("schema_mismatch", str(exc), status=503)
    return None


@app.errorhandler(429)
def _err_429(_: Exception) -> Any:
    return _err("rate_limited", "too many requests", status=429)


@app.errorhandler(500)
def _err_500(exc: Exception) -> Any:
    root_exc = getattr(exc, "original_exception", None) or exc
    tb = traceback.format_exc()
    fields: Dict[str, Any] = {"path": request.path, "detail": str(root_exc)}
    if _API_DEBUG_ERRORS:
        fields["traceback"] = tb
    _log("ERROR", "unhandled_exception", fields)
    return _api_internal_error_response(root_exc)

# --------------------
# Auth (Bearer token)
# --------------------

# If API_BEARER_TOKEN is unset/empty, authentication is disabled (useful for
# local dev). In hosted environments, set it to require:
#   Authorization: Bearer <token>
_API_BEARER_TOKEN = (os.getenv("API_BEARER_TOKEN") or "").strip()


def _is_auth_required() -> bool:
    return bool(_API_BEARER_TOKEN)


def _check_bearer_token() -> None:
    """Abort the request if the bearer token is missing/invalid."""
    if not _is_auth_required():
        return

    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        abort(401)

    token = auth[len("Bearer ") :].strip()
    # constant-time comparison
    if not hmac.compare_digest(token, _API_BEARER_TOKEN):
        abort(403)


@app.before_request
def _enforce_api_auth() -> None:
    """Enforce bearer auth for API routes.

    - /health remains public.
    - /api/health/db remains public (useful for platform health checks).
    - All other /api/* routes require Authorization: Bearer ... when
      API_BEARER_TOKEN is set.
    """
    path = _canonical_api_path(request.path or "")
    if not path.startswith("/api/"):
        return
    if path in {"/api/health/db"}:
        return
    _check_bearer_token()


# --------------------
# OpenAPI + API versioning
# --------------------

_OPENAPI_EXCLUDED_CANONICAL_PATHS = {"/api/openapi.json"}


def _operation_summary_from_view(view_func: Any, method: str, path: str) -> str:
    doc = str(getattr(view_func, "__doc__", "") or "").strip()
    if doc:
        return doc.splitlines()[0].strip()
    clean = path.strip("/").replace("/", " ")
    return f"{method.upper()} {clean or 'root'}"


def _openapi_security_for_path(path: str) -> list[dict[str, list[str]]]:
    # Keep health + OpenAPI discovery unauthenticated in docs.
    if path in {"/api/health/db", "/api/openapi.json"}:
        return []
    return [{"bearerAuth": []}]


def _build_openapi_spec() -> Dict[str, Any]:
    """Build OpenAPI 3.0 spec from registered Flask API routes."""
    paths: Dict[str, Dict[str, Any]] = {}
    seen_ops: Set[Tuple[str, str]] = set()

    for rule in app.url_map.iter_rules():
        if rule.endpoint == "static":
            continue

        canonical = _canonical_api_path(str(rule.rule or ""))
        if not canonical.startswith("/api/"):
            continue
        if canonical in _OPENAPI_EXCLUDED_CANONICAL_PATHS:
            continue

        subpath = canonical[len("/api") :] or "/"
        openapi_path = _rule_to_openapi_path(subpath)

        raw_methods = set(rule.methods or set())
        methods = sorted(m.lower() for m in raw_methods if m not in {"HEAD", "OPTIONS"})
        if not methods:
            continue

        view_func = app.view_functions.get(rule.endpoint)
        if view_func is None:
            continue

        path_item = paths.setdefault(openapi_path, {})
        for method in methods:
            op_key = (openapi_path, method)
            if op_key in seen_ops:
                continue
            seen_ops.add(op_key)

            method_u = method.upper()
            parameters: List[Dict[str, Any]] = []
            for arg in sorted(rule.arguments):
                parameters.append(
                    {
                        "name": arg,
                        "in": "path",
                        "required": True,
                        "schema": {"type": "string"},
                    }
                )

            operation: Dict[str, Any] = {
                "operationId": f"{rule.endpoint.replace('.', '_')}_{method}",
                "summary": _operation_summary_from_view(view_func, method_u, openapi_path),
                "tags": [openapi_path.strip("/").split("/", 1)[0] or "root"],
                "parameters": parameters,
                "responses": {
                    "200": {"description": "Successful response"},
                    "400": {"description": "Bad request"},
                    "500": {"description": "Internal server error"},
                },
                "security": _openapi_security_for_path(canonical),
            }
            if method in {"post", "put", "patch"}:
                operation["requestBody"] = {
                    "required": False,
                    "content": {
                        "application/json": {
                            "schema": {"type": "object"},
                        }
                    },
                }
            path_item[method] = operation

    return {
        "openapi": "3.0.3",
        "info": {
            "title": "McKaySystem API",
            "version": _API_VERSION,
            "description": "Generated from Flask routes; versioned and legacy API bases are both supported.",
        },
        "servers": [
            {"url": _API_PREFIX, "description": f"Versioned API base ({_API_VERSION})"},
            {"url": "/api", "description": "Legacy API base (compatibility)"},
        ],
        "paths": dict(sorted(paths.items(), key=lambda kv: kv[0])),
        "components": {
            "securitySchemes": {
                "bearerAuth": {
                    "type": "http",
                    "scheme": "bearer",
                    "bearerFormat": "token",
                }
            }
        },
    }


@app.get("/openapi.json")
def api_openapi_public() -> Any:
    """OpenAPI 3.0 specification (public endpoint)."""
    return _json(_build_openapi_spec())


@app.get("/api/openapi.json")
def api_openapi_scoped() -> Any:
    """OpenAPI 3.0 specification under API base."""
    return _json(_build_openapi_spec())


@app.get("/api/version")
def api_version() -> Any:
    """API version metadata and supported versions."""
    return _json(
        {
            "version": _API_VERSION,
            "prefix": _API_PREFIX,
            "supported_versions": [_API_VERSION],
            "legacy_prefix": "/api",
        }
    )


# --------------------
# Small parsing helpers
# --------------------

def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _q(name: str, default: Optional[str] = None) -> Optional[str]:
    v = request.args.get(name)
    if v is None or v == "":
        return default
    return v


def _require_scope_from_query() -> Tuple[str, str]:
    tenant_id = _q("tenant_id") or _q("tenant") or ""
    workspace = _q("workspace") or ""
    if not tenant_id or not workspace:
        raise ValueError("tenant_id and workspace are required")
    return tenant_id, workspace


def _require_scope_from_json(payload: Dict[str, Any]) -> Tuple[str, str]:
    tenant_id = str(payload.get("tenant_id") or payload.get("tenant") or "").strip()
    workspace = str(payload.get("workspace") or "").strip()
    if not tenant_id or not workspace:
        raise ValueError("tenant_id and workspace are required")
    return tenant_id, workspace


def _parse_int(value: Optional[str], *, default: int, min_v: int, max_v: int) -> int:
    if value is None or value == "":
        return default
    try:
        n = int(value)
    except ValueError as exc:
        raise ValueError(f"Invalid integer: {value}") from exc
    return max(min_v, min(max_v, n))


def _parse_csv_list(value: Optional[str]) -> Optional[List[str]]:
    if not value:
        return None
    items = [x.strip() for x in value.split(",") if x.strip()]
    return items or None


def _json(payload: Dict[str, Any], *, status: int = 200) -> Any:
    """Return a JSON response with an explicit status code.

    Backward-compatible helper. If 'ok' is missing, it is inferred from status.
    Prefer using _ok() / _err() for new code.
    """
    if "ok" not in payload:
        payload = dict(payload)
        payload["ok"] = status < 400
    return jsonify(payload), status


def _parse_iso8601_dt(value: Optional[str], *, field_name: str = "timestamp") -> Optional[datetime]:
    """Parse an ISO-8601 timestamp (accepts trailing 'Z') into an aware UTC datetime."""
    if value is None:
        return None
    s = str(value).strip()
    if not s:
        return None
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"Invalid {field_name} (expected ISO-8601): {s!r}") from exc
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


_MISSING = object()


def _coerce_optional_text(value: Any) -> Optional[str]:
    """Normalize optional API text values to trimmed strings or None."""
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _payload_optional_text(payload: Dict[str, Any], key: str) -> Any:
    """Return normalized payload value for a key or _MISSING when absent."""
    if key not in payload:
        return _MISSING
    return _coerce_optional_text(payload.get(key))


def _coerce_positive_int(value: Any, *, field_name: str) -> int:
    """Parse a required positive integer field from JSON payload data."""
    try:
        n = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field_name} must be an integer") from exc
    if n <= 0:
        raise ValueError(f"{field_name} must be > 0")
    return n

# --------------------
# Health / meta routes
# --------------------

@app.get("/health")
def health() -> Any:
    return jsonify({"ok": True})


@app.get("/api/health/db")
def api_health_db() -> Any:
    with db_conn() as conn:
        row = fetch_one_dict_conn(conn, "SELECT 1 AS ok")
    return _ok({"db": bool(row and row.get("ok") == 1)})


# --------------------
# Runs
# --------------------

@app.get("/api/runs/latest")
def api_runs_latest() -> Any:
    try:
        tenant_id, workspace = _require_scope_from_query()
        with db_conn() as conn:
            row = fetch_one_dict_conn(
                conn,
                """
                SELECT tenant_id, workspace, run_id, run_ts, status, artifact_prefix,
                       ingested_at, engine_version,
                       raw_present, correlated_present, enriched_present
                FROM runs
                WHERE tenant_id = %s AND workspace = %s
                ORDER BY run_ts DESC
                LIMIT 1
                """,
                (tenant_id, workspace),
            )
        return jsonify({"tenant_id": tenant_id, "workspace": workspace, "run": row})
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400



@app.get("/api/runs/diff/latest")
def api_runs_diff_latest() -> Any:
    """Compute a best-effort diff between the latest two *ready* runs.

    Returns counts for:
    - new: fingerprints present in latest run but not in previous
    - disappeared: fingerprints present in previous run but not in latest

    Notes:
    - Uses finding_presence for membership (history).
    - Attributes category/check_id/service from finding_current (canonical read model).
    """
    try:
        tenant_id, workspace = _require_scope_from_query()
        with db_conn() as conn:
            runs = fetch_all_dict_conn(
                conn,
                """
                SELECT run_id, run_ts
                FROM runs
                WHERE tenant_id=%s AND workspace=%s AND status='ready'
                ORDER BY run_ts DESC
                LIMIT 2
                """,
                (tenant_id, workspace),
            )

            if not runs or len(runs) < 2:
                return _json(
                    {
                        "tenant_id": tenant_id,
                        "workspace": workspace,
                        "ok": True,
                        "message": "Need at least 2 ready runs to compute a diff.",
                        "runs": runs or [],
                        "new": {"count": 0, "by_category": {}, "by_check_id": {}, "by_service": {}},
                        "disappeared": {"count": 0, "by_category": {}, "by_check_id": {}, "by_service": {}},
                    }
                )

            run_new = str(runs[0]["run_id"])
            run_old = str(runs[1]["run_id"])

            new_rows = fetch_all_dict_conn(
                conn,
                """
                WITH new_fps AS (
                  SELECT p1.fingerprint
                  FROM finding_presence p1
                  WHERE p1.tenant_id=%s AND p1.workspace=%s AND p1.run_id=%s
                  EXCEPT
                  SELECT p0.fingerprint
                  FROM finding_presence p0
                  WHERE p0.tenant_id=%s AND p0.workspace=%s AND p0.run_id=%s
                )
                SELECT
                  COALESCE(fc.category, 'other') AS category,
                  COALESCE(fc.check_id, 'unknown') AS check_id,
                  COALESCE(fc.service, 'unknown') AS service,
                  COUNT(*)::bigint AS count
                FROM new_fps nf
                LEFT JOIN finding_current fc
                  ON fc.tenant_id=%s AND fc.workspace=%s AND fc.fingerprint=nf.fingerprint
                GROUP BY 1,2,3
                """,
                (tenant_id, workspace, run_new, tenant_id, workspace, run_old, tenant_id, workspace),
            )

            gone_rows = fetch_all_dict_conn(
                conn,
                """
                WITH gone_fps AS (
                  SELECT p0.fingerprint
                  FROM finding_presence p0
                  WHERE p0.tenant_id=%s AND p0.workspace=%s AND p0.run_id=%s
                  EXCEPT
                  SELECT p1.fingerprint
                  FROM finding_presence p1
                  WHERE p1.tenant_id=%s AND p1.workspace=%s AND p1.run_id=%s
                )
                SELECT
                  COALESCE(fc.category, 'other') AS category,
                  COALESCE(fc.check_id, 'unknown') AS check_id,
                  COALESCE(fc.service, 'unknown') AS service,
                  COUNT(*)::bigint AS count
                FROM gone_fps gf
                LEFT JOIN finding_current fc
                  ON fc.tenant_id=%s AND fc.workspace=%s AND fc.fingerprint=gf.fingerprint
                GROUP BY 1,2,3
                """,
                (tenant_id, workspace, run_old, tenant_id, workspace, run_new, tenant_id, workspace),
            )

        def _rollup(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
            total = 0
            by_cat: Dict[str, int] = {}
            by_check: Dict[str, int] = {}
            by_svc: Dict[str, int] = {}
            for r in rows:
                c = int(r.get("count") or 0)
                total += c
                cat = str(r.get("category") or "other")
                chk = str(r.get("check_id") or "unknown")
                svc = str(r.get("service") or "unknown")
                by_cat[cat] = by_cat.get(cat, 0) + c
                by_check[chk] = by_check.get(chk, 0) + c
                by_svc[svc] = by_svc.get(svc, 0) + c
            return {"count": total, "by_category": by_cat, "by_check_id": by_check, "by_service": by_svc, "rows": rows}

        return _json(
            {
                "tenant_id": tenant_id,
                "workspace": workspace,
                "ok": True,
                "runs": [
                    {"run_id": run_new, "run_ts": runs[0]["run_ts"]},
                    {"run_id": run_old, "run_ts": runs[1]["run_ts"]},
                ],
                "new": _rollup(new_rows),
                "disappeared": _rollup(gone_rows),
            }
        )
    except ValueError as exc:
        return _json({"error": "bad_request", "message": str(exc)}, status=400)

# --------------------
# Findings (canonical)
# --------------------

@app.get("/api/findings")
def api_findings() -> Any:
    try:
        tenant_id, workspace = _require_scope_from_query()

        limit = _parse_int(_q("limit"), default=100, min_v=1, max_v=1000)
        offset = _parse_int(_q("offset"), default=0, min_v=0, max_v=5_000_000)

        # Filters
        effective_states = _parse_csv_list(_q("state"))  # open, snoozed, ignored, resolved
        severities = _parse_csv_list(_q("severity"))
        services = _parse_csv_list(_q("service"))
        check_ids = _parse_csv_list(_q("check_id"))
        categories = _parse_csv_list(_q("category"))
        regions = _parse_csv_list(_q("region"))
        account_ids = _parse_csv_list(_q("account_id"))
        team_ids = _parse_csv_list(_q("team_id"))
        owner_emails = _parse_csv_list(_q("owner_email"))
        sla_statuses = _parse_csv_list(_q("sla_status"))
        query_str = _q("q")  # substring match on title

        order = (_q("order", "savings_desc") or "savings_desc").lower()
        if order not in {"savings_desc", "detected_desc"}:
            raise ValueError("order must be 'savings_desc' or 'detected_desc'")

        where = ["tenant_id = %s", "workspace = %s"]
        params: List[Any] = [tenant_id, workspace]

        def _add_any(field: str, values: Optional[List[str]]) -> None:
            if not values:
                return
            where.append(f"{field} = ANY(%s)")
            params.append(values)

        _add_any("effective_state", effective_states)
        _add_any("severity", severities)
        _add_any("service", services)
        _add_any("check_id", check_ids)
        _add_any("category", categories)
        _add_any("region", regions)
        _add_any("account_id", account_ids)
        _add_any("team_id", team_ids)
        _add_any("owner_email", owner_emails)
        _add_any("sla_status", sla_statuses)

        if query_str:
            where.append("title ILIKE %s")
            params.append(f"%{query_str}%")

        order_sql = (
            "estimated_monthly_savings DESC NULLS LAST, detected_at DESC"
            if order == "savings_desc"
            else "detected_at DESC"
        )

        sql = f"""
            SELECT
              tenant_id, workspace, fingerprint, run_id,
              check_id, service, severity, title,
              estimated_monthly_savings, region, account_id,
              category, group_key,
              detected_at,
              state, snooze_until, reason, effective_state,
              first_detected_at, first_opened_at,
              owner_id, owner_email, owner_name, team_id,
              sla_deadline, sla_paused_at, sla_total_paused_seconds,
              sla_breached_at, sla_extended_count,
              age_days_open, age_days_detected,
              sla_status, sla_days_remaining,
              payload
            FROM finding_current
            WHERE {' AND '.join(where)}
            ORDER BY {order_sql}
            LIMIT %s OFFSET %s
        """
        params2 = params + [limit, offset]

        with db_conn() as conn:
            rows = fetch_all_dict_conn(conn, sql, params2)
            count_row = fetch_one_dict_conn(
                conn,
                f"SELECT COUNT(*) AS n FROM finding_current WHERE {' AND '.join(where)}",
                params,
            )

        return _ok(
            {
                "tenant_id": tenant_id,
                "workspace": workspace,
                "limit": limit,
                "offset": offset,
                "total": int((count_row or {}).get("n") or 0),
                "items": rows,
            }
        )
    except ValueError as exc:
        return _err("bad_request", str(exc), status=400)


@app.get("/api/findings/sla/breached")
def api_findings_sla_breached() -> Any:
    """List findings currently in breached SLA state."""
    try:
        tenant_id, workspace = _require_scope_from_query()
        limit = _parse_int(_q("limit"), default=100, min_v=1, max_v=1000)
        offset = _parse_int(_q("offset"), default=0, min_v=0, max_v=5_000_000)

        severities = _parse_csv_list(_q("severity"))
        services = _parse_csv_list(_q("service"))
        check_ids = _parse_csv_list(_q("check_id"))
        categories = _parse_csv_list(_q("category"))
        regions = _parse_csv_list(_q("region"))
        account_ids = _parse_csv_list(_q("account_id"))
        team_ids = _parse_csv_list(_q("team_id"))
        owner_emails = _parse_csv_list(_q("owner_email"))
        query_str = _q("q")

        where = ["tenant_id = %s", "workspace = %s", "sla_status = 'breached'"]
        params: List[Any] = [tenant_id, workspace]

        def _add_any(field: str, values: Optional[List[str]]) -> None:
            if not values:
                return
            where.append(f"{field} = ANY(%s)")
            params.append(values)

        _add_any("severity", severities)
        _add_any("service", services)
        _add_any("check_id", check_ids)
        _add_any("category", categories)
        _add_any("region", regions)
        _add_any("account_id", account_ids)
        _add_any("team_id", team_ids)
        _add_any("owner_email", owner_emails)

        if query_str:
            where.append("title ILIKE %s")
            params.append(f"%{query_str}%")

        sql = f"""
            SELECT
              tenant_id, workspace, fingerprint, run_id,
              check_id, service, severity, title,
              estimated_monthly_savings, region, account_id,
              category, group_key,
              detected_at,
              state, snooze_until, reason, effective_state,
              first_detected_at, first_opened_at,
              owner_id, owner_email, owner_name, team_id,
              sla_deadline, sla_paused_at, sla_total_paused_seconds,
              sla_extension_seconds, sla_breached_at, sla_extended_count,
              age_days_open, age_days_detected,
              sla_status, sla_days_remaining,
              payload
            FROM finding_current
            WHERE {' AND '.join(where)}
            ORDER BY sla_deadline ASC NULLS LAST, detected_at DESC
            LIMIT %s OFFSET %s
        """
        params2 = params + [limit, offset]

        with db_conn() as conn:
            rows = fetch_all_dict_conn(conn, sql, params2)
            count_row = fetch_one_dict_conn(
                conn,
                f"SELECT COUNT(*) AS n FROM finding_current WHERE {' AND '.join(where)}",
                params,
            )

        return _ok(
            {
                "tenant_id": tenant_id,
                "workspace": workspace,
                "limit": limit,
                "offset": offset,
                "total": int((count_row or {}).get("n") or 0),
                "items": rows,
            }
        )
    except ValueError as exc:
        return _err("bad_request", str(exc), status=400)


@app.get("/api/findings/aging")
def api_findings_aging() -> Any:
    """List findings filtered by aging clock (open or detected age)."""
    try:
        tenant_id, workspace = _require_scope_from_query()
        limit = _parse_int(_q("limit"), default=100, min_v=1, max_v=1000)
        offset = _parse_int(_q("offset"), default=0, min_v=0, max_v=5_000_000)

        age_basis = (_q("age_basis", "open") or "open").strip().lower()
        if age_basis not in {"open", "detected"}:
            raise ValueError("age_basis must be 'open' or 'detected'")
        age_col = "age_days_open" if age_basis == "open" else "age_days_detected"

        min_days = _parse_int(_q("min_days"), default=0, min_v=0, max_v=36500)
        max_days_raw = _q("max_days")
        max_days: Optional[int] = None
        if max_days_raw is not None and max_days_raw != "":
            max_days = _parse_int(max_days_raw, default=0, min_v=0, max_v=36500)
            if max_days < min_days:
                raise ValueError("max_days must be >= min_days")

        effective_states = _parse_csv_list(_q("state"))
        severities = _parse_csv_list(_q("severity"))
        services = _parse_csv_list(_q("service"))
        check_ids = _parse_csv_list(_q("check_id"))
        categories = _parse_csv_list(_q("category"))
        regions = _parse_csv_list(_q("region"))
        account_ids = _parse_csv_list(_q("account_id"))
        team_ids = _parse_csv_list(_q("team_id"))
        owner_emails = _parse_csv_list(_q("owner_email"))
        sla_statuses = _parse_csv_list(_q("sla_status"))
        query_str = _q("q")

        where = ["tenant_id = %s", "workspace = %s", f"{age_col} IS NOT NULL", f"{age_col} >= %s"]
        params: List[Any] = [tenant_id, workspace, min_days]

        if max_days is not None:
            where.append(f"{age_col} <= %s")
            params.append(max_days)

        def _add_any(field: str, values: Optional[List[str]]) -> None:
            if not values:
                return
            where.append(f"{field} = ANY(%s)")
            params.append(values)

        _add_any("effective_state", effective_states)
        _add_any("severity", severities)
        _add_any("service", services)
        _add_any("check_id", check_ids)
        _add_any("category", categories)
        _add_any("region", regions)
        _add_any("account_id", account_ids)
        _add_any("team_id", team_ids)
        _add_any("owner_email", owner_emails)
        _add_any("sla_status", sla_statuses)

        if query_str:
            where.append("title ILIKE %s")
            params.append(f"%{query_str}%")

        sql = f"""
            SELECT
              tenant_id, workspace, fingerprint, run_id,
              check_id, service, severity, title,
              estimated_monthly_savings, region, account_id,
              category, group_key,
              detected_at,
              state, snooze_until, reason, effective_state,
              first_detected_at, first_opened_at,
              owner_id, owner_email, owner_name, team_id,
              sla_deadline, sla_paused_at, sla_total_paused_seconds,
              sla_extension_seconds, sla_breached_at, sla_extended_count,
              age_days_open, age_days_detected,
              {age_col} AS age_days,
              sla_status, sla_days_remaining,
              payload
            FROM finding_current
            WHERE {' AND '.join(where)}
            ORDER BY {age_col} DESC, detected_at DESC
            LIMIT %s OFFSET %s
        """
        params2 = params + [limit, offset]

        with db_conn() as conn:
            rows = fetch_all_dict_conn(conn, sql, params2)
            count_row = fetch_one_dict_conn(
                conn,
                f"SELECT COUNT(*) AS n FROM finding_current WHERE {' AND '.join(where)}",
                params,
            )

        return _ok(
            {
                "tenant_id": tenant_id,
                "workspace": workspace,
                "age_basis": age_basis,
                "min_days": min_days,
                "max_days": max_days,
                "limit": limit,
                "offset": offset,
                "total": int((count_row or {}).get("n") or 0),
                "items": rows,
            }
        )
    except ValueError as exc:
        return _err("bad_request", str(exc), status=400)


@app.get("/api/findings/aggregates")
def api_findings_aggregates() -> Any:
    """Aggregations for building dashboards/filters without loading all findings."""
    try:
        tenant_id, workspace = _require_scope_from_query()
        with db_conn() as conn:
            by_state = fetch_all_dict_conn(
                conn,
                """
                SELECT effective_state AS key,
                       COUNT(*)::bigint AS count,
                       COALESCE(SUM(estimated_monthly_savings), 0)::double precision AS savings
                FROM finding_current
                WHERE tenant_id = %s AND workspace = %s
                GROUP BY effective_state
                ORDER BY count DESC
                """,
                (tenant_id, workspace),
            )
            by_severity = fetch_all_dict_conn(
                conn,
                """
                SELECT severity AS key,
                       COUNT(*)::bigint AS count,
                       COALESCE(SUM(estimated_monthly_savings), 0)::double precision AS savings
                FROM finding_current
                WHERE tenant_id = %s AND workspace = %s
                GROUP BY severity
                ORDER BY count DESC
                """,
                (tenant_id, workspace),
            )
            by_service = fetch_all_dict_conn(
                conn,
                """
                SELECT service AS key,
                       COUNT(*)::bigint AS count,
                       COALESCE(SUM(estimated_monthly_savings), 0)::double precision AS savings
                FROM finding_current
                WHERE tenant_id = %s AND workspace = %s
                GROUP BY service
                ORDER BY savings DESC NULLS LAST
                LIMIT 50
                """,
                (tenant_id, workspace),
            )
        return jsonify(
            {
                "tenant_id": tenant_id,
                "workspace": workspace,
                "by_state": by_state,
                "by_severity": by_severity,
                "by_service": by_service,
            }
        )
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400


@app.get("/api/facets")
def api_facets() -> Any:
    """Return distinct values (with counts) for common filters."""
    try:
        tenant_id, workspace = _require_scope_from_query()
        with db_conn() as conn:
            services = fetch_all_dict_conn(
                conn,
                """
                SELECT service AS value, COUNT(*)::bigint AS count
                FROM finding_current
                WHERE tenant_id=%s AND workspace=%s AND service IS NOT NULL
                GROUP BY service
                ORDER BY count DESC
                """,
                (tenant_id, workspace),
            )
            regions = fetch_all_dict_conn(
                conn,
                """
                SELECT region AS value, COUNT(*)::bigint AS count
                FROM finding_current
                WHERE tenant_id=%s AND workspace=%s AND region IS NOT NULL
                GROUP BY region
                ORDER BY count DESC
                """,
                (tenant_id, workspace),
            )
            severities = fetch_all_dict_conn(
                conn,
                """
                SELECT severity AS value, COUNT(*)::bigint AS count
                FROM finding_current
                WHERE tenant_id=%s AND workspace=%s AND severity IS NOT NULL
                GROUP BY severity
                ORDER BY count DESC
                """,
                (tenant_id, workspace),
            )
            states = fetch_all_dict_conn(
                conn,
                """
                SELECT effective_state AS value, COUNT(*)::bigint AS count
                FROM finding_current
                WHERE tenant_id=%s AND workspace=%s
                GROUP BY effective_state
                ORDER BY count DESC
                """,
                (tenant_id, workspace),
            )

        return jsonify(
            {
                "tenant_id": tenant_id,
                "workspace": workspace,
                "services": services,
                "regions": regions,
                "severities": severities,
                "states": states,
            }
        )
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400


@app.get("/api/audit")
def api_audit() -> Any:
    """Query append-only governance audit events."""
    try:
        tenant_id, workspace = _require_scope_from_query()
        limit = _parse_int(_q("limit"), default=100, min_v=1, max_v=1000)
        offset = _parse_int(_q("offset"), default=0, min_v=0, max_v=5_000_000)

        where = ["tenant_id = %s", "workspace = %s"]
        params: List[Any] = [tenant_id, workspace]

        entity_type = _coerce_optional_text(_q("entity_type"))
        entity_id = _coerce_optional_text(_q("entity_id"))
        fingerprint = _coerce_optional_text(_q("fingerprint"))
        event_type = _coerce_optional_text(_q("event_type"))
        event_category = _coerce_optional_text(_q("event_category"))
        actor_email = _coerce_optional_text(_q("actor_email"))
        correlation_id = _coerce_optional_text(_q("correlation_id"))

        if entity_type:
            where.append("entity_type = %s")
            params.append(entity_type)
        if entity_id:
            where.append("entity_id = %s")
            params.append(entity_id)
        if fingerprint:
            where.append("fingerprint = %s")
            params.append(fingerprint)
        if event_type:
            where.append("event_type = %s")
            params.append(event_type)
        if event_category:
            where.append("event_category = %s")
            params.append(event_category)
        if actor_email:
            where.append("actor_email = %s")
            params.append(actor_email)
        if correlation_id:
            where.append("correlation_id = %s")
            params.append(correlation_id)

        with db_conn() as conn:
            rows = fetch_all_dict_conn(
                conn,
                f"""
                SELECT
                  id,
                  tenant_id,
                  workspace,
                  entity_type,
                  entity_id,
                  fingerprint,
                  event_type,
                  event_category,
                  previous_value,
                  new_value,
                  actor_id,
                  actor_email,
                  actor_name,
                  source,
                  ip_address,
                  user_agent,
                  run_id,
                  correlation_id,
                  created_at
                FROM audit_log
                WHERE {' AND '.join(where)}
                ORDER BY id DESC
                LIMIT %s OFFSET %s
                """,
                params + [limit, offset],
            )
            count_row = fetch_one_dict_conn(
                conn,
                f"SELECT COUNT(*)::bigint AS n FROM audit_log WHERE {' AND '.join(where)}",
                params,
            )

        return _ok(
            {
                "tenant_id": tenant_id,
                "workspace": workspace,
                "limit": limit,
                "offset": offset,
                "total": int((count_row or {}).get("n") or 0),
                "items": rows,
            }
        )
    except ValueError as exc:
        return _err("bad_request", str(exc), status=400)


# --------------------
# Governance: Teams
# --------------------


@app.get("/api/teams")
def api_teams() -> Any:
    """List teams in tenant/workspace scope."""
    try:
        tenant_id, workspace = _require_scope_from_query()
        limit = _parse_int(_q("limit"), default=100, min_v=1, max_v=1000)
        offset = _parse_int(_q("offset"), default=0, min_v=0, max_v=5_000_000)
        query_str = _q("q")

        where = ["t.tenant_id = %s", "t.workspace = %s"]
        params: List[Any] = [tenant_id, workspace]
        if query_str:
            where.append("(t.team_id ILIKE %s OR t.name ILIKE %s)")
            params.extend([f"%{query_str}%", f"%{query_str}%"])

        with db_conn() as conn:
            rows = fetch_all_dict_conn(
                conn,
                f"""
                SELECT
                  t.tenant_id,
                  t.workspace,
                  t.team_id,
                  t.name,
                  t.description,
                  t.parent_team_id,
                  t.created_at,
                  t.updated_at,
                  COUNT(tm.user_id)::bigint AS member_count
                FROM teams t
                LEFT JOIN team_members tm
                  ON tm.tenant_id = t.tenant_id
                  AND tm.workspace = t.workspace
                  AND tm.team_id = t.team_id
                WHERE {' AND '.join(where)}
                GROUP BY
                  t.tenant_id,
                  t.workspace,
                  t.team_id,
                  t.name,
                  t.description,
                  t.parent_team_id,
                  t.created_at,
                  t.updated_at
                ORDER BY t.name ASC, t.team_id ASC
                LIMIT %s OFFSET %s
                """,
                params + [limit, offset],
            )
            count_row = fetch_one_dict_conn(
                conn,
                f"SELECT COUNT(*)::bigint AS n FROM teams t WHERE {' AND '.join(where)}",
                params,
            )

        return _ok(
            {
                "tenant_id": tenant_id,
                "workspace": workspace,
                "limit": limit,
                "offset": offset,
                "total": int((count_row or {}).get("n") or 0),
                "items": rows,
            }
        )
    except ValueError as exc:
        return _err("bad_request", str(exc), status=400)


@app.post("/api/teams")
def api_create_team() -> Any:
    """Create a team in tenant/workspace scope."""
    try:
        payload = request.get_json(force=True, silent=False) or {}
        tenant_id, workspace = _require_scope_from_json(payload)
        team_id = _coerce_optional_text(payload.get("team_id"))
        name = _coerce_optional_text(payload.get("name"))
        description_v = _payload_optional_text(payload, "description")
        parent_team_id_v = _payload_optional_text(payload, "parent_team_id")
        updated_by = _coerce_optional_text(payload.get("updated_by"))

        if not team_id:
            raise ValueError("team_id is required")
        if not name:
            raise ValueError("name is required")

        description = None if description_v is _MISSING else description_v
        parent_team_id = None if parent_team_id_v is _MISSING else parent_team_id_v

        if parent_team_id == team_id:
            raise ValueError("parent_team_id cannot equal team_id")

        with db_conn() as conn:
            if parent_team_id is not None and not _team_exists(
                conn, tenant_id=tenant_id, workspace=workspace, team_id=parent_team_id
            ):
                return _err("not_found", f"parent team not found: {parent_team_id}", status=404)
            if _team_exists(conn, tenant_id=tenant_id, workspace=workspace, team_id=team_id):
                return _err("conflict", f"team already exists: {team_id}", status=409)

            execute_conn(
                conn,
                """
                INSERT INTO teams
                  (tenant_id, workspace, team_id, name, description, parent_team_id, created_at, updated_at)
                VALUES
                  (%s, %s, %s, %s, %s, %s, now(), now())
                """,
                (tenant_id, workspace, team_id, name, description, parent_team_id),
            )
            team = _fetch_team(conn, tenant_id=tenant_id, workspace=workspace, team_id=team_id)

            _audit_log_event(
                conn,
                tenant_id=tenant_id,
                workspace=workspace,
                entity_type="team",
                entity_id=team_id,
                fingerprint=None,
                event_type="team.created",
                event_category="configuration",
                previous_value=None,
                new_value=team,
                actor_id=updated_by,
                actor_email=updated_by,
                actor_name=None,
                source="api",
            )
            conn.commit()

        return _ok({"tenant_id": tenant_id, "workspace": workspace, "team": team}, status=201)
    except ValueError as exc:
        return _err("bad_request", str(exc), status=400)


@app.put("/api/teams/<team_id>")
def api_update_team(team_id: str) -> Any:
    """Update mutable team fields in tenant/workspace scope."""
    try:
        payload = request.get_json(force=True, silent=False) or {}
        tenant_id, workspace = _require_scope_from_json(payload)
        tid = _coerce_optional_text(team_id)
        if not tid:
            raise ValueError("team_id is required")

        name_v = _payload_optional_text(payload, "name")
        description_v = _payload_optional_text(payload, "description")
        parent_team_id_v = _payload_optional_text(payload, "parent_team_id")
        updated_by = _coerce_optional_text(payload.get("updated_by"))
        if name_v is _MISSING and description_v is _MISSING and parent_team_id_v is _MISSING:
            raise ValueError("at least one of name, description, parent_team_id must be provided")

        with db_conn() as conn:
            before = _fetch_team(conn, tenant_id=tenant_id, workspace=workspace, team_id=tid)
            if before is None:
                return _err("not_found", "team not found", status=404)

            name = before.get("name") if name_v is _MISSING else name_v
            if not name:
                raise ValueError("name cannot be empty")
            description = before.get("description") if description_v is _MISSING else description_v
            parent_team_id = before.get("parent_team_id") if parent_team_id_v is _MISSING else parent_team_id_v
            if parent_team_id == tid:
                raise ValueError("parent_team_id cannot equal team_id")

            if parent_team_id is not None and not _team_exists(
                conn, tenant_id=tenant_id, workspace=workspace, team_id=str(parent_team_id)
            ):
                return _err("not_found", f"parent team not found: {parent_team_id}", status=404)

            execute_conn(
                conn,
                """
                UPDATE teams
                SET
                  name = %s,
                  description = %s,
                  parent_team_id = %s,
                  updated_at = now()
                WHERE tenant_id = %s AND workspace = %s AND team_id = %s
                """,
                (name, description, parent_team_id, tenant_id, workspace, tid),
            )
            after = _fetch_team(conn, tenant_id=tenant_id, workspace=workspace, team_id=tid)

            _audit_log_event(
                conn,
                tenant_id=tenant_id,
                workspace=workspace,
                entity_type="team",
                entity_id=tid,
                fingerprint=None,
                event_type="team.updated",
                event_category="configuration",
                previous_value=before,
                new_value=after,
                actor_id=updated_by,
                actor_email=updated_by,
                actor_name=None,
                source="api",
            )
            conn.commit()

        return _ok({"tenant_id": tenant_id, "workspace": workspace, "team": after})
    except ValueError as exc:
        return _err("bad_request", str(exc), status=400)


@app.delete("/api/teams/<team_id>")
def api_delete_team(team_id: str) -> Any:
    """Delete a team in tenant/workspace scope."""
    try:
        tenant_id, workspace = _require_scope_from_query()
        tid = _coerce_optional_text(team_id)
        if not tid:
            raise ValueError("team_id is required")
        updated_by = _coerce_optional_text(_q("updated_by"))

        with db_conn() as conn:
            before = _fetch_team(conn, tenant_id=tenant_id, workspace=workspace, team_id=tid)
            if before is None:
                return _err("not_found", "team not found", status=404)

            execute_conn(
                conn,
                "DELETE FROM teams WHERE tenant_id = %s AND workspace = %s AND team_id = %s",
                (tenant_id, workspace, tid),
            )
            _audit_log_event(
                conn,
                tenant_id=tenant_id,
                workspace=workspace,
                entity_type="team",
                entity_id=tid,
                fingerprint=None,
                event_type="team.deleted",
                event_category="configuration",
                previous_value=before,
                new_value=None,
                actor_id=updated_by,
                actor_email=updated_by,
                actor_name=None,
                source="api",
            )
            conn.commit()

        return _ok({"tenant_id": tenant_id, "workspace": workspace, "team_id": tid})
    except ValueError as exc:
        return _err("bad_request", str(exc), status=400)


@app.get("/api/teams/<team_id>/members")
def api_team_members(team_id: str) -> Any:
    """List members for one team in tenant/workspace scope."""
    try:
        tenant_id, workspace = _require_scope_from_query()
        tid = _coerce_optional_text(team_id)
        if not tid:
            raise ValueError("team_id is required")

        limit = _parse_int(_q("limit"), default=200, min_v=1, max_v=1000)
        offset = _parse_int(_q("offset"), default=0, min_v=0, max_v=5_000_000)
        query_str = _q("q")

        with db_conn() as conn:
            if not _team_exists(conn, tenant_id=tenant_id, workspace=workspace, team_id=tid):
                return _err("not_found", "team not found", status=404)

            where = ["tenant_id = %s", "workspace = %s", "team_id = %s"]
            params: List[Any] = [tenant_id, workspace, tid]
            if query_str:
                where.append(
                    "(user_id ILIKE %s OR user_email ILIKE %s OR COALESCE(user_name, '') ILIKE %s)"
                )
                params.extend([f"%{query_str}%", f"%{query_str}%", f"%{query_str}%"])

            members = fetch_all_dict_conn(
                conn,
                f"""
                SELECT
                  tenant_id,
                  workspace,
                  team_id,
                  user_id,
                  user_email,
                  user_name,
                  role,
                  joined_at
                FROM team_members
                WHERE {' AND '.join(where)}
                ORDER BY user_email ASC, user_id ASC
                LIMIT %s OFFSET %s
                """,
                params + [limit, offset],
            )
            count_row = fetch_one_dict_conn(
                conn,
                f"SELECT COUNT(*)::bigint AS n FROM team_members WHERE {' AND '.join(where)}",
                params,
            )

        return _ok(
            {
                "tenant_id": tenant_id,
                "workspace": workspace,
                "team_id": tid,
                "limit": limit,
                "offset": offset,
                "total": int((count_row or {}).get("n") or 0),
                "items": members,
            }
        )
    except ValueError as exc:
        return _err("bad_request", str(exc), status=400)


@app.post("/api/teams/<team_id>/members")
def api_team_member_add(team_id: str) -> Any:
    """Add one member to a team in tenant/workspace scope."""
    try:
        payload = request.get_json(force=True, silent=False) or {}
        tenant_id, workspace = _require_scope_from_json(payload)
        tid = _coerce_optional_text(team_id)
        if not tid:
            raise ValueError("team_id is required")

        user_id = _coerce_optional_text(payload.get("user_id"))
        user_email = _coerce_optional_text(payload.get("user_email"))
        user_name_v = _payload_optional_text(payload, "user_name")
        role_v = _payload_optional_text(payload, "role")
        updated_by = _coerce_optional_text(payload.get("updated_by"))

        if not user_id:
            raise ValueError("user_id is required")
        if not user_email:
            raise ValueError("user_email is required")

        role = "member" if role_v is _MISSING else role_v
        if role not in {"owner", "member", "viewer"}:
            raise ValueError("role must be one of: owner, member, viewer")
        user_name = None if user_name_v is _MISSING else user_name_v

        with db_conn() as conn:
            if not _team_exists(conn, tenant_id=tenant_id, workspace=workspace, team_id=tid):
                return _err("not_found", "team not found", status=404)
            before = _fetch_team_member(
                conn,
                tenant_id=tenant_id,
                workspace=workspace,
                team_id=tid,
                user_id=user_id,
            )
            if before is not None:
                return _err("conflict", f"team member already exists: {user_id}", status=409)

            execute_conn(
                conn,
                """
                INSERT INTO team_members
                  (tenant_id, workspace, team_id, user_id, user_email, user_name, role, joined_at)
                VALUES
                  (%s, %s, %s, %s, %s, %s, %s, now())
                """,
                (tenant_id, workspace, tid, user_id, user_email, user_name, role),
            )
            after = _fetch_team_member(
                conn,
                tenant_id=tenant_id,
                workspace=workspace,
                team_id=tid,
                user_id=user_id,
            )
            _audit_log_event(
                conn,
                tenant_id=tenant_id,
                workspace=workspace,
                entity_type="team_member",
                entity_id=f"{tid}:{user_id}",
                fingerprint=None,
                event_type="member.added",
                event_category="access",
                previous_value=None,
                new_value=after,
                actor_id=updated_by,
                actor_email=updated_by,
                actor_name=None,
                source="api",
            )
            conn.commit()

        return _ok(
            {
                "tenant_id": tenant_id,
                "workspace": workspace,
                "team_id": tid,
                "member": after,
            },
            status=201,
        )
    except ValueError as exc:
        return _err("bad_request", str(exc), status=400)


@app.delete("/api/teams/<team_id>/members/<user_id>")
def api_team_member_remove(team_id: str, user_id: str) -> Any:
    """Remove one member from a team in tenant/workspace scope."""
    try:
        tenant_id, workspace = _require_scope_from_query()
        tid = _coerce_optional_text(team_id)
        uid = _coerce_optional_text(user_id)
        if not tid:
            raise ValueError("team_id is required")
        if not uid:
            raise ValueError("user_id is required")
        updated_by = _coerce_optional_text(_q("updated_by"))

        with db_conn() as conn:
            if not _team_exists(conn, tenant_id=tenant_id, workspace=workspace, team_id=tid):
                return _err("not_found", "team not found", status=404)
            before = _fetch_team_member(
                conn,
                tenant_id=tenant_id,
                workspace=workspace,
                team_id=tid,
                user_id=uid,
            )
            if before is None:
                return _err("not_found", "team member not found", status=404)

            execute_conn(
                conn,
                """
                DELETE FROM team_members
                WHERE tenant_id = %s
                  AND workspace = %s
                  AND team_id = %s
                  AND user_id = %s
                """,
                (tenant_id, workspace, tid, uid),
            )
            _audit_log_event(
                conn,
                tenant_id=tenant_id,
                workspace=workspace,
                entity_type="team_member",
                entity_id=f"{tid}:{uid}",
                fingerprint=None,
                event_type="member.removed",
                event_category="access",
                previous_value=before,
                new_value=None,
                actor_id=updated_by,
                actor_email=updated_by,
                actor_name=None,
                source="api",
            )
            conn.commit()

        return _ok({"tenant_id": tenant_id, "workspace": workspace, "team_id": tid, "user_id": uid})
    except ValueError as exc:
        return _err("bad_request", str(exc), status=400)


# --------------------
# Governance: SLA Policies
# --------------------


@app.get("/api/sla/policies")
def api_sla_policies() -> Any:
    """List category SLA policies in tenant/workspace scope."""
    try:
        tenant_id, workspace = _require_scope_from_query()
        limit = _parse_int(_q("limit"), default=200, min_v=1, max_v=1000)
        offset = _parse_int(_q("offset"), default=0, min_v=0, max_v=5_000_000)

        with db_conn() as conn:
            rows = fetch_all_dict_conn(
                conn,
                """
                SELECT
                  tenant_id,
                  workspace,
                  category,
                  sla_days,
                  description,
                  created_at,
                  updated_at
                FROM sla_policy_category
                WHERE tenant_id = %s AND workspace = %s
                ORDER BY category ASC
                LIMIT %s OFFSET %s
                """,
                (tenant_id, workspace, limit, offset),
            )
            count_row = fetch_one_dict_conn(
                conn,
                """
                SELECT COUNT(*)::bigint AS n
                FROM sla_policy_category
                WHERE tenant_id = %s AND workspace = %s
                """,
                (tenant_id, workspace),
            )

        return _ok(
            {
                "tenant_id": tenant_id,
                "workspace": workspace,
                "limit": limit,
                "offset": offset,
                "total": int((count_row or {}).get("n") or 0),
                "items": rows,
            }
        )
    except ValueError as exc:
        return _err("bad_request", str(exc), status=400)


@app.post("/api/sla/policies")
def api_create_sla_policy() -> Any:
    """Create a category SLA policy in tenant/workspace scope."""
    try:
        payload = request.get_json(force=True, silent=False) or {}
        tenant_id, workspace = _require_scope_from_json(payload)
        category = _coerce_optional_text(payload.get("category"))
        sla_days = _coerce_positive_int(payload.get("sla_days"), field_name="sla_days")
        description_v = _payload_optional_text(payload, "description")
        updated_by = _coerce_optional_text(payload.get("updated_by"))

        if not category:
            raise ValueError("category is required")
        description = None if description_v is _MISSING else description_v

        with db_conn() as conn:
            if _fetch_sla_policy_category(conn, tenant_id=tenant_id, workspace=workspace, category=category):
                return _err("conflict", f"sla policy already exists for category: {category}", status=409)

            execute_conn(
                conn,
                """
                INSERT INTO sla_policy_category
                  (tenant_id, workspace, category, sla_days, description, created_at, updated_at)
                VALUES
                  (%s, %s, %s, %s, %s, now(), now())
                """,
                (tenant_id, workspace, category, sla_days, description),
            )
            policy = _fetch_sla_policy_category(conn, tenant_id=tenant_id, workspace=workspace, category=category)

            _audit_log_event(
                conn,
                tenant_id=tenant_id,
                workspace=workspace,
                entity_type="sla_policy_category",
                entity_id=category,
                fingerprint=None,
                event_type="sla.policy.created",
                event_category="configuration",
                previous_value=None,
                new_value=policy,
                actor_id=updated_by,
                actor_email=updated_by,
                actor_name=None,
                source="api",
            )
            conn.commit()

        return _ok({"tenant_id": tenant_id, "workspace": workspace, "policy": policy}, status=201)
    except ValueError as exc:
        return _err("bad_request", str(exc), status=400)


@app.put("/api/sla/policies/<category>")
def api_update_sla_policy(category: str) -> Any:
    """Update one category SLA policy in tenant/workspace scope."""
    try:
        payload = request.get_json(force=True, silent=False) or {}
        tenant_id, workspace = _require_scope_from_json(payload)
        cat = _coerce_optional_text(category)
        if not cat:
            raise ValueError("category is required")

        sla_days_raw = payload.get("sla_days")
        description_v = _payload_optional_text(payload, "description")
        updated_by = _coerce_optional_text(payload.get("updated_by"))
        if sla_days_raw is None and description_v is _MISSING:
            raise ValueError("at least one of sla_days, description must be provided")

        with db_conn() as conn:
            before = _fetch_sla_policy_category(conn, tenant_id=tenant_id, workspace=workspace, category=cat)
            if before is None:
                return _err("not_found", "sla policy not found", status=404)

            sla_days = int(before.get("sla_days") or 0)
            if sla_days_raw is not None:
                sla_days = _coerce_positive_int(sla_days_raw, field_name="sla_days")
            description = before.get("description") if description_v is _MISSING else description_v

            execute_conn(
                conn,
                """
                UPDATE sla_policy_category
                SET
                  sla_days = %s,
                  description = %s,
                  updated_at = now()
                WHERE tenant_id = %s AND workspace = %s AND category = %s
                """,
                (sla_days, description, tenant_id, workspace, cat),
            )
            after = _fetch_sla_policy_category(conn, tenant_id=tenant_id, workspace=workspace, category=cat)

            _audit_log_event(
                conn,
                tenant_id=tenant_id,
                workspace=workspace,
                entity_type="sla_policy_category",
                entity_id=cat,
                fingerprint=None,
                event_type="sla.policy.updated",
                event_category="configuration",
                previous_value=before,
                new_value=after,
                actor_id=updated_by,
                actor_email=updated_by,
                actor_name=None,
                source="api",
            )
            conn.commit()

        return _ok({"tenant_id": tenant_id, "workspace": workspace, "policy": after})
    except ValueError as exc:
        return _err("bad_request", str(exc), status=400)


@app.get("/api/sla/policies/overrides")
def api_sla_overrides() -> Any:
    """List check-level SLA overrides in tenant/workspace scope."""
    try:
        tenant_id, workspace = _require_scope_from_query()
        limit = _parse_int(_q("limit"), default=200, min_v=1, max_v=1000)
        offset = _parse_int(_q("offset"), default=0, min_v=0, max_v=5_000_000)
        check_ids = _parse_csv_list(_q("check_id"))

        where = ["tenant_id = %s", "workspace = %s"]
        params: List[Any] = [tenant_id, workspace]
        if check_ids:
            where.append("check_id = ANY(%s)")
            params.append(check_ids)

        with db_conn() as conn:
            rows = fetch_all_dict_conn(
                conn,
                f"""
                SELECT
                  tenant_id,
                  workspace,
                  check_id,
                  sla_days,
                  reason,
                  created_at,
                  updated_at
                FROM sla_policy_check_override
                WHERE {' AND '.join(where)}
                ORDER BY check_id ASC
                LIMIT %s OFFSET %s
                """,
                params + [limit, offset],
            )
            count_row = fetch_one_dict_conn(
                conn,
                f"SELECT COUNT(*)::bigint AS n FROM sla_policy_check_override WHERE {' AND '.join(where)}",
                params,
            )

        return _ok(
            {
                "tenant_id": tenant_id,
                "workspace": workspace,
                "limit": limit,
                "offset": offset,
                "total": int((count_row or {}).get("n") or 0),
                "items": rows,
            }
        )
    except ValueError as exc:
        return _err("bad_request", str(exc), status=400)


@app.post("/api/sla/policies/overrides")
def api_create_sla_override() -> Any:
    """Create a check-level SLA override in tenant/workspace scope."""
    try:
        payload = request.get_json(force=True, silent=False) or {}
        tenant_id, workspace = _require_scope_from_json(payload)
        check_id = _coerce_optional_text(payload.get("check_id"))
        sla_days = _coerce_positive_int(payload.get("sla_days"), field_name="sla_days")
        reason_v = _payload_optional_text(payload, "reason")
        updated_by = _coerce_optional_text(payload.get("updated_by"))

        if not check_id:
            raise ValueError("check_id is required")
        reason = None if reason_v is _MISSING else reason_v

        with db_conn() as conn:
            if _fetch_sla_policy_override(conn, tenant_id=tenant_id, workspace=workspace, check_id=check_id):
                return _err("conflict", f"sla override already exists for check_id: {check_id}", status=409)

            execute_conn(
                conn,
                """
                INSERT INTO sla_policy_check_override
                  (tenant_id, workspace, check_id, sla_days, reason, created_at, updated_at)
                VALUES
                  (%s, %s, %s, %s, %s, now(), now())
                """,
                (tenant_id, workspace, check_id, sla_days, reason),
            )
            override = _fetch_sla_policy_override(conn, tenant_id=tenant_id, workspace=workspace, check_id=check_id)

            _audit_log_event(
                conn,
                tenant_id=tenant_id,
                workspace=workspace,
                entity_type="sla_policy_check_override",
                entity_id=check_id,
                fingerprint=None,
                event_type="sla.override.created",
                event_category="configuration",
                previous_value=None,
                new_value=override,
                actor_id=updated_by,
                actor_email=updated_by,
                actor_name=None,
                source="api",
            )
            conn.commit()

        return _ok({"tenant_id": tenant_id, "workspace": workspace, "override": override}, status=201)
    except ValueError as exc:
        return _err("bad_request", str(exc), status=400)


# --------------------
# Lifecycle actions
# --------------------


def _audit_log_event(
    conn: Any,
    *,
    tenant_id: str,
    workspace: str,
    entity_type: str,
    entity_id: str,
    fingerprint: Optional[str],
    event_type: str,
    event_category: str,
    previous_value: Optional[Dict[str, Any]],
    new_value: Optional[Dict[str, Any]],
    actor_id: Optional[str],
    actor_email: Optional[str],
    actor_name: Optional[str],
    source: str,
    run_id: Optional[str] = None,
    correlation_id: Optional[str] = None,
) -> None:
    """Best-effort append-only write to audit_log, isolated by savepoint."""
    try:
        ip_address = request.headers.get("X-Forwarded-For", request.remote_addr)
        user_agent = request.headers.get("User-Agent", "")
    except RuntimeError:
        ip_address = None
        user_agent = ""

    params = (
        tenant_id,
        workspace,
        entity_type,
        entity_id,
        fingerprint,
        event_type,
        event_category,
        (json.dumps(previous_value, separators=(",", ":")) if previous_value is not None else None),
        (json.dumps(new_value, separators=(",", ":")) if new_value is not None else None),
        actor_id,
        actor_email,
        actor_name,
        source,
        ip_address,
        user_agent,
        run_id,
        correlation_id,
    )

    with conn.cursor() as cur:
        try:
            cur.execute("SAVEPOINT mckay_audit_log_1")
            cur.execute(
                """
                INSERT INTO audit_log
                  (
                    tenant_id, workspace, entity_type, entity_id, fingerprint,
                    event_type, event_category, previous_value, new_value,
                    actor_id, actor_email, actor_name, source, ip_address, user_agent,
                    run_id, correlation_id, created_at
                  )
                VALUES
                  (%s,%s,%s,%s,%s,%s,%s,%s::jsonb,%s::jsonb,%s,%s,%s,%s,%s,%s,%s,%s, now())
                """,
                params,
            )
            cur.execute("RELEASE SAVEPOINT mckay_audit_log_1")
            return
        except Exception:
            try:
                cur.execute("ROLLBACK TO SAVEPOINT mckay_audit_log_1")
            except Exception:
                pass
            try:
                cur.execute("RELEASE SAVEPOINT mckay_audit_log_1")
            except Exception:
                pass
            _log(
                "WARN",
                "audit_log_db_write_failed",
                {
                    "tenant_id": tenant_id,
                    "workspace": workspace,
                    "entity_type": entity_type,
                    "entity_id": entity_id,
                    "event_type": event_type,
                },
            )
            return


def _audit_lifecycle(
    conn: Any,
    *,
    tenant_id: str,
    workspace: str,
    action: str,
    subject_type: str,
    subject_id: str,
    state: str,
    snooze_until: Optional[datetime],
    reason: Optional[str],
    updated_by: Optional[str],
) -> None:
    """Best-effort lifecycle audit logging.

    Always emits a structured audit log event. Best-effort insert into finding_state_audit.
    Audit write failures must never impact the caller transaction.
    """
    evt = {
        "tenant_id": tenant_id,
        "workspace": workspace,
        "action": action,
        "subject_type": subject_type,
        "subject_id": subject_id,
        "state": state,
        "snooze_until": _iso_z(snooze_until) if snooze_until else None,
        "reason": reason,
        "updated_by": updated_by,
    }
    _log("INFO", "lifecycle_audit", evt)

    _audit_log_event(
        conn,
        tenant_id=tenant_id,
        workspace=workspace,
        entity_type=subject_type,
        entity_id=subject_id,
        fingerprint=(subject_id if subject_type == "fingerprint" else None),
        event_type="finding.state.changed",
        event_category="lifecycle",
        previous_value=None,
        new_value={
            "action": action,
            "state": state,
            "snooze_until": _iso_z(snooze_until) if snooze_until else None,
            "reason": reason,
        },
        actor_id=updated_by,
        actor_email=updated_by,
        actor_name=None,
        source="api",
        run_id=None,
        correlation_id=None,
    )

    params = (
        tenant_id,
        workspace,
        subject_type,
        subject_id,
        action,
        state,
        snooze_until,
        reason,
        updated_by,
    )

    # Never let optional audit writes poison the caller transaction.
    with conn.cursor() as cur:
        try:
            cur.execute("SAVEPOINT mckay_audit_1")
            cur.execute(
                """
                INSERT INTO finding_state_audit
                  (
                    tenant_id, workspace, subject_type, subject_id, action,
                    state, snooze_until, reason, updated_by, created_at
                  )
                VALUES
                  (%s,%s,%s,%s,%s,%s,%s,%s,%s, now())
                """,
                params,
            )
            cur.execute("RELEASE SAVEPOINT mckay_audit_1")
            return
        except Exception:
            try:
                cur.execute("ROLLBACK TO SAVEPOINT mckay_audit_1")
            except Exception:
                pass
            try:
                cur.execute("RELEASE SAVEPOINT mckay_audit_1")
            except Exception:
                pass
            _log(
                "WARN",
                "lifecycle_audit_db_write_failed",
                {
                    "tenant_id": tenant_id,
                    "workspace": workspace,
                    "action": action,
                    "subject_type": subject_type,
                    "subject_id": subject_id,
                },
            )
            return



def _upsert_state(
    conn: Any,
    *,
    tenant_id: str,
    workspace: str,
    fingerprint: str,
    state: str,
    snooze_until: Optional[datetime],
    reason: Optional[str],
    updated_by: Optional[str],
) -> None:
    execute_conn(
        conn,
        """
        INSERT INTO finding_state_current (
        tenant_id, workspace, fingerprint, state,
        snooze_until, reason, updated_by, updated_at
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s, now())
        ON CONFLICT (tenant_id, workspace, fingerprint)
        DO UPDATE SET
        state = EXCLUDED.state,
        snooze_until = EXCLUDED.snooze_until,
        reason = EXCLUDED.reason,
        updated_by = EXCLUDED.updated_by,
        updated_at = now(),
        version = finding_state_current.version + 1;
        """,
        (tenant_id, workspace, fingerprint, state, snooze_until, reason, updated_by),
    )


def _upsert_group_state(
    conn: Any,
    *,
    tenant_id: str,
    workspace: str,
    group_key: str,
    state: str,
    snooze_until: Optional[datetime],
    reason: Optional[str],
    updated_by: Optional[str],
) -> None:
    execute_conn(
        conn,
        """
        INSERT INTO finding_group_state_current
          (tenant_id, workspace, group_key, state, snooze_until, reason, updated_at, updated_by, version)
        VALUES
          (%s, %s, %s, %s, %s, %s, now(), %s, 1)
        ON CONFLICT (tenant_id, workspace, group_key)
        DO UPDATE SET
          state = EXCLUDED.state,
          snooze_until = EXCLUDED.snooze_until,
          reason = EXCLUDED.reason,
          updated_at = now(),
          updated_by = EXCLUDED.updated_by,
          version = finding_group_state_current.version + 1
        """,
        (tenant_id, workspace, group_key, state, snooze_until, reason, updated_by),
    )


def _finding_exists(conn: Any, *, tenant_id: str, workspace: str, fingerprint: str) -> bool:
    """Return True when a finding fingerprint exists in finding_latest."""
    row = fetch_one_dict_conn(
        conn,
        """
        SELECT 1 AS ok
        FROM finding_latest
        WHERE tenant_id = %s AND workspace = %s AND fingerprint = %s
        LIMIT 1
        """,
        (tenant_id, workspace, fingerprint),
    )
    return bool(row and row.get("ok") == 1)


def _fetch_finding_effective_state(
    conn: Any,
    *,
    tenant_id: str,
    workspace: str,
    fingerprint: str,
) -> Optional[str]:
    """Return effective_state for a finding from finding_current."""
    row = fetch_one_dict_conn(
        conn,
        """
        SELECT effective_state
        FROM finding_current
        WHERE tenant_id = %s AND workspace = %s AND fingerprint = %s
        """,
        (tenant_id, workspace, fingerprint),
    )
    return _coerce_optional_text((row or {}).get("effective_state"))


def _fetch_team(
    conn: Any,
    *,
    tenant_id: str,
    workspace: str,
    team_id: str,
) -> Optional[Dict[str, Any]]:
    """Fetch one team by scoped id."""
    return fetch_one_dict_conn(
        conn,
        """
        SELECT
          tenant_id,
          workspace,
          team_id,
          name,
          description,
          parent_team_id,
          created_at,
          updated_at
        FROM teams
        WHERE tenant_id = %s AND workspace = %s AND team_id = %s
        """,
        (tenant_id, workspace, team_id),
    )


def _fetch_team_member(
    conn: Any,
    *,
    tenant_id: str,
    workspace: str,
    team_id: str,
    user_id: str,
) -> Optional[Dict[str, Any]]:
    """Fetch one team member by scoped team_id + user_id."""
    return fetch_one_dict_conn(
        conn,
        """
        SELECT
          tenant_id,
          workspace,
          team_id,
          user_id,
          user_email,
          user_name,
          role,
          joined_at
        FROM team_members
        WHERE tenant_id = %s
          AND workspace = %s
          AND team_id = %s
          AND user_id = %s
        """,
        (tenant_id, workspace, team_id, user_id),
    )


def _team_exists(conn: Any, *, tenant_id: str, workspace: str, team_id: str) -> bool:
    """Return True when a team exists for a tenant/workspace scope."""
    row = fetch_one_dict_conn(
        conn,
        """
        SELECT 1 AS ok
        FROM teams
        WHERE tenant_id = %s AND workspace = %s AND team_id = %s
        LIMIT 1
        """,
        (tenant_id, workspace, team_id),
    )
    return bool(row and row.get("ok") == 1)


def _ensure_finding_governance_row(
    conn: Any,
    *,
    tenant_id: str,
    workspace: str,
    fingerprint: str,
) -> None:
    """Ensure governance overlay row exists for a finding fingerprint."""
    execute_conn(
        conn,
        """
        INSERT INTO finding_governance
          (tenant_id, workspace, fingerprint, first_detected_at, first_opened_at, created_at, updated_at)
        SELECT
          fc.tenant_id,
          fc.workspace,
          fc.fingerprint,
          fc.detected_at,
          CASE WHEN fc.effective_state = 'open' THEN fc.detected_at ELSE NULL END,
          now(),
          now()
        FROM finding_current fc
        WHERE fc.tenant_id = %s AND fc.workspace = %s AND fc.fingerprint = %s
        ON CONFLICT (tenant_id, workspace, fingerprint) DO NOTHING
        """,
        (tenant_id, workspace, fingerprint),
    )


def _fetch_governance_owner_team(
    conn: Any,
    *,
    tenant_id: str,
    workspace: str,
    fingerprint: str,
) -> Dict[str, Optional[str]]:
    """Fetch owner/team governance fields for a finding."""
    row = fetch_one_dict_conn(
        conn,
        """
        SELECT owner_id, owner_email, owner_name, team_id
        FROM finding_governance
        WHERE tenant_id = %s AND workspace = %s AND fingerprint = %s
        """,
        (tenant_id, workspace, fingerprint),
    ) or {}
    return {
        "owner_id": _coerce_optional_text(row.get("owner_id")),
        "owner_email": _coerce_optional_text(row.get("owner_email")),
        "owner_name": _coerce_optional_text(row.get("owner_name")),
        "team_id": _coerce_optional_text(row.get("team_id")),
    }


def _fetch_sla_policy_category(
    conn: Any,
    *,
    tenant_id: str,
    workspace: str,
    category: str,
) -> Optional[Dict[str, Any]]:
    """Fetch one category SLA policy row by scope + category."""
    return fetch_one_dict_conn(
        conn,
        """
        SELECT
          tenant_id,
          workspace,
          category,
          sla_days,
          description,
          created_at,
          updated_at
        FROM sla_policy_category
        WHERE tenant_id = %s AND workspace = %s AND category = %s
        """,
        (tenant_id, workspace, category),
    )


def _fetch_sla_policy_override(
    conn: Any,
    *,
    tenant_id: str,
    workspace: str,
    check_id: str,
) -> Optional[Dict[str, Any]]:
    """Fetch one check SLA override row by scope + check_id."""
    return fetch_one_dict_conn(
        conn,
        """
        SELECT
          tenant_id,
          workspace,
          check_id,
          sla_days,
          reason,
          created_at,
          updated_at
        FROM sla_policy_check_override
        WHERE tenant_id = %s AND workspace = %s AND check_id = %s
        """,
        (tenant_id, workspace, check_id),
    )


def _fetch_governance_sla(
    conn: Any,
    *,
    tenant_id: str,
    workspace: str,
    fingerprint: str,
) -> Dict[str, Any]:
    """Fetch SLA governance fields for a finding."""
    row = fetch_one_dict_conn(
        conn,
        """
        SELECT
          sla_deadline,
          sla_paused_at,
          sla_total_paused_seconds,
          sla_extension_seconds,
          sla_breached_at,
          sla_extended_count,
          sla_extension_reason
        FROM finding_governance
        WHERE tenant_id = %s AND workspace = %s AND fingerprint = %s
        """,
        (tenant_id, workspace, fingerprint),
    ) or {}
    return {
        "sla_deadline": row.get("sla_deadline"),
        "sla_paused_at": row.get("sla_paused_at"),
        "sla_total_paused_seconds": int(row.get("sla_total_paused_seconds") or 0),
        "sla_extension_seconds": int(row.get("sla_extension_seconds") or 0),
        "sla_breached_at": row.get("sla_breached_at"),
        "sla_extended_count": int(row.get("sla_extended_count") or 0),
        "sla_extension_reason": _coerce_optional_text(row.get("sla_extension_reason")),
    }


def _apply_finding_sla_extension(
    conn: Any,
    *,
    tenant_id: str,
    workspace: str,
    fingerprint: str,
    extend_days: int,
    reason: Optional[str],
    event_ts: datetime,
) -> Optional[Dict[str, Any]]:
    """Apply manual SLA extension in seconds and return updated SLA fields."""
    execute_conn(
        conn,
        "SELECT governance_sync_finding_sla(%s, %s, %s, %s)",
        (tenant_id, workspace, fingerprint, event_ts),
    )

    before = _fetch_governance_sla(
        conn,
        tenant_id=tenant_id,
        workspace=workspace,
        fingerprint=fingerprint,
    )
    if before.get("sla_deadline") is None:
        return None

    extend_seconds = int(extend_days) * 86400
    execute_conn(
        conn,
        """
        UPDATE finding_governance
        SET
          sla_extension_seconds = COALESCE(sla_extension_seconds, 0) + %s,
          sla_extended_count = COALESCE(sla_extended_count, 0) + 1,
          sla_extension_reason = CASE
              WHEN %s IS NOT NULL THEN %s
              ELSE sla_extension_reason
          END,
          updated_at = now()
        WHERE tenant_id = %s AND workspace = %s AND fingerprint = %s
        """,
        (
            extend_seconds,
            reason,
            reason,
            tenant_id,
            workspace,
            fingerprint,
        ),
    )

    execute_conn(
        conn,
        "SELECT governance_sync_finding_sla(%s, %s, %s, %s)",
        (tenant_id, workspace, fingerprint, event_ts),
    )

    return _fetch_governance_sla(
        conn,
        tenant_id=tenant_id,
        workspace=workspace,
        fingerprint=fingerprint,
    )


def _update_finding_owner(
    conn: Any,
    *,
    tenant_id: str,
    workspace: str,
    fingerprint: str,
    owner_id: Optional[str],
    owner_email: Optional[str],
    owner_name: Optional[str],
) -> None:
    """Persist owner fields in finding_governance."""
    execute_conn(
        conn,
        """
        UPDATE finding_governance
        SET owner_id = %s,
            owner_email = %s,
            owner_name = %s,
            updated_at = now()
        WHERE tenant_id = %s AND workspace = %s AND fingerprint = %s
        """,
        (owner_id, owner_email, owner_name, tenant_id, workspace, fingerprint),
    )


def _update_finding_team(
    conn: Any,
    *,
    tenant_id: str,
    workspace: str,
    fingerprint: str,
    team_id: Optional[str],
) -> None:
    """Persist team assignment in finding_governance."""
    execute_conn(
        conn,
        """
        UPDATE finding_governance
        SET team_id = %s,
            updated_at = now()
        WHERE tenant_id = %s AND workspace = %s AND fingerprint = %s
        """,
        (team_id, tenant_id, workspace, fingerprint),
    )


@app.put("/api/findings/<fingerprint>/owner")
def api_findings_set_owner(fingerprint: str) -> Any:
    """Assign or clear owner governance fields for a finding."""
    try:
        payload = request.get_json(force=True, silent=False) or {}
        tenant_id, workspace = _require_scope_from_json(payload)
        fp = str(fingerprint or "").strip()
        if not fp:
            raise ValueError("fingerprint is required")

        owner_id_v = _payload_optional_text(payload, "owner_id")
        owner_email_v = _payload_optional_text(payload, "owner_email")
        owner_name_v = _payload_optional_text(payload, "owner_name")
        if owner_id_v is _MISSING and owner_email_v is _MISSING and owner_name_v is _MISSING:
            raise ValueError("at least one of owner_id, owner_email, owner_name must be provided")

        updated_by = _coerce_optional_text(payload.get("updated_by"))

        with db_conn() as conn:
            if not _finding_exists(conn, tenant_id=tenant_id, workspace=workspace, fingerprint=fp):
                return _err("not_found", "finding not found", status=404)

            _ensure_finding_governance_row(conn, tenant_id=tenant_id, workspace=workspace, fingerprint=fp)
            before = _fetch_governance_owner_team(conn, tenant_id=tenant_id, workspace=workspace, fingerprint=fp)

            owner_id = before["owner_id"] if owner_id_v is _MISSING else owner_id_v
            owner_email = before["owner_email"] if owner_email_v is _MISSING else owner_email_v
            owner_name = before["owner_name"] if owner_name_v is _MISSING else owner_name_v

            _update_finding_owner(
                conn,
                tenant_id=tenant_id,
                workspace=workspace,
                fingerprint=fp,
                owner_id=owner_id,
                owner_email=owner_email,
                owner_name=owner_name,
            )
            after = _fetch_governance_owner_team(conn, tenant_id=tenant_id, workspace=workspace, fingerprint=fp)

            event_type = (
                "finding.owner.cleared"
                if not after.get("owner_id") and not after.get("owner_email") and not after.get("owner_name")
                else "finding.owner.assigned"
            )
            _audit_log_event(
                conn,
                tenant_id=tenant_id,
                workspace=workspace,
                entity_type="finding",
                entity_id=fp,
                fingerprint=fp,
                event_type=event_type,
                event_category="ownership",
                previous_value=before,
                new_value=after,
                actor_id=updated_by,
                actor_email=updated_by,
                actor_name=None,
                source="api",
            )
            conn.commit()

        return _ok(
            {
                "tenant_id": tenant_id,
                "workspace": workspace,
                "fingerprint": fp,
                "owner_id": after.get("owner_id"),
                "owner_email": after.get("owner_email"),
                "owner_name": after.get("owner_name"),
            }
        )
    except ValueError as exc:
        return _err("bad_request", str(exc), status=400)


@app.put("/api/findings/<fingerprint>/team")
def api_findings_set_team(fingerprint: str) -> Any:
    """Assign or clear team ownership for a finding."""
    try:
        payload = request.get_json(force=True, silent=False) or {}
        tenant_id, workspace = _require_scope_from_json(payload)
        fp = str(fingerprint or "").strip()
        if not fp:
            raise ValueError("fingerprint is required")

        team_id_v = _payload_optional_text(payload, "team_id")
        if team_id_v is _MISSING:
            raise ValueError("team_id must be provided (nullable to clear)")

        updated_by = _coerce_optional_text(payload.get("updated_by"))

        with db_conn() as conn:
            if not _finding_exists(conn, tenant_id=tenant_id, workspace=workspace, fingerprint=fp):
                return _err("not_found", "finding not found", status=404)

            _ensure_finding_governance_row(conn, tenant_id=tenant_id, workspace=workspace, fingerprint=fp)
            before = _fetch_governance_owner_team(conn, tenant_id=tenant_id, workspace=workspace, fingerprint=fp)

            if team_id_v is not None and not _team_exists(
                conn,
                tenant_id=tenant_id,
                workspace=workspace,
                team_id=team_id_v,
            ):
                return _err("not_found", f"team not found: {team_id_v}", status=404)

            _update_finding_team(
                conn,
                tenant_id=tenant_id,
                workspace=workspace,
                fingerprint=fp,
                team_id=team_id_v,
            )
            after = _fetch_governance_owner_team(conn, tenant_id=tenant_id, workspace=workspace, fingerprint=fp)

            _audit_log_event(
                conn,
                tenant_id=tenant_id,
                workspace=workspace,
                entity_type="finding",
                entity_id=fp,
                fingerprint=fp,
                event_type=("finding.team.cleared" if after.get("team_id") is None else "finding.team.assigned"),
                event_category="ownership",
                previous_value={"team_id": before.get("team_id")},
                new_value={"team_id": after.get("team_id")},
                actor_id=updated_by,
                actor_email=updated_by,
                actor_name=None,
                source="api",
            )
            conn.commit()

        return _ok(
            {
                "tenant_id": tenant_id,
                "workspace": workspace,
                "fingerprint": fp,
                "team_id": after.get("team_id"),
            }
        )
    except ValueError as exc:
        return _err("bad_request", str(exc), status=400)


@app.post("/api/findings/<fingerprint>/sla/extend")
def api_findings_extend_sla(fingerprint: str) -> Any:
    """Extend SLA deadline for a finding while preserving pause accounting."""
    try:
        payload = request.get_json(force=True, silent=False) or {}
        tenant_id, workspace = _require_scope_from_json(payload)
        fp = str(fingerprint or "").strip()
        if not fp:
            raise ValueError("fingerprint is required")

        extend_days = _coerce_positive_int(payload.get("extend_days"), field_name="extend_days")
        reason = _coerce_optional_text(payload.get("reason"))
        updated_by = _coerce_optional_text(payload.get("updated_by"))
        event_ts = _now_utc()

        with db_conn() as conn:
            if not _finding_exists(conn, tenant_id=tenant_id, workspace=workspace, fingerprint=fp):
                return _err("not_found", "finding not found", status=404)

            effective_state = _fetch_finding_effective_state(
                conn,
                tenant_id=tenant_id,
                workspace=workspace,
                fingerprint=fp,
            )
            if effective_state in {"resolved", "ignored"}:
                return _err("invalid_state", f"cannot extend SLA in state '{effective_state}'", status=409)

            _ensure_finding_governance_row(conn, tenant_id=tenant_id, workspace=workspace, fingerprint=fp)
            before = _fetch_governance_sla(conn, tenant_id=tenant_id, workspace=workspace, fingerprint=fp)
            after = _apply_finding_sla_extension(
                conn,
                tenant_id=tenant_id,
                workspace=workspace,
                fingerprint=fp,
                extend_days=extend_days,
                reason=reason,
                event_ts=event_ts,
            )
            if after is None:
                return _err("bad_request", "finding has no SLA policy to extend", status=400)

            _audit_log_event(
                conn,
                tenant_id=tenant_id,
                workspace=workspace,
                entity_type="finding",
                entity_id=fp,
                fingerprint=fp,
                event_type="finding.sla.extended",
                event_category="sla",
                previous_value=before,
                new_value=after,
                actor_id=updated_by,
                actor_email=updated_by,
                actor_name=None,
                source="api",
            )
            conn.commit()

        return _ok(
            {
                "tenant_id": tenant_id,
                "workspace": workspace,
                "fingerprint": fp,
                "extend_days": extend_days,
                "sla_deadline": after.get("sla_deadline"),
                "sla_breached_at": after.get("sla_breached_at"),
                "sla_extended_count": after.get("sla_extended_count"),
                "sla_extension_reason": after.get("sla_extension_reason"),
                "sla_extension_seconds": after.get("sla_extension_seconds"),
            }
        )
    except ValueError as exc:
        return _err("bad_request", str(exc), status=400)


@app.post("/api/lifecycle/group/ignore")
def api_lifecycle_group_ignore() -> Any:
    try:
        payload = request.get_json(force=True, silent=False) or {}
        tenant_id, workspace = _require_scope_from_json(payload)
        group_key = str(payload.get("group_key") or "").strip()
        if not group_key:
            raise ValueError("group_key is required")
        reason = payload.get("reason")
        updated_by = payload.get("updated_by")
        with db_conn() as conn:
            _upsert_group_state(
                conn,
                tenant_id=tenant_id,
                workspace=workspace,
                group_key=group_key,
                state="ignored",
                snooze_until=None,
                reason=reason,
                updated_by=updated_by,
            )
            _audit_lifecycle(
                conn,
                tenant_id=tenant_id,
                workspace=workspace,
                action="group_ignore",
                subject_type="group_key",
                subject_id=group_key,
                state="ignored",
                snooze_until=None,
                reason=reason,
                updated_by=updated_by,
            )
            conn.commit()
        return jsonify({"ok": True})
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400


@app.post("/api/lifecycle/group/resolve")
def api_lifecycle_group_resolve() -> Any:
    try:
        payload = request.get_json(force=True, silent=False) or {}
        tenant_id, workspace = _require_scope_from_json(payload)
        group_key = str(payload.get("group_key") or "").strip()
        if not group_key:
            raise ValueError("group_key is required")
        reason = payload.get("reason")
        updated_by = payload.get("updated_by")
        with db_conn() as conn:
            _upsert_group_state(
                conn,
                tenant_id=tenant_id,
                workspace=workspace,
                group_key=group_key,
                state="resolved",
                snooze_until=None,
                reason=reason,
                updated_by=updated_by,
            )
            _audit_lifecycle(
                conn,
                tenant_id=tenant_id,
                workspace=workspace,
                action="group_resolve",
                subject_type="group_key",
                subject_id=group_key,
                state="resolved",
                snooze_until=None,
                reason=reason,
                updated_by=updated_by,
            )
            conn.commit()
        return jsonify({"ok": True})
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400


@app.post("/api/lifecycle/group/snooze")
def api_lifecycle_group_snooze() -> Any:
    try:
        payload = request.get_json(force=True, silent=False) or {}
        tenant_id, workspace = _require_scope_from_json(payload)
        group_key = str(payload.get("group_key") or "").strip()
        if not group_key:
            raise ValueError("group_key is required")
        snooze_until_raw = payload.get("snooze_until")
        if not snooze_until_raw:
            raise ValueError("snooze_until is required (ISO 8601 timestamp)")
        snooze_until = _parse_iso8601_dt(snooze_until_raw, field_name="snooze_until")
        reason = payload.get("reason")
        updated_by = payload.get("updated_by")
        with db_conn() as conn:
            _upsert_group_state(
                conn,
                tenant_id=tenant_id,
                workspace=workspace,
                group_key=group_key,
                state="snoozed",
                snooze_until=snooze_until,
                reason=reason,
                updated_by=updated_by,
            )
            _audit_lifecycle(
                conn,
                tenant_id=tenant_id,
                workspace=workspace,
                action="group_snooze",
                subject_type="group_key",
                subject_id=group_key,
                state="snoozed",
                snooze_until=snooze_until,
                reason=reason,
                updated_by=updated_by,
            )
            conn.commit()
        return jsonify({"ok": True})
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

@app.get("/api/groups")
def api_groups() -> Any:
    """List grouped finding types.

    Groups are defined by finding_current.group_key (populated at ingest).
    """
    try:
        tenant_id, workspace = _require_scope_from_query()

        limit = _parse_int(_q("limit"), default=100, min_v=1, max_v=1000)
        offset = _parse_int(_q("offset"), default=0, min_v=0, max_v=5_000_000)

        effective_states = _parse_csv_list(_q("state"))  # open, snoozed, ignored, resolved
        categories = _parse_csv_list(_q("category"))
        services = _parse_csv_list(_q("service"))
        check_ids = _parse_csv_list(_q("check_id"))
        severities = _parse_csv_list(_q("severity"))
        q = _q("q")  # substring match on title (cheap)

        order = (_q("order", "savings_desc") or "savings_desc").lower()
        if order not in {"savings_desc", "count_desc"}:
            raise ValueError("order must be 'savings_desc' or 'count_desc'")

        where = ["tenant_id = %s", "workspace = %s", "group_key IS NOT NULL"]
        params: List[Any] = [tenant_id, workspace]

        def _add_any(field: str, values: Optional[List[str]]) -> None:
            if not values:
                return
            where.append(f"{field} = ANY(%s)")
            params.append(values)

        _add_any("effective_state", effective_states)
        _add_any("category", categories)
        _add_any("service", services)
        _add_any("check_id", check_ids)
        _add_any("severity", severities)

        if q:
            where.append("COALESCE(title, '') ILIKE %s")
            params.append(f"%{q}%")

        order_sql = "total_savings DESC NULLS LAST"
        if order == "count_desc":
            order_sql = "finding_count DESC"

        sql = f"""
            SELECT
              group_key,
              MIN(title) AS title,
              MIN(check_id) AS check_id,
              MIN(service) AS service,
              MIN(category) AS category,
              COUNT(*)::bigint AS finding_count,
              SUM(COALESCE(estimated_monthly_savings, 0))::double precision AS total_savings,
              MAX(
                CASE lower(COALESCE(severity,''))
                  WHEN 'critical' THEN 4
                  WHEN 'high' THEN 3
                  WHEN 'medium' THEN 2
                  WHEN 'low' THEN 1
                  ELSE 0
                END
              )::int AS max_severity_rank
            FROM finding_current
            WHERE {' AND '.join(where)}
            GROUP BY group_key
            ORDER BY {order_sql}
            LIMIT %s OFFSET %s
        """
        params2 = params + [limit, offset]

        with db_conn() as conn:
            groups = fetch_all_dict_conn(conn, sql, params2)
            count_row = fetch_one_dict_conn(
                conn,
                f"SELECT COUNT(DISTINCT group_key) AS n FROM finding_current WHERE {' AND '.join(where)}",
                params,
            )
            total = int(count_row["n"] or 0) if count_row else 0

        # Map rank back to a label (best-effort)
        for g in groups:
            rank = int(g.get("max_severity_rank") or 0)
            g["max_severity"] = {4: "critical", 3: "high", 2: "medium", 1: "low"}.get(rank, "unknown")

        return _json({"items": groups, "total": total, "limit": limit, "offset": offset})

    except ValueError as exc:
        return _json({"error": "bad_request", "message": str(exc)}, status=400)


@app.get("/api/groups/<group_key>")
def api_group_detail(group_key: str) -> Any:
    """Get one group summary + member findings (paginated)."""
    try:
        tenant_id, workspace = _require_scope_from_query()

        limit = _parse_int(_q("limit"), default=100, min_v=1, max_v=1000)
        offset = _parse_int(_q("offset"), default=0, min_v=0, max_v=5_000_000)

        effective_states = _parse_csv_list(_q("state"))
        q = _q("q")

        where = ["tenant_id = %s", "workspace = %s", "group_key = %s"]
        params: List[Any] = [tenant_id, workspace, group_key]

        if effective_states:
            where.append("effective_state = ANY(%s)")
            params.append(effective_states)

        if q:
            where.append("COALESCE(title, '') ILIKE %s")
            params.append(f"%{q}%")

        with db_conn() as conn:
            summary = fetch_one_dict_conn(
                conn,
                f"""
                SELECT
                  group_key,
                  MIN(title) AS title,
                  MIN(check_id) AS check_id,
                  MIN(service) AS service,
                  MIN(category) AS category,
                  COUNT(*)::bigint AS finding_count,
                  SUM(COALESCE(estimated_monthly_savings, 0))::double precision AS total_savings
                FROM finding_current
                WHERE {' AND '.join(where)}
                GROUP BY group_key
                """,
                params,
            )

            if not summary:
                return _json({"error": "not_found", "message": "group not found"}, status=404)

            members_sql = f"""
                SELECT
                  tenant_id, workspace, fingerprint, run_id,
                  check_id, service, severity, title,
                  estimated_monthly_savings, region, account_id,
                  category, group_key,
                  detected_at, state, snooze_until, reason, effective_state,
                  payload
                FROM finding_current
                WHERE {' AND '.join(where)}
                ORDER BY estimated_monthly_savings DESC NULLS LAST, detected_at DESC
                LIMIT %s OFFSET %s
            """
            members = fetch_all_dict_conn(conn, members_sql, params + [limit, offset])
            count_row = fetch_one_dict_conn(
                conn,
                f"SELECT COUNT(*) AS n FROM finding_current WHERE {' AND '.join(where)}",
                params,
            )
            total = int(count_row["n"] or 0) if count_row else 0

        return _json({"group": summary, "items": members, "total": total, "limit": limit, "offset": offset})

    except ValueError as exc:
        return _json({"error": "bad_request", "message": str(exc)}, status=400)

@app.post("/api/lifecycle/ignore")
def api_lifecycle_ignore() -> Any:
    try:
        payload = request.get_json(force=True, silent=False) or {}
        tenant_id, workspace = _require_scope_from_json(payload)
        fingerprint = str(payload.get("fingerprint") or "")
        if not fingerprint.strip():
            raise ValueError("fingerprint is required")
        reason = payload.get("reason")
        updated_by = payload.get("updated_by")
        with db_conn() as conn:
            _upsert_state(
                conn,
                tenant_id=tenant_id,
                workspace=workspace,
                fingerprint=fingerprint,
                state="ignored",
                snooze_until=None,
                reason=reason,
                updated_by=updated_by,
            )
            _audit_lifecycle(
                conn,
                tenant_id=tenant_id,
                workspace=workspace,
                action="ignore",
                subject_type="fingerprint",
                subject_id=fingerprint,
                state="ignored",
                snooze_until=None,
                reason=reason,
                updated_by=updated_by,
            )
            conn.commit()
        return jsonify({"ok": True})
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400


@app.post("/api/lifecycle/resolve")
def api_lifecycle_resolve() -> Any:
    try:
        payload = request.get_json(force=True, silent=False) or {}
        tenant_id, workspace = _require_scope_from_json(payload)
        fingerprint = str(payload.get("fingerprint") or "")
        if not fingerprint.strip():
            raise ValueError("fingerprint is required")
        reason = payload.get("reason")
        updated_by = payload.get("updated_by")
        with db_conn() as conn:
            _upsert_state(
                conn,
                tenant_id=tenant_id,
                workspace=workspace,
                fingerprint=fingerprint,
                state="resolved",
                snooze_until=None,
                reason=reason,
                updated_by=updated_by,
            )
            _audit_lifecycle(
                conn,
                tenant_id=tenant_id,
                workspace=workspace,
                action="resolve",
                subject_type="fingerprint",
                subject_id=fingerprint,
                state="resolved",
                snooze_until=None,
                reason=reason,
                updated_by=updated_by,
            )
            conn.commit()
        return jsonify({"ok": True})
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400


@app.post("/api/lifecycle/snooze")
def api_lifecycle_snooze() -> Any:
    try:
        payload = request.get_json(force=True, silent=False) or {}
        tenant_id, workspace = _require_scope_from_json(payload)
        fingerprint = str(payload.get("fingerprint") or "")
        if not fingerprint.strip():
            raise ValueError("fingerprint is required")
        snooze_until_raw = payload.get("snooze_until")
        if not snooze_until_raw:
            raise ValueError("snooze_until is required (ISO 8601 timestamp)")
        snooze_until = _parse_iso8601_dt(snooze_until_raw, field_name="snooze_until")
        reason = payload.get("reason")
        updated_by = payload.get("updated_by")
        with db_conn() as conn:
            _upsert_state(
                conn,
                tenant_id=tenant_id,
                workspace=workspace,
                fingerprint=fingerprint,
                state="snoozed",
                snooze_until=snooze_until,
                reason=reason,
                updated_by=updated_by,
            )
            _audit_lifecycle(
                conn,
                tenant_id=tenant_id,
                workspace=workspace,
                action="snooze",
                subject_type="fingerprint",
                subject_id=fingerprint,
                state="snoozed",
                snooze_until=snooze_until,
                reason=reason,
                updated_by=updated_by,
            )
            conn.commit()
        return jsonify({"ok": True})
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400


_versioned_aliases_registered = False


def _register_versioned_api_aliases() -> None:
    """Register `/api/<version>/...` aliases for all existing `/api/...` routes."""
    global _versioned_aliases_registered
    if _versioned_aliases_registered:
        return

    existing_rules = {str(rule.rule or "") for rule in app.url_map.iter_rules()}
    rules = list(app.url_map.iter_rules())
    for rule in rules:
        raw_path = str(rule.rule or "")
        if not raw_path.startswith("/api/"):
            continue
        if re.match(r"^/api/v\d+(?:/|$)", raw_path):
            continue

        versioned_path = f"{_API_PREFIX}{raw_path[len('/api'):]}"
        if versioned_path in existing_rules:
            continue

        view_func = app.view_functions.get(rule.endpoint)
        if view_func is None:
            continue

        methods = sorted(m for m in (rule.methods or set()) if m not in {"HEAD", "OPTIONS"})
        if not methods:
            continue

        alias_endpoint = f"{rule.endpoint}__{_API_VERSION}"
        app.add_url_rule(
            versioned_path,
            endpoint=alias_endpoint,
            view_func=view_func,
            methods=methods,
            strict_slashes=rule.strict_slashes,
        )
        existing_rules.add(versioned_path)

    _versioned_aliases_registered = True


_register_versioned_api_aliases()


if __name__ == "__main__":
    port = int(os.getenv("PORT", "5000"))
    app.run(host="0.0.0.0", port=port)
