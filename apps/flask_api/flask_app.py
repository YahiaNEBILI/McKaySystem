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

import hmac
import json
import os
import threading
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from flask import Flask, Response, abort, jsonify, request

from apps.backend.db import (
    db_conn,
    execute_conn,
    fetch_one_dict_conn,
    fetch_all_dict_conn,
)

app = Flask(__name__)


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
    """Emit a single-line JSON log to stdout."""
    level_u = (level or "INFO").upper()
    order = {"ERROR": 3, "WARN": 2, "INFO": 1}
    if order.get(level_u, 1) < order.get(_API_LOG_LEVEL, 1):
        return
    payload: Dict[str, Any] = {"ts": _iso_z(_now_utc()), "level": level_u, "event": event}
    payload.update(fields)
    print(json.dumps(payload, ensure_ascii=False, separators=(",", ":")))


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
    except Exception:
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
    except Exception:
        pass

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
    path = request.path or ""
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
    path = request.path or ""
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
    path = request.path or ""
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
    if _API_DEBUG_ERRORS:
        tb = traceback.format_exc()
        _log("ERROR", "unhandled_exception", {"path": request.path, "detail": str(exc), "traceback": tb})
        return _err("internal_error", "internal error", status=500, extra={"detail": str(exc), "traceback": tb})
    _log("ERROR", "unhandled_exception", {"path": request.path, "detail": str(exc)})
    return _err("internal_error", "internal error", status=500)

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
    path = request.path or ""
    if not path.startswith("/api/"):
        return
    if path in {"/api/health/db"}:
        return
    _check_bearer_token()


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

# --------------------
# Health / meta routes
# --------------------

@app.get("/health")
def health() -> Any:
    return jsonify({"ok": True})


@app.get("/api/health/db")
def api_health_db() -> Any:
    try:
        with db_conn() as conn:
            row = fetch_one_dict_conn(conn, "SELECT 1 AS ok")
        return _ok({"db": bool(row and row.get("ok") == 1)})
    except Exception as exc:
        if _API_DEBUG_ERRORS:
            return _err("db_unhealthy", "db health check failed", status=500, extra={"detail": str(exc)})
        return _err("db_unhealthy", "db health check failed", status=500)


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
    except Exception as exc:
        return _json({"error": "internal_error", "message": str(exc)}, status=500)

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
        regions = _parse_csv_list(_q("region"))
        account_ids = _parse_csv_list(_q("account_id"))
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
        _add_any("region", regions)
        _add_any("account_id", account_ids)

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
    except Exception as exc:
        extra = None
        if _API_DEBUG_ERRORS:
            extra = {"detail": str(exc), "traceback": traceback.format_exc()}
        return _err("internal_error", "internal error", status=500, extra=extra)


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
    except Exception as exc:
        return jsonify({"error": "internal_error", "detail": str(exc)}), 500


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
    except Exception as exc:
        return jsonify({"error": "internal_error", "detail": str(exc)}), 500


# --------------------
# Lifecycle actions
# --------------------


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

    Always logs to stdout. Best-effort insert into finding_state_audit.
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
    except Exception as exc:
        return jsonify({"error": "internal_error", "detail": str(exc)}), 500


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
    except Exception as exc:
        return jsonify({"error": "internal_error", "detail": str(exc)}), 500


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
    except Exception as exc:
        return jsonify({"error": "internal_error", "detail": str(exc)}), 500

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
    except Exception as exc:
        return _json({"error": "internal_error", "message": str(exc)}, status=500)


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
    except Exception as exc:
        return _json({"error": "internal_error", "message": str(exc)}, status=500)

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
    except Exception as exc:
        return jsonify({"error": "internal_error", "detail": str(exc)}), 500


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
    except Exception as exc:
        return jsonify({"error": "internal_error", "detail": str(exc)}), 500


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
    except Exception as exc:
        return jsonify({"error": "internal_error", "detail": str(exc)}), 500


if __name__ == "__main__":
    port = int(os.getenv("PORT", "5000"))
    app.run(host="0.0.0.0", port=port)
