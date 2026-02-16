"""Runs Blueprint.

Provides run management endpoints for querying runs and computing diffs.
"""

from typing import Any

from flask import Blueprint, jsonify

from apps.backend.db import db_conn, fetch_all_dict_conn, fetch_one_dict_conn
from apps.flask_api.utils import _json, _require_scope_from_query

# Create the blueprint
runs_bp = Blueprint("runs", __name__)


@runs_bp.route("/api/runs/latest", methods=["GET"])
def api_runs_latest() -> Any:
    """Get the latest run for a tenant/workspace.

    Query params:
        tenant_id (required): Tenant identifier
        workspace (required): Workspace identifier

    Returns:
        JSON with run details or error
    """
    try:
        tenant_id, workspace = _require_scope_from_query()
        with db_conn() as conn:
            row = fetch_one_dict_conn(
                conn,
                """
                SELECT tenant_id, workspace, run_id, run_ts, status, artifact_prefix,
                       ingested_at, engine_version, pricing_version, pricing_source,
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


@runs_bp.route("/api/runs/diff/latest", methods=["GET"])
def api_runs_diff_latest() -> Any:
    """Compute a best-effort diff between the latest two *ready* runs.

    Returns counts for:
    - new: fingerprints present in latest run but not in previous
    - disappeared: fingerprints present in previous run but not in latest

    Notes:
    - Uses finding_presence for membership (history).
    - Attributes category/check_id/service from finding_current (canonical read model).

    Query params:
        tenant_id (required): Tenant identifier
        workspace (required): Workspace identifier

    Returns:
        JSON with diff results or error
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

        def _rollup(rows: list[dict[str, Any]]) -> dict[str, Any]:
            total = 0
            by_cat: dict[str, int] = {}
            by_check: dict[str, int] = {}
            by_svc: dict[str, int] = {}
            for r in rows:
                c = int(r.get("count") or 0)
                total += c
                cat = str(r.get("category") or "other")
                chk = str(r.get("check_id") or "unknown")
                svc = str(r.get("service") or "unknown")
                by_cat[cat] = by_cat.get(cat, 0) + c
                by_check[chk] = by_check.get(chk, 0) + c
                by_svc[svc] = by_svc.get(svc, 0) + c
            return {
                "count": total,
                "by_category": by_cat,
                "by_check_id": by_check,
                "by_service": by_svc,
                "rows": rows,
            }

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
