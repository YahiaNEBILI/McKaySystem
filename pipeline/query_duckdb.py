"""Thin wrapper utilities around DuckDB.

Kept separate so higher-level pipeline modules can depend on a small surface
area (connection creation, safe parameter handling, convenience helpers).
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import date, datetime
from decimal import Decimal
from typing import Any

import duckdb


def _json_default(obj: Any) -> Any:
    """JSON serializer for datetime/Decimal returned by DuckDB."""
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    if isinstance(obj, Decimal):
        return str(obj)
    return str(obj)


def _as_jsonable_row(row: Mapping[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in row.items():
        if v is None:
            out[k] = None
        elif isinstance(v, (datetime, date)):
            out[k] = v.isoformat()
        elif isinstance(v, Decimal):
            out[k] = str(v)
        else:
            out[k] = v
    return out


@dataclass(frozen=True)
class DuckDBConfig:
    findings_glob: str  # ex: "data/finops_findings/**/**/**.parquet"
    database: str = ":memory:"  # can be a file path later
    threads: int = 4


class DuckDBClient:
    """
    Minimal DuckDB query layer for finops_findings Parquet datasets.
    """

    def __init__(self, cfg: DuckDBConfig) -> None:
        self._cfg = cfg
        self._con = duckdb.connect(cfg.database, read_only=False)
        self._con.execute(f"PRAGMA threads={int(cfg.threads)};")

    def close(self) -> None:
        self._con.close()

    # -------------------------
    # Internal helpers
    # -------------------------

    def _findings_rel(self) -> str:
        # Single source of truth for reading findings
        # union_by_name allows schema evolution (new columns later)
        return f"read_parquet('{self._cfg.findings_glob}', union_by_name=True)"

    def _exec(self, sql: str, params: Sequence[Any]) -> list[dict[str, Any]]:
        cur = self._con.execute(sql, params)
        cols = [d[0] for d in cur.description]
        rows = cur.fetchall()
        out: list[dict[str, Any]] = []
        for r in rows:
            out.append(_as_jsonable_row(dict(zip(cols, r, strict=False))))
        return out

    # -------------------------
    # Public API queries
    # -------------------------

    def list_findings(
        self,
        *,
        tenant_id: str,
        status: str | None = None,
        category: str | None = None,
        severity_level: str | None = None,
        limit: int = 200,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """
        List findings (flattened fields for UI).
        """
        where = ["tenant_id = ?"]
        params: list[Any] = [tenant_id]

        if status:
            where.append("status = ?")
            params.append(status)
        if category:
            where.append("category = ?")
            params.append(category)
        if severity_level:
            where.append("severity.level = ?")
            params.append(severity_level)

        where_sql = " AND ".join(where)

        # Note: DuckDB supports struct field access with dot syntax.
        sql = f"""
        SELECT
            tenant_id,
            workspace_id,
            finding_id,
            fingerprint,
            run_id,
            run_ts,
            check_id,
            check_name,
            category,
            sub_category,
            status,
            severity.level AS severity_level,
            severity.score AS severity_score,
            scope.cloud AS cloud,
            scope.account_id AS account_id,
            scope.region AS region,
            scope.service AS service,
            scope.resource_type AS resource_type,
            scope.resource_id AS resource_id,
            title,
            message,
            recommendation,
            estimated.monthly_savings AS est_monthly_savings,
            estimated.confidence AS est_confidence,
            actual.cost_30d AS actual_cost_30d,
            actual.attribution.method AS attribution_method,
            actual.attribution.confidence AS attribution_confidence
        FROM {self._findings_rel()}
        WHERE {where_sql}
        ORDER BY run_ts DESC
        LIMIT ? OFFSET ?;
        """
        params.extend([int(limit), int(offset)])
        return self._exec(sql, params)

    def findings_summary(
        self,
        *,
        tenant_id: str,
    ) -> dict[str, Any]:
        """
        Basic KPI summary for a tenant (counts by status and severity).
        """
        sql = f"""
        SELECT
            status,
            severity.level AS severity_level,
            count(*) AS cnt
        FROM {self._findings_rel()}
        WHERE tenant_id = ?
        GROUP BY 1, 2
        ORDER BY 1, 2;
        """
        rows = self._exec(sql, [tenant_id])

        # Reshape to something API-friendly
        out: dict[str, Any] = {"tenant_id": tenant_id, "by_status": {}, "by_severity": {}, "matrix": rows}
        for r in rows:
            st = r["status"]
            sev = r["severity_level"]
            cnt = int(r["cnt"])
            out["by_status"][st] = out["by_status"].get(st, 0) + cnt
            out["by_severity"][sev] = out["by_severity"].get(sev, 0) + cnt
        return out

    def top_savings(
        self,
        *,
        tenant_id: str,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """
        Top savings opportunities by estimated.monthly_savings (DESC).
        """
        sql = f"""
        SELECT
            finding_id,
            fingerprint,
            check_id,
            check_name,
            status,
            severity.level AS severity_level,
            scope.service AS service,
            scope.resource_type AS resource_type,
            scope.resource_id AS resource_id,
            title,
            estimated.monthly_savings AS est_monthly_savings,
            estimated.confidence AS est_confidence
        FROM {self._findings_rel()}
        WHERE tenant_id = ?
          AND status = 'fail'
          AND estimated.monthly_savings IS NOT NULL
        ORDER BY estimated.monthly_savings DESC
        LIMIT ?;
        """
        return self._exec(sql, [tenant_id, int(limit)])

    def to_json(self, obj: Any) -> str:
        """
        Serialize query outputs to JSON.
        """
        return json.dumps(obj, default=_json_default, ensure_ascii=False)
