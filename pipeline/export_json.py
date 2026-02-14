"""DuckDB-powered JSON export.

The Flask UI (and other thin consumers) read pre-materialized JSON files.
This module loads the Parquet datasets (raw + correlated + optionally enriched)
into DuckDB and writes a few JSON artifacts (summary, top savings, findings
lists, coverage).
"""

from __future__ import annotations

import glob as _glob
import json
from dataclasses import dataclass
from datetime import date, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any, Dict, List, Optional

import duckdb


def _json_default(obj: Any) -> Any:
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    if isinstance(obj, Decimal):
        return str(obj)
    return str(obj)


def _rows_to_jsonable(cols: List[str], rows: List[tuple]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for row in rows:
        rec: Dict[str, Any] = {}
        for k, v in zip(cols, row):
            if isinstance(v, (datetime, date)):
                rec[k] = v.isoformat()
            elif isinstance(v, Decimal):
                rec[k] = str(v)
            else:
                rec[k] = v
        out.append(rec)
    return out


@dataclass(frozen=True)
class ExportConfig:
    tenant_id: str
    out_dir: str = "webapp_data"
    limit_findings: int = 500

    # Back-compat single glob
    findings_glob: str = ""

    # Preferred for multiple datasets
    findings_globs: Optional[List[str]] = None

    # Optional: also export correlated-only JSON
    export_correlated: bool = True


class FinOpsJsonExporter:
    """
    Export parquet findings datasets to JSON files for the Flask app.

    Behavior:
      - If an enriched dataset exists (data/finops_findings_enriched/**/*.parquet),
        and the caller is exporting the standard raw/correlated datasets, the exporter
        automatically switches to the enriched dataset.
      - Always exports: findings.json, summary.json, top_savings.json, coverage.json
      - Optionally exports: correlated_findings.json
    """

    ENRICHED_GLOB = "data/finops_findings_enriched/**/*.parquet"
    STANDARD_RAW_GLOB = "data/finops_findings/**/*.parquet"
    STANDARD_CORR_GLOB = "data/finops_findings_correlated/**/*.parquet"

    def __init__(self, cfg: ExportConfig) -> None:
        self.cfg = cfg
        self.con = duckdb.connect(":memory:")
        self.con.execute("PRAGMA threads=4;")
        self.con.execute("PRAGMA enable_progress_bar=false;")

        globs = self._effective_globs()

        # If enriched exists and caller is exporting standard datasets, prefer enriched.
        if (self.ENRICHED_GLOB not in globs) and self._glob_has_files(self.ENRICHED_GLOB):
            standard = {self.STANDARD_RAW_GLOB, self.STANDARD_CORR_GLOB}
            if any(g in standard for g in globs):
                print("[export_json] enriched dataset detected, using it for export")
                globs = [self.ENRICHED_GLOB]

        self._globs_used = globs
        self._files = self._expand_globs_to_files(globs)
        if not self._files:
            raise ValueError("No parquet files matched findings_glob(s). Check your paths/globs.")

        print(f"[export_json] matched parquet files: {len(self._files)}")

        # Fail fast if the tenant doesn't exist in the dataset (avoids silently
        # producing empty JSON artifacts).
        self._preflight_tenant()

    def _preflight_tenant(self) -> None:
        sql = """
        WITH all_rows AS (
            SELECT tenant_id FROM read_parquet(?, union_by_name=true)
        )
        SELECT tenant_id, count(*) AS n
        FROM all_rows
        GROUP BY 1
        ORDER BY 2 DESC;
        """
        cur = self.con.execute(sql, [self._files])
        rows = cur.fetchall() or []
        tenants = {str(r[0]): int(r[1] or 0) for r in rows if r and r[0] is not None}

        if not tenants:
            # Unlikely, but be explicit.
            raise ValueError("No rows found in parquet datasets.")

        if self.cfg.tenant_id not in tenants:
            preview = ", ".join([f"{k}({v})" for k, v in list(tenants.items())[:6]])
            raise ValueError(
                "Export tenant_id does not exist in parquet datasets. "
                f"requested={self.cfg.tenant_id!r}, available={preview or 'none'}"
            )

    def close(self) -> None:
        self.con.close()

    def _effective_globs(self) -> List[str]:
        if self.cfg.findings_globs:
            globs = [str(x).strip() for x in self.cfg.findings_globs if str(x).strip()]
            if globs:
                return globs
        if str(self.cfg.findings_glob).strip():
            return [str(self.cfg.findings_glob).strip()]
        raise ValueError("ExportConfig must set findings_glob or findings_globs")

    @staticmethod
    def _glob_has_files(glob_pattern: str) -> bool:
        return bool(_glob.glob(glob_pattern, recursive=True))

    @staticmethod
    def _expand_globs_to_files(globs: List[str]) -> List[str]:
        files: List[str] = []
        for g in globs:
            matches = _glob.glob(g, recursive=True)
            for m in matches:
                if m.endswith(".parquet"):
                    files.append(m)
        return sorted(set(files))

    # -------------------------
    # Exports
    # -------------------------

    def export_findings(self) -> None:
        sql = """
        WITH findings_all AS (
            SELECT * FROM read_parquet(?, union_by_name=true)
        )
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
            estimated.monthly_cost AS est_monthly_cost,
            estimated.monthly_savings AS est_monthly_savings,
            estimated.confidence AS est_confidence,
            actual.cost_30d AS actual_cost_30d,
            actual.attribution.method AS attribution_method,
            tags,
            source.source_ref AS source_ref
        FROM findings_all
        WHERE tenant_id = ?
        ORDER BY run_ts DESC
        LIMIT ?;
        """
        cur = self.con.execute(sql, [self._files, self.cfg.tenant_id, self.cfg.limit_findings])
        rows = cur.fetchall()
        cols = [d[0] for d in cur.description]
        self._write_json("findings.json", _rows_to_jsonable(cols, rows))

    def export_summary(self) -> None:
        sql = """
        WITH findings_all AS (
            SELECT * FROM read_parquet(?, union_by_name=true)
        )
        SELECT
            status,
            severity.level AS severity_level,
            count(*) AS count
        FROM findings_all
        WHERE tenant_id = ?
        GROUP BY 1, 2
        ORDER BY 1, 2;
        """
        cur = self.con.execute(sql, [self._files, self.cfg.tenant_id])
        rows = cur.fetchall()
        cols = [d[0] for d in cur.description]
        matrix = _rows_to_jsonable(cols, rows)

        summary: Dict[str, Any] = {
            "tenant_id": self.cfg.tenant_id,
            "by_status": {},
            "by_severity": {},
            "matrix": matrix,
        }

        for r in matrix:
            summary["by_status"][r["status"]] = summary["by_status"].get(r["status"], 0) + r["count"]
            sev = r["severity_level"]
            summary["by_severity"][sev] = summary["by_severity"].get(sev, 0) + r["count"]

        self._write_json("summary.json", summary)

    def export_top_savings(self) -> None:
        sql = """
        WITH findings_all AS (
            SELECT * FROM read_parquet(?, union_by_name=true)
        )
        SELECT
            finding_id,
            check_id,
            check_name,
            severity.level AS severity_level,
            scope.service AS service,
            scope.resource_type AS resource_type,
            scope.resource_id AS resource_id,
            title,
            estimated.monthly_savings AS est_monthly_savings,
            estimated.confidence AS est_confidence
        FROM findings_all
        WHERE tenant_id = ?
          AND status = 'fail'
          AND estimated.monthly_savings IS NOT NULL
        ORDER BY estimated.monthly_savings DESC
        LIMIT 50;
        """
        cur = self.con.execute(sql, [self._files, self.cfg.tenant_id])
        rows = cur.fetchall()
        cols = [d[0] for d in cur.description]
        self._write_json("top_savings.json", _rows_to_jsonable(cols, rows))

    def export_coverage(self) -> None:
        sql = """
        WITH findings_all AS (
            SELECT * FROM read_parquet(?, union_by_name=true)
        ),
        base AS (
            SELECT
                *,
                (actual.cost_30d IS NOT NULL) AS has_actual_cost
            FROM findings_all
            WHERE tenant_id = ?
        )
        SELECT
            count(*) AS findings_total,
            sum(CASE WHEN has_actual_cost THEN 1 ELSE 0 END) AS findings_with_actual_cost,
            round(
                100.0 * sum(CASE WHEN has_actual_cost THEN 1 ELSE 0 END) / NULLIF(count(*), 0),
                2
            ) AS actual_cost_coverage_pct
        FROM base;
        """
        cur = self.con.execute(sql, [self._files, self.cfg.tenant_id])
        row = cur.fetchone() or (0, 0, 0.0)

        enriched_used = any("finops_findings_enriched" in g for g in getattr(self, "_globs_used", []))
        payload = {
            "tenant_id": self.cfg.tenant_id,
            "dataset": "enriched" if enriched_used else "raw_union",
            "findings_total": int(row[0] or 0),
            "findings_with_actual_cost": int(row[1] or 0),
            "actual_cost_coverage_pct": float(row[2] or 0.0),
        }
        self._write_json("coverage.json", payload)

    def export_correlated_findings(self) -> None:
        sql = """
        WITH findings_all AS (
            SELECT * FROM read_parquet(?, union_by_name=true)
        )
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
            status,
            severity.level AS severity_level,
            severity.score AS severity_score,
            scope.account_id AS account_id,
            scope.region AS region,
            scope.service AS service,
            scope.resource_type AS resource_type,
            scope.resource_id AS resource_id,
            title,
            message,
            recommendation,
            estimated.monthly_cost AS est_monthly_cost,
            estimated.monthly_savings AS est_monthly_savings,
            estimated.confidence AS est_confidence,
            actual.cost_30d AS actual_cost_30d,
            actual.attribution.method AS attribution_method,
            source.source_ref AS source_ref
        FROM findings_all
        WHERE tenant_id = ?
          AND source.source_ref LIKE 'correlation:%'
        ORDER BY run_ts DESC
        LIMIT ?
        """
        cur = self.con.execute(sql, [self._files, self.cfg.tenant_id, self.cfg.limit_findings])
        rows = cur.fetchall()
        cols = [d[0] for d in cur.description]
        self._write_json("correlated_findings.json", _rows_to_jsonable(cols, rows))

    # -------------------------
    # Utils
    # -------------------------

    def _write_json(self, filename: str, payload: Any) -> None:
        out_dir = Path(self.cfg.out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        path = out_dir / filename
        with path.open("w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False, default=_json_default)
        print(f"[OK] wrote {path}")


def run_export(cfg: ExportConfig) -> None:
    exporter = FinOpsJsonExporter(cfg)
    try:
        exporter.export_findings()
        exporter.export_summary()
        exporter.export_top_savings()
        exporter.export_coverage()
        if cfg.export_correlated:
            exporter.export_correlated_findings()
    finally:
        exporter.close()
