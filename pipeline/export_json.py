from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import date, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any, Dict, List

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
    findings_glob: str                  # ex: data/finops_findings/**/**/**.parquet
    tenant_id: str
    out_dir: str = "webapp_data"        # directory where JSON files are written
    limit_findings: int = 500           # safety limit


class FinOpsJsonExporter:
    def __init__(self, cfg: ExportConfig) -> None:
        self.cfg = cfg
        self.con = duckdb.connect(":memory:")
        self.con.execute("PRAGMA threads=4;")

    def close(self) -> None:
        self.con.close()

    def _findings_rel(self) -> str:
        return f"read_parquet('{self.cfg.findings_glob}', union_by_name=True)"

    # -------------------------
    # Exports
    # -------------------------

    def export_findings(self) -> None:
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
            tags
        FROM {self._findings_rel()}
        WHERE tenant_id = ?
        ORDER BY run_ts DESC
        LIMIT ?;
        """
        cur = self.con.execute(sql, [self.cfg.tenant_id, self.cfg.limit_findings])
        rows = cur.fetchall()
        cols = [d[0] for d in cur.description]

        data = _rows_to_jsonable(cols, rows)
        self._write_json("findings.json", data)

    def export_summary(self) -> None:
        sql = f"""
        SELECT
            status,
            severity.level AS severity_level,
            count(*) AS count
        FROM {self._findings_rel()}
        WHERE tenant_id = ?
        GROUP BY 1, 2
        ORDER BY 1, 2;
        """
        cur = self.con.execute(sql, [self.cfg.tenant_id])
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
        sql = f"""
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
        FROM {self._findings_rel()}
        WHERE tenant_id = ?
          AND status = 'fail'
          AND estimated.monthly_savings IS NOT NULL
        ORDER BY estimated.monthly_savings DESC
        LIMIT 50;
        """
        cur = self.con.execute(sql, [self.cfg.tenant_id])
        rows = cur.fetchall()
        cols = [d[0] for d in cur.description]

        data = _rows_to_jsonable(cols, rows)
        self._write_json("top_savings.json", data)

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
    finally:
        exporter.close()
