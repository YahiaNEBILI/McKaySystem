from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from db import execute, execute_many, fetch_one


DEFAULT_EXPORT_DIR = Path("webapp_data/")


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_dt(value: str) -> Optional[datetime]:
    v = (value or "").strip()
    if not v:
        return None
    try:
        dt = datetime.fromisoformat(v.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def _norm(s: Any) -> str:
    if s is None:
        return ""
    return str(s).strip()


def _lower(s: Any) -> str:
    return _norm(s).lower()


def _to_float(v: Any) -> Optional[float]:
    """Best-effort numeric parsing for savings/cost fields."""
    if v is None:
        return None
    if isinstance(v, (int, float)):
        return float(v)
    if isinstance(v, dict):
        for k in ("amount", "value", "usd", "eur"):
            if k in v:
                return _to_float(v.get(k))
        return None
    try:
        s = str(v).strip()
        if not s:
            return None
        s = re.sub(r"[^0-9,\.-]", "", s)
        if s.count(",") == 1 and s.count(".") == 0:
            s = s.replace(",", ".")
        if s.count(",") >= 1 and s.count(".") >= 1:
            s = s.replace(",", "")
        return float(s)
    except Exception:
        return None


def _pick_latest_json(export_dir: Path) -> Path:
    if not export_dir.exists():
        raise FileNotFoundError(f"export dir not found: {export_dir}")
    candidates = sorted(export_dir.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not candidates:
        raise FileNotFoundError(f"no .json files in {export_dir}")
    for name in ("results.json", "export.json", "findings.json"):
        for p in candidates:
            if p.name == name:
                return p
    return candidates[0]


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _extract_items(payload: Any) -> List[Dict[str, Any]]:
    if isinstance(payload, list):
        return [x for x in payload if isinstance(x, dict)]
    if isinstance(payload, dict):
        for key in ("recommendations", "findings", "items"):
            v = payload.get(key)
            if isinstance(v, list):
                return [x for x in v if isinstance(x, dict)]
    return []


def _extract_run_meta(payload: Any, file_path: Path) -> Tuple[str, str, str, datetime, Optional[str]]:
    tenant_id = ""
    workspace = ""
    run_id = ""
    run_ts: Optional[datetime] = None
    engine_version: Optional[str] = None

    if isinstance(payload, dict):
        tenant_id = _norm(payload.get("tenant_id") or payload.get("tenant") or payload.get("org"))
        workspace = _norm(payload.get("workspace") or payload.get("workspace_id") or payload.get("workspaceId"))
        run_id = _norm(payload.get("run_id") or payload.get("run") or payload.get("id"))
        engine_version = _norm(payload.get("engine_version") or payload.get("version") or "") or None
        run_ts = _parse_dt(_norm(payload.get("run_ts") or payload.get("run_time") or payload.get("generated_at") or ""))

    if not tenant_id:
        tenant_id = os.getenv("TENANT_ID", "default")
    if not workspace:
        workspace = os.getenv("WORKSPACE", "default")

    if run_ts is None:
        run_ts = datetime.fromtimestamp(file_path.stat().st_mtime, tz=timezone.utc)

    if not run_id:
        run_id = f"run_{run_ts.strftime('%Y%m%dT%H%M%SZ')}"

    return tenant_id, workspace, run_id, run_ts, engine_version


def _fingerprint(item: Dict[str, Any]) -> str:
    for key in ("fingerprint", "finding_id", "id", "issue_fingerprint"):
        v = item.get(key)
        if v:
            return _norm(v)
    return ""


def _guess_fields(
    item: Dict[str, Any],
) -> Tuple[Optional[str], Optional[str], Optional[str], Optional[str], Optional[float], Optional[str], Optional[str]]:
    check_id = _norm(item.get("check_id") or item.get("checkId") or "") or None
    service = _norm(item.get("service") or item.get("provider_service") or "") or None
    severity = _norm(item.get("severity") or item.get("severity_level") or "") or None
    title = _norm(item.get("title") or item.get("message") or item.get("summary") or "") or None

    savings = item.get("estimated_monthly_savings")
    if savings is None:
        savings = item.get("est_monthly_savings")
    if savings is None:
        savings = item.get("monthly_savings")
    if savings is None:
        savings = item.get("estimated_monthly_savings_usd")
    if savings is None:
        savings = item.get("estimated_monthly_savings_eur")

    if savings is None:
        cost_obj = item.get("cost") or item.get("costs")
        if isinstance(cost_obj, dict):
            savings = cost_obj.get("estimated_monthly_savings") or cost_obj.get("estimated_savings")

    savings_f = _to_float(savings)

    region = _norm(item.get("region") or item.get("aws_region") or "") or None
    account_id = _norm(item.get("account_id") or item.get("aws_account_id") or item.get("account") or "") or None

    return check_id, service, severity, title, savings_f, region, account_id


def ingest_latest_export() -> None:
    export_dir = Path(os.getenv("EXPORT_DIR", str(DEFAULT_EXPORT_DIR)))
    file_path = _pick_latest_json(export_dir)
    payload = _load_json(file_path)

    tenant_id, workspace, run_id, run_ts, engine_version = _extract_run_meta(payload, file_path)

    existing = fetch_one(
        "SELECT status FROM runs WHERE tenant_id=%s AND workspace=%s AND run_id=%s",
        (tenant_id, workspace, run_id),
    )
    if existing and existing[0] == "ready":
        print(f"SKIP: run already ingested: {tenant_id}/{workspace}/{run_id}")
        return

    artifact_prefix = str(file_path)

    execute(
        """
        INSERT INTO runs (tenant_id, workspace, run_id, run_ts, status, artifact_prefix, ingested_at, engine_version,
                          raw_present, correlated_present, enriched_present)
        VALUES (%s, %s, %s, %s, 'ingesting', %s, NULL, %s, FALSE, FALSE, FALSE)
        ON CONFLICT (tenant_id, workspace, run_id) DO UPDATE SET
          run_ts = EXCLUDED.run_ts,
          status = 'ingesting',
          artifact_prefix = EXCLUDED.artifact_prefix,
          engine_version = EXCLUDED.engine_version
        """,
        (tenant_id, workspace, run_id, run_ts, artifact_prefix, engine_version),
    )

    items = _extract_items(payload)

    # Re-ingesting a run should be idempotent for finding_presence
    execute(
        "DELETE FROM finding_presence WHERE tenant_id=%s AND workspace=%s AND run_id=%s",
        (tenant_id, workspace, run_id),
    )

    presence_rows: List[Tuple[Any, ...]] = []
    latest_rows: List[Tuple[Any, ...]] = []

    for it in items:
        if not isinstance(it, dict):
            continue

        fp = _fingerprint(it)
        if not fp:
            continue

        check_id, service, severity, title, savings_f, region, account_id = _guess_fields(it)

        # 1) presence rows (run membership + fast KPI aggregation)
        presence_rows.append(
            (
                tenant_id,
                workspace,
                run_id,
                fp,
                check_id,
                service,
                severity,
                title,
                savings_f,
                region,
                account_id,
                run_ts,
            )
        )

        # 2) latest snapshot rows (full payload for UI/detail drilldowns)
        # Store the full finding object as JSONB.
        payload_json = json.dumps(it, ensure_ascii=False, separators=(",", ":"))
        latest_rows.append(
            (
                tenant_id,
                workspace,
                fp,
                run_id,
                check_id,
                service,
                severity,
                title,
                savings_f,
                region,
                account_id,
                payload_json,
                run_ts,
            )
        )

    execute_many(
        """
        INSERT INTO finding_presence
          (tenant_id, workspace, run_id, fingerprint, check_id, service, severity, title,
           estimated_monthly_savings, region, account_id, detected_at)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """,
        presence_rows,
    )

    # Upsert full payload into finding_latest (one row per fingerprint for latest snapshot)
    # NOTE: This expects a table:
    #   finding_latest(tenant_id, workspace, fingerprint PRIMARY KEY, ..., payload JSONB, detected_at, run_id, ...)
    execute_many(
        """
        INSERT INTO finding_latest
          (tenant_id, workspace, fingerprint, run_id,
           check_id, service, severity, title,
           estimated_monthly_savings, region, account_id,
           payload, detected_at)
        VALUES
          (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb,%s)
        ON CONFLICT (tenant_id, workspace, fingerprint) DO UPDATE SET
          run_id = EXCLUDED.run_id,
          check_id = EXCLUDED.check_id,
          service = EXCLUDED.service,
          severity = EXCLUDED.severity,
          title = EXCLUDED.title,
          estimated_monthly_savings = EXCLUDED.estimated_monthly_savings,
          region = EXCLUDED.region,
          account_id = EXCLUDED.account_id,
          payload = EXCLUDED.payload,
          detected_at = EXCLUDED.detected_at
        """,
        latest_rows,
    )

    execute(
        "UPDATE runs SET status='ready', ingested_at=NOW() WHERE tenant_id=%s AND workspace=%s AND run_id=%s",
        (tenant_id, workspace, run_id),
    )

    print(
        f"OK: ingested {len(presence_rows)} items from {file_path.name} as run {tenant_id}/{workspace}/{run_id} "
        f"(presence={len(presence_rows)}, latest={len(latest_rows)})"
    )


def main() -> None:
    ingest_latest_export()


if __name__ == "__main__":
    main()
