from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Sequence

from db import execute, execute_many, fetch_one
from pipeline.run_manifest import load_manifest, manifest_path


DEFAULT_EXPORT_DIR = Path("webapp_data/")


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
    """Pick the most relevant export JSON file.

    Preference order:
    - findings_full.json (unbounded, if you generate it)
    - findings.json (bounded UI list)
    - results.json / export.json (legacy)
    - newest .json by mtime
    """
    if not export_dir.exists():
        raise FileNotFoundError(f"export dir not found: {export_dir}")
    candidates = sorted(export_dir.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not candidates:
        raise FileNotFoundError(f"no .json files in {export_dir}")
    for name in ("findings_full.json", "findings.json", "results.json", "export.json"):
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


# ---------------------------
# Taxonomy + grouping helpers
# ---------------------------

_CATEGORY_BY_PREFIX: list[tuple[str, str]] = [
    ("aws.cloudwatch.", "cost"),
    ("aws.ec2.", "cost"),
    ("aws.ebs.", "cost"),
    ("aws.elb", "cost"),
    ("aws.rds.", "cost"),
    ("aws.s3.", "cost"),
    ("aws.vpc.", "cost"),
    ("aws.fsx.", "cost"),
    ("aws.backup.", "reliability"),
    ("aws.iam.", "security"),
]


def _derive_category(check_id: Optional[str]) -> str:
    if not check_id:
        return "other"
    for prefix, cat in _CATEGORY_BY_PREFIX:
        if check_id.startswith(prefix):
            return cat
    return "other"


_ID_PATTERNS = [
    r"\barn:[^\s]+",
    r"\bi-[0-9a-f]{8,}\b",
    r"\bvol-[0-9a-f]{8,}\b",
    r"\bsg-[0-9a-f]{8,}\b",
    r"\bsubnet-[0-9a-f]{8,}\b",
    r"\bvpc-[0-9a-f]{8,}\b",
    r"\b[a-z0-9-]{1,63}\.amazonaws\.com\b",
]


def _normalize_title(title: Optional[str]) -> str:
    t = (title or "").strip().lower()
    if not t:
        return ""
    for pat in _ID_PATTERNS:
        t = re.sub(pat, "<id>", t)
    t = re.sub(r"\d+", "<n>", t)
    t = re.sub(r"\s+", " ", t)
    return t.strip()


def _derive_group_key(check_id: Optional[str], category: str, title: Optional[str]) -> Optional[str]:
    base = f"{(check_id or '').strip()}|{category}|{_normalize_title(title)}".strip("|")
    if not base:
        return None
    return hashlib.sha1(base.encode("utf-8")).hexdigest()


def _guess_fields(
    item: Dict[str, Any],
) -> Tuple[
    Optional[str], Optional[str], Optional[str], Optional[str],
    Optional[float], Optional[str], Optional[str],
    str, Optional[str],
]:
    check_id = _norm(item.get("check_id") or item.get("checkId") or "") or None
    service = _norm(item.get("service") or item.get("provider_service") or "") or None
    severity = _norm(item.get("severity") or item.get("severity_level") or "") or None
    title = _norm(item.get("title") or item.get("message") or item.get("summary") or "") or None

    # Prefer category coming from export JSON if present.
    category = _norm(item.get("category") or item.get("finding_category") or "") or ""
    if not category:
        category = _derive_category(check_id)

    # Prefer group_key coming from export JSON if present.
    group_key = _norm(item.get("group_key") or item.get("groupKey") or "") or None
    if not group_key:
        group_key = _derive_group_key(check_id, category, title)

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

    return check_id, service, severity, title, savings_f, region, account_id, category, group_key


def ingest_latest_export() -> None:
    export_dir = Path(os.getenv("EXPORT_DIR", str(DEFAULT_EXPORT_DIR)))

    # If export produced a manifest, use it as the single source of truth.
    m = None
    mpath = manifest_path(export_dir)
    if mpath.exists():
        try:
            m = load_manifest(mpath)
        except Exception as exc:
            raise SystemExit(f"Invalid run manifest in export_dir: {mpath} ({exc})") from exc

        # Fail fast on mismatch: prevents ingesting with the wrong tenant/workspace.
        env_tenant = (os.getenv("TENANT_ID") or "").strip()
        env_ws = (os.getenv("WORKSPACE") or "").strip()
        if env_tenant and not hmac.compare_digest(env_tenant, m.tenant_id):
            raise SystemExit(f"TENANT_ID mismatch: env={env_tenant!r} manifest={m.tenant_id!r}")
        if env_ws and not hmac.compare_digest(env_ws, m.workspace):
            raise SystemExit(f"WORKSPACE mismatch: env={env_ws!r} manifest={m.workspace!r}")

    file_path = _pick_latest_json(export_dir)
    payload = _load_json(file_path)

    if m:
        tenant_id = m.tenant_id
        workspace = m.workspace
        run_id = m.run_id
        run_ts = _parse_dt(m.run_ts) or datetime.fromtimestamp(file_path.stat().st_mtime, tz=timezone.utc)
        engine_version = m.engine_version
    else:
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

    presence_rows: List[Sequence[Any]] = []
    latest_rows: List[Sequence[Any]] = []

    for it in items:
        if not isinstance(it, dict):
            continue

        fp = _fingerprint(it)
        if not fp:
            continue

        check_id, service, severity, title, savings_f, region, account_id, category, group_key = _guess_fields(it)

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
                category,
                group_key,
                payload_json,
                run_ts,
            )
        )

    if presence_rows:
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
    if latest_rows:
        execute_many(
            """
            INSERT INTO finding_latest
            (tenant_id, workspace, fingerprint, run_id,
             check_id, service, severity, title,
             estimated_monthly_savings, region, account_id,
             category, group_key,
             payload, detected_at)
            VALUES
            (%s,%s,%s,%s,
             %s,%s,%s,%s,
             %s,%s,%s,
             %s,%s,
             %s::jsonb,%s)
            ON CONFLICT (tenant_id, workspace, fingerprint) DO UPDATE SET
              run_id = EXCLUDED.run_id,
              check_id = EXCLUDED.check_id,
              service = EXCLUDED.service,
              severity = EXCLUDED.severity,
              title = EXCLUDED.title,
              estimated_monthly_savings = EXCLUDED.estimated_monthly_savings,
              region = EXCLUDED.region,
              account_id = EXCLUDED.account_id,
              category = EXCLUDED.category,
              group_key = EXCLUDED.group_key,
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
