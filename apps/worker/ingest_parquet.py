"""
apps.worker.ingest_parquet

Ingest findings from Parquet datasets into Postgres using run_manifest.json
as the single source of truth for tenant/workspace/run and dataset paths.
"""

from __future__ import annotations

import csv
import io
import json
import logging
import re
from dataclasses import dataclass
from datetime import date, datetime, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any, Callable, List, Mapping, Optional, Sequence, Tuple

import pyarrow.dataset as ds

from apps.backend.db import db_conn, execute, execute_many, fetch_one
from apps.backend.run_state import (
    STATE_READY,
    acquire_run_lock,
    append_run_event,
    begin_run_running,
    default_owner,
    release_run_lock,
    transition_run_to_failed,
    transition_run_to_ready,
)
from infra.config import get_settings
from pipeline.run_manifest import find_manifest, load_manifest
from services.remediation.impact import refresh_scope_action_impacts
from version import SCHEMA_VERSION

logger = logging.getLogger(__name__)
_IMPACT_REFRESH_LIMIT = 500


def _lock_ttl_seconds() -> int:
    """Lock TTL for run-scoped ingestion lock."""
    return int(get_settings(reload=True).worker.run_lock_ttl_seconds)


def _parse_dt(value: Any) -> Optional[datetime]:
    """Parse a datetime from common inputs, returning UTC-aware."""
    if isinstance(value, datetime):
        dt = value
    else:
        v = (str(value or "")).strip()
        if not v:
            return None
        try:
            dt = datetime.fromisoformat(v.replace("Z", "+00:00"))
        except ValueError:
            return None

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _manifest_run_ts(manifest_run_ts: str) -> datetime:
    """Parse and validate run_ts from manifest (required, deterministic)."""
    run_ts = _parse_dt(manifest_run_ts)
    if run_ts is None:
        raise SystemExit(f"Invalid run_ts in manifest: {manifest_run_ts!r}")
    return run_ts


def _json_default(obj: Any) -> Any:
    """JSON serializer for datetime/Decimal values."""
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    if isinstance(obj, Decimal):
        return str(obj)
    return str(obj)


def _to_float(v: Any) -> Optional[float]:
    """Best-effort numeric parsing for savings/cost fields."""
    if v is None:
        return None
    if isinstance(v, (int, float, Decimal)):
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
        s = re.sub(r"[^0-9,\\.-]", "", s)
        if s.count(",") == 1 and s.count(".") == 0:
            s = s.replace(",", ".")
        if s.count(",") >= 1 and s.count(".") >= 1:
            s = s.replace(",", "")
        return float(s)
    except (TypeError, ValueError, OverflowError):
        return None


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
    """Infer a coarse category from check_id prefix."""
    if not check_id:
        return "other"
    for prefix, cat in _CATEGORY_BY_PREFIX:
        if check_id.startswith(prefix):
            return cat
    return "other"


_ID_PATTERNS = [
    r"\\barn:[^\\s]+",
    r"\\bi-[0-9a-f]{8,}\\b",
    r"\\bvol-[0-9a-f]{8,}\\b",
    r"\\bsg-[0-9a-f]{8,}\\b",
    r"\\bsubnet-[0-9a-f]{8,}\\b",
    r"\\bvpc-[0-9a-f]{8,}\\b",
    r"\\b[a-z0-9-]{1,63}\\.amazonaws\\.com\\b",
]


def _normalize_title(title: Optional[str]) -> str:
    """Normalize titles for grouping (mask IDs and digits)."""
    t = (title or "").strip().lower()
    if not t:
        return ""
    for pat in _ID_PATTERNS:
        t = re.sub(pat, "<id>", t)
    t = re.sub(r"\\d+", "<n>", t)
    t = re.sub(r"\\s+", " ", t)
    return t.strip()


def _derive_group_key(check_id: Optional[str], category: str, title: Optional[str]) -> Optional[str]:
    """Build a stable group key from check_id/category/title."""
    base = f"{(check_id or '').strip()}|{category}|{_normalize_title(title)}".strip("|")
    if not base:
        return None
    import hashlib

    return hashlib.sha1(base.encode("utf-8")).hexdigest()


def _scope_get(scope: Any, key: str) -> Optional[str]:
    """Safe access to a scope mapping field."""
    if isinstance(scope, Mapping):
        v = scope.get(key)
        return str(v).strip() if v is not None else None
    return None


def _guess_fields_from_record(
    rec: Mapping[str, Any],
) -> Tuple[
    Optional[str], Optional[str], Optional[str], Optional[str],
    Optional[float], Optional[str], Optional[str],
    str, Optional[str],
]:
    """Extract DB fields from a Parquet record with best-effort fallbacks."""
    check_id = rec.get("check_id")
    if check_id is not None:
        check_id = str(check_id).strip() or None

    scope = rec.get("scope") or {}
    service = _scope_get(scope, "service") or (str(rec.get("service") or "").strip() or None)

    severity = None
    sev = rec.get("severity")
    if isinstance(sev, Mapping):
        severity = str(sev.get("level") or "").strip() or None
    elif sev is not None:
        severity = str(sev).strip() or None

    title = str(rec.get("title") or "").strip() or None

    category = str(rec.get("category") or "").strip() or ""
    if not category:
        category = _derive_category(check_id)

    group_key = str(rec.get("group_key") or rec.get("groupKey") or "").strip() or None
    if not group_key:
        group_key = _derive_group_key(check_id, category, title)

    estimated = rec.get("estimated") if isinstance(rec.get("estimated"), Mapping) else {}
    savings = estimated.get("monthly_savings") if isinstance(estimated, Mapping) else None
    savings_f = _to_float(savings)

    region = _scope_get(scope, "region") or (str(rec.get("region") or "").strip() or None)
    account_id = _scope_get(scope, "account_id") or (str(rec.get("account_id") or "").strip() or None)

    return check_id, service, severity, title, savings_f, region, account_id, category, group_key


def _glob_has_files(path: str | Path) -> bool:
    """Return True if the path contains any parquet files."""
    base = Path(path)
    if not base.exists():
        return False
    return bool(list(base.glob("**/*.parquet")))


def _list_parquet_files(path: str | Path) -> List[Path]:
    """List parquet files under a dataset directory."""
    base = Path(path)
    if not base.exists():
        return []
    return [p for p in base.rglob("*.parquet") if p.is_file()]


def _as_copy_value(value: Any) -> str:
    """Normalize a value for CSV COPY."""
    if value is None:
        return "\\N"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=_json_default)
    return str(value)


def _copy_rows(cur, table: str, columns: Sequence[str], rows: List[Sequence[Any]]) -> int:
    """Bulk copy rows into a table using CSV COPY."""
    if not rows:
        return 0
    buf = io.StringIO()
    writer = csv.writer(
        buf,
        delimiter="\t",
        lineterminator="\n",
        quoting=csv.QUOTE_MINIMAL,
    )
    for row in rows:
        writer.writerow([_as_copy_value(v) for v in row])
    buf.seek(0)

    cols_sql = ", ".join(columns)
    # NOTE: table/columns are internal constants; do not pass user input here.
    sql = f"COPY {table} ({cols_sql}) FROM STDIN WITH (FORMAT CSV, DELIMITER E'\\t', NULL '\\\\N')"
    cur.copy_expert(sql, buf)
    return len(rows)


def _selected_dataset_paths(manifest) -> tuple[List[str], str]:
    """Resolve dataset paths to ingest.

    Rules:
    - If enriched exists, ingest enriched only (already includes merged findings).
    - Otherwise ingest raw and correlated together when available.
    """
    if manifest.out_enriched and _glob_has_files(manifest.out_enriched):
        return [manifest.out_enriched], "enriched"

    selected: List[str] = []
    labels: List[str] = []
    if manifest.out_raw and _glob_has_files(manifest.out_raw):
        selected.append(manifest.out_raw)
        labels.append("raw")
    if manifest.out_correlated and _glob_has_files(manifest.out_correlated):
        selected.append(manifest.out_correlated)
        labels.append("correlated")

    if selected:
        return selected, "+".join(labels)

    # Fall back to configured paths for a clearer error message upstream.
    fallback: List[str] = []
    if manifest.out_enriched:
        fallback.append(manifest.out_enriched)
    if manifest.out_raw:
        fallback.append(manifest.out_raw)
    if manifest.out_correlated:
        fallback.append(manifest.out_correlated)
    return fallback, "none"


def _list_parquet_files_for_paths(paths: Sequence[str]) -> List[Path]:
    """List parquet files across multiple dataset roots."""
    files: List[Path] = []
    for path in paths:
        files.extend(_list_parquet_files(path))
    # Deterministic and de-duplicated
    return sorted({p.resolve() for p in files})


@dataclass(frozen=True)
class DbApi:
    execute: Callable[[str, Optional[Sequence[Any]]], None]
    execute_many: Callable[[str, List[Sequence[Any]]], None]
    fetch_one: Callable[[str, Optional[Sequence[Any]]], Optional[Tuple[Any, ...]]]


def _default_db_api() -> DbApi:
    """Return the default DB API backed by apps.backend.db helpers."""
    return DbApi(execute=execute, execute_many=execute_many, fetch_one=fetch_one)


def _ensure_db_schema_current() -> None:
    """Fail fast if the database schema is behind local migrations."""
    from apps.backend.db_migrate import ensure_schema_current

    migrations_dir = Path(__file__).resolve().parents[2] / "migrations"
    ensure_schema_current(migrations_dir=migrations_dir)


@dataclass
class IngestStats:
    dataset_used: str
    dataset_dir: str
    raw_present: bool
    correlated_present: bool
    enriched_present: bool
    presence_rows: int
    latest_rows: int


_AGG_DELETE_SQL = """
DELETE FROM finding_aggregates_current
WHERE tenant_id=%s AND workspace=%s
"""


_AGG_INSERT_SQL = """
INSERT INTO finding_aggregates_current
  (tenant_id, workspace, dimension, key, finding_count, total_savings, refreshed_at)
SELECT
  tenant_id,
  workspace,
  dimension,
  key,
  finding_count,
  total_savings,
  now()
FROM (
  SELECT
    tenant_id,
    workspace,
    'effective_state'::text AS dimension,
    COALESCE(effective_state, 'open') AS key,
    COUNT(*)::bigint AS finding_count,
    COALESCE(SUM(estimated_monthly_savings), 0)::double precision AS total_savings
  FROM finding_current
  WHERE tenant_id=%s AND workspace=%s
  GROUP BY tenant_id, workspace, COALESCE(effective_state, 'open')

  UNION ALL

  SELECT
    tenant_id,
    workspace,
    'severity'::text AS dimension,
    COALESCE(severity, 'unknown') AS key,
    COUNT(*)::bigint AS finding_count,
    COALESCE(SUM(estimated_monthly_savings), 0)::double precision AS total_savings
  FROM finding_current
  WHERE tenant_id=%s AND workspace=%s
  GROUP BY tenant_id, workspace, COALESCE(severity, 'unknown')

  UNION ALL

  SELECT
    tenant_id,
    workspace,
    'service'::text AS dimension,
    COALESCE(service, 'unknown') AS key,
    COUNT(*)::bigint AS finding_count,
    COALESCE(SUM(estimated_monthly_savings), 0)::double precision AS total_savings
  FROM finding_current
  WHERE tenant_id=%s AND workspace=%s
  GROUP BY tenant_id, workspace, COALESCE(service, 'unknown')

  UNION ALL

  SELECT
    tenant_id,
    workspace,
    'category'::text AS dimension,
    COALESCE(category, 'other') AS key,
    COUNT(*)::bigint AS finding_count,
    COALESCE(SUM(estimated_monthly_savings), 0)::double precision AS total_savings
  FROM finding_current
  WHERE tenant_id=%s AND workspace=%s
  GROUP BY tenant_id, workspace, COALESCE(category, 'other')
) agg
ON CONFLICT (tenant_id, workspace, dimension, key) DO UPDATE SET
  finding_count = EXCLUDED.finding_count,
  total_savings = EXCLUDED.total_savings,
  refreshed_at = EXCLUDED.refreshed_at
"""


def _aggregate_params(tenant_id: str, workspace: str) -> tuple[str, str, str, str, str, str, str, str]:
    """Return reusable parameter tuple for aggregate refresh SQL."""
    return (
        tenant_id,
        workspace,
        tenant_id,
        workspace,
        tenant_id,
        workspace,
        tenant_id,
        workspace,
    )


def _refresh_aggregates_with_api(api: DbApi, *, tenant_id: str, workspace: str) -> None:
    """Refresh aggregate read-model rows for one tenant/workspace."""
    api.execute(_AGG_DELETE_SQL, (tenant_id, workspace))
    api.execute(_AGG_INSERT_SQL, _aggregate_params(tenant_id, workspace))


def _refresh_aggregates_with_cursor(cur, *, tenant_id: str, workspace: str) -> None:
    """Refresh aggregate read-model rows inside an existing DB transaction."""
    cur.execute(_AGG_DELETE_SQL, (tenant_id, workspace))
    cur.execute(_AGG_INSERT_SQL, _aggregate_params(tenant_id, workspace))


def _refresh_remediation_impacts_best_effort(
    *,
    tenant_id: str,
    workspace: str,
    run_id: str,
    actor: str,
) -> int:
    """Refresh remediation impact snapshots after a run reaches ready state.

    This runs outside the ingest transaction to avoid coupling core ingestion
    success to remediation impact refresh failures.

    Args:
        tenant_id: Tenant scope.
        workspace: Workspace scope.
        run_id: Run identifier associated with this refresh.
        actor: System actor attributed in run event logs.

    Returns:
        Number of refreshed impact rows. Returns ``0`` when refresh fails.
    """
    try:
        with db_conn() as conn:
            refreshed = refresh_scope_action_impacts(
                conn,
                tenant_id=tenant_id,
                workspace=workspace,
                limit=_IMPACT_REFRESH_LIMIT,
            )
            append_run_event(
                conn,
                tenant_id=tenant_id,
                workspace=workspace,
                run_id=run_id,
                event_type="run.remediation_impact.refresh.completed",
                actor=actor,
                payload={
                    "refreshed_count": refreshed,
                    "limit": _IMPACT_REFRESH_LIMIT,
                },
            )
            conn.commit()
        return refreshed
    except Exception as exc:  # pragma: no cover - defensive logging path
        logger.warning(
            "Skipped remediation impact refresh for %s/%s: %s",
            tenant_id,
            workspace,
            exc,
        )
        try:
            with db_conn() as conn:
                append_run_event(
                    conn,
                    tenant_id=tenant_id,
                    workspace=workspace,
                    run_id=run_id,
                    event_type="run.remediation_impact.refresh.failed",
                    actor=actor,
                    payload={
                        "error": str(exc),
                        "limit": _IMPACT_REFRESH_LIMIT,
                    },
                )
                conn.commit()
        except Exception as event_exc:  # pragma: no cover - defensive logging path
            logger.warning(
                "Failed to persist remediation impact refresh failure event for %s/%s/%s: %s",
                tenant_id,
                workspace,
                run_id,
                event_exc,
            )
        return 0


def ingest_from_manifest(
    manifest_path: Path,
    *,
    db_api: Optional[DbApi] = None,
    batch_size: Optional[int] = None,
    parquet_batch_size: Optional[int] = None,
) -> IngestStats:
    """Ingest a Parquet dataset described by a run_manifest.json."""
    worker_cfg = get_settings(reload=True).worker
    api = db_api or _default_db_api()
    batch_size = batch_size or int(worker_cfg.ingest_batch_size)
    parquet_batch_size = parquet_batch_size or int(worker_cfg.parquet_batch_size)
    allow_schema_mismatch = bool(worker_cfg.allow_schema_mismatch)

    if db_api is None and not allow_schema_mismatch:
        _ensure_db_schema_current()

    manifest = load_manifest(manifest_path)
    expected_schema = int(SCHEMA_VERSION)
    if manifest.schema_version is not None:
        try:
            manifest_ver = int(manifest.schema_version)
        except (TypeError, ValueError):
            raise SystemExit(f"Invalid schema_version in manifest: {manifest.schema_version!r}") from None

        if manifest_ver != expected_schema and not allow_schema_mismatch:
            raise SystemExit(
                f"Schema mismatch: manifest={manifest_ver} expected={expected_schema}. "
                "Run `mckay migrate` (or `python -m apps.backend.db_migrate`) to update the DB, "
                "or set ALLOW_SCHEMA_MISMATCH=1 to override."
            )

    # Fail fast on mismatch: prevents ingesting with the wrong tenant/workspace.
    env_tenant = str(worker_cfg.tenant_id or "").strip()
    env_ws = str(worker_cfg.workspace or "").strip()
    if env_tenant and env_tenant != manifest.tenant_id:
        raise SystemExit(f"TENANT_ID mismatch: env={env_tenant!r} manifest={manifest.tenant_id!r}")
    if env_ws and env_ws != manifest.workspace:
        raise SystemExit(f"WORKSPACE mismatch: env={env_ws!r} manifest={manifest.workspace!r}")

    # Determine datasets to ingest (enriched only, or raw+correlated union).
    dataset_paths, dataset_label = _selected_dataset_paths(manifest)
    if not dataset_paths:
        raise SystemExit("No parquet files found for manifest datasets.")
    dataset_dir = ";".join(dataset_paths)

    raw_present = bool(manifest.out_raw and _glob_has_files(manifest.out_raw))
    correlated_present = bool(manifest.out_correlated and _glob_has_files(manifest.out_correlated))
    enriched_present = bool(manifest.out_enriched and _glob_has_files(manifest.out_enriched))

    use_copy = db_api is None and not bool(worker_cfg.ingest_disable_copy)
    if use_copy:
        return _ingest_with_copy(
            manifest=manifest,
            dataset_paths=dataset_paths,
            dataset_dir=dataset_dir,
            dataset_label=dataset_label,
            raw_present=raw_present,
            correlated_present=correlated_present,
            enriched_present=enriched_present,
            batch_size=batch_size,
            parquet_batch_size=parquet_batch_size,
        )

    run_ts = _manifest_run_ts(manifest.run_ts)

    existing = api.fetch_one(
        "SELECT status FROM runs WHERE tenant_id=%s AND workspace=%s AND run_id=%s",
        (manifest.tenant_id, manifest.workspace, manifest.run_id),
    )
    if existing and existing[0] == "ready":
        logger.info(
            "SKIP: run already ingested: %s/%s/%s",
            manifest.tenant_id,
            manifest.workspace,
            manifest.run_id,
        )
        return IngestStats(
            dataset_used=dataset_label,
            dataset_dir=dataset_dir,
            raw_present=raw_present,
            correlated_present=correlated_present,
            enriched_present=enriched_present,
            presence_rows=0,
            latest_rows=0,
        )

    try:
        api.execute(
            """
            INSERT INTO runs (tenant_id, workspace, run_id, run_ts, status, artifact_prefix, ingested_at, engine_version,
                              pricing_version, pricing_source,
                              raw_present, correlated_present, enriched_present)
            VALUES (%s, %s, %s, %s, 'running', %s, NULL, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (tenant_id, workspace, run_id) DO UPDATE SET
              run_ts = EXCLUDED.run_ts,
              status = 'running',
              artifact_prefix = EXCLUDED.artifact_prefix,
              engine_version = EXCLUDED.engine_version,
              pricing_version = EXCLUDED.pricing_version,
              pricing_source = EXCLUDED.pricing_source,
              raw_present = EXCLUDED.raw_present,
              correlated_present = EXCLUDED.correlated_present,
              enriched_present = EXCLUDED.enriched_present,
              ingested_at = NULL
            """,
            (
                manifest.tenant_id,
                manifest.workspace,
                manifest.run_id,
                run_ts,
                dataset_dir,
                manifest.engine_version,
                manifest.pricing_version,
                manifest.pricing_source,
                raw_present,
                correlated_present,
                enriched_present,
            ),
        )

        # Idempotence for presence rows
        api.execute(
            "DELETE FROM finding_presence WHERE tenant_id=%s AND workspace=%s AND run_id=%s",
            (manifest.tenant_id, manifest.workspace, manifest.run_id),
        )

        parquet_files = _list_parquet_files_for_paths(dataset_paths)
        if not parquet_files:
            raise SystemExit("No parquet files found for manifest datasets.")

        dataset = ds.dataset([str(p) for p in parquet_files], format="parquet", partitioning="hive")
        schema_names = set(dataset.schema.names)

        filt = None
        if "tenant_id" in schema_names:
            filt = ds.field("tenant_id") == manifest.tenant_id
        if "workspace_id" in schema_names:
            expr = ds.field("workspace_id") == manifest.workspace
            filt = expr if filt is None else (filt & expr)
        if "run_id" in schema_names and manifest.run_id:
            expr = ds.field("run_id") == manifest.run_id
            filt = expr if filt is None else (filt & expr)

        scanner = dataset.scanner(filter=filt, batch_size=int(parquet_batch_size))

        presence_rows: List[Sequence[Any]] = []
        latest_rows: List[Sequence[Any]] = []
        seen_fingerprints: set[str] = set()
        total_presence = 0
        total_latest = 0

        def _flush_presence() -> None:
            """Flush buffered presence rows to the DB."""
            nonlocal total_presence
            if not presence_rows:
                return
            api.execute_many(
                """
                INSERT INTO finding_presence
                (tenant_id, workspace, run_id, fingerprint, check_id, service, severity, title,
                estimated_monthly_savings, region, account_id, detected_at)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                """,
                presence_rows,
            )
            total_presence += len(presence_rows)
            presence_rows.clear()

        def _flush_latest() -> None:
            """Flush buffered latest rows to the DB."""
            nonlocal total_latest
            if not latest_rows:
                return
            api.execute_many(
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
            total_latest += len(latest_rows)
            latest_rows.clear()

        for batch in scanner.to_batches():
            rows = batch.to_pylist()
            for rec in rows:
                if not isinstance(rec, dict):
                    continue

                # Safety guard if filters were not applied.
                if rec.get("tenant_id") != manifest.tenant_id:
                    continue
                if rec.get("workspace_id") and rec.get("workspace_id") != manifest.workspace:
                    continue
                if rec.get("run_id") and manifest.run_id and rec.get("run_id") != manifest.run_id:
                    continue

                fp = str(rec.get("fingerprint") or "").strip()
                if not fp:
                    continue
                if fp in seen_fingerprints:
                    continue
                seen_fingerprints.add(fp)

                check_id, service, severity, title, savings_f, region, account_id, category, group_key = (
                    _guess_fields_from_record(rec)
                )

                detected_at = _parse_dt(rec.get("run_ts")) or run_ts

                presence_rows.append(
                    (
                        manifest.tenant_id,
                        manifest.workspace,
                        manifest.run_id,
                        fp,
                        check_id,
                        service,
                        severity,
                        title,
                        savings_f,
                        region,
                        account_id,
                        detected_at,
                    )
                )

                payload_json = json.dumps(rec, ensure_ascii=False, separators=(",", ":"), default=_json_default)
                latest_rows.append(
                    (
                        manifest.tenant_id,
                        manifest.workspace,
                        fp,
                        manifest.run_id,
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
                        detected_at,
                    )
                )

                if len(presence_rows) >= batch_size:
                    _flush_presence()
                if len(latest_rows) >= batch_size:
                    _flush_latest()

        _flush_presence()
        _flush_latest()

        _refresh_aggregates_with_api(
            api,
            tenant_id=manifest.tenant_id,
            workspace=manifest.workspace,
        )

        api.execute(
            """
            UPDATE runs
            SET status='ready', ingested_at=NOW(),
                raw_present=%s, correlated_present=%s, enriched_present=%s
            WHERE tenant_id=%s AND workspace=%s AND run_id=%s
            """,
            (
                raw_present,
                correlated_present,
                enriched_present,
                manifest.tenant_id,
                manifest.workspace,
                manifest.run_id,
            ),
        )
        if db_api is None:
            _refresh_remediation_impacts_best_effort(
                tenant_id=manifest.tenant_id,
                workspace=manifest.workspace,
                run_id=manifest.run_id,
                actor=default_owner("ingest_parquet"),
            )
    except Exception as exc:
        logger.exception(
            "Ingest failed for %s/%s/%s: %s",
            manifest.tenant_id,
            manifest.workspace,
            manifest.run_id,
            exc,
        )
        api.execute(
            """
            UPDATE runs
            SET status='failed'
            WHERE tenant_id=%s AND workspace=%s AND run_id=%s
            """,
            (manifest.tenant_id, manifest.workspace, manifest.run_id),
        )
        raise

    logger.info(
        "OK: ingested %s items from %s as run %s/%s/%s (presence=%s, latest=%s)",
        total_presence,
        dataset_dir,
        manifest.tenant_id,
        manifest.workspace,
        manifest.run_id,
        total_presence,
        total_latest,
    )

    return IngestStats(
        dataset_used=dataset_label,
        dataset_dir=dataset_dir,
        raw_present=raw_present,
        correlated_present=correlated_present,
        enriched_present=enriched_present,
        presence_rows=total_presence,
        latest_rows=total_latest,
    )


def _ingest_with_copy(
    *,
    manifest,
    dataset_paths: Sequence[str],
    dataset_dir: str,
    dataset_label: str,
    raw_present: bool,
    correlated_present: bool,
    enriched_present: bool,
    batch_size: int,
    parquet_batch_size: int,
) -> IngestStats:
    """Ingest using COPY into temp tables for scale."""
    run_ts = _manifest_run_ts(manifest.run_ts)

    parquet_files = _list_parquet_files_for_paths(dataset_paths)
    if not parquet_files:
        raise SystemExit("No parquet files found for manifest datasets.")

    dataset = ds.dataset([str(p) for p in parquet_files], format="parquet", partitioning="hive")
    schema_names = set(dataset.schema.names)

    filt = None
    if "tenant_id" in schema_names:
        filt = ds.field("tenant_id") == manifest.tenant_id
    if "workspace_id" in schema_names:
        expr = ds.field("workspace_id") == manifest.workspace
        filt = expr if filt is None else (filt & expr)
    if "run_id" in schema_names and manifest.run_id:
        expr = ds.field("run_id") == manifest.run_id
        filt = expr if filt is None else (filt & expr)

    scanner = dataset.scanner(filter=filt, batch_size=int(parquet_batch_size))

    presence_cols = (
        "tenant_id",
        "workspace",
        "run_id",
        "fingerprint",
        "check_id",
        "service",
        "severity",
        "title",
        "estimated_monthly_savings",
        "region",
        "account_id",
        "detected_at",
    )
    latest_cols = (
        "tenant_id",
        "workspace",
        "fingerprint",
        "run_id",
        "check_id",
        "service",
        "severity",
        "title",
        "estimated_monthly_savings",
        "region",
        "account_id",
        "category",
        "group_key",
        "payload",
        "detected_at",
    )

    total_presence = 0
    total_latest = 0
    lock_owner = default_owner("ingest_parquet")
    lock_token: Optional[str] = None

    with db_conn() as conn:
        try:
            lock = acquire_run_lock(
                conn,
                tenant_id=manifest.tenant_id,
                workspace=manifest.workspace,
                run_id=manifest.run_id,
                owner=lock_owner,
                ttl_seconds=_lock_ttl_seconds(),
            )
            if lock is None:
                raise SystemExit(
                    "Run is already being ingested (active lock). "
                    f"tenant={manifest.tenant_id} workspace={manifest.workspace} run_id={manifest.run_id}"
                )
            lock_token = lock.token
            append_run_event(
                conn,
                tenant_id=manifest.tenant_id,
                workspace=manifest.workspace,
                run_id=manifest.run_id,
                event_type="run.lock.acquired",
                actor=lock_owner,
                payload={"expires_at": lock.expires_at.isoformat()},
            )

            state = begin_run_running(
                conn,
                tenant_id=manifest.tenant_id,
                workspace=manifest.workspace,
                run_id=manifest.run_id,
                run_ts=run_ts,
                artifact_prefix=dataset_dir,
                engine_version=manifest.engine_version,
                pricing_version=manifest.pricing_version,
                pricing_source=manifest.pricing_source,
                raw_present=raw_present,
                correlated_present=correlated_present,
                enriched_present=enriched_present,
                actor=lock_owner,
            )
            if state == STATE_READY:
                released = release_run_lock(
                    conn,
                    tenant_id=manifest.tenant_id,
                    workspace=manifest.workspace,
                    run_id=manifest.run_id,
                    lock_token=lock_token,
                )
                if released:
                    append_run_event(
                        conn,
                        tenant_id=manifest.tenant_id,
                        workspace=manifest.workspace,
                        run_id=manifest.run_id,
                        event_type="run.lock.released",
                        actor=lock_owner,
                    )
                conn.commit()
                logger.info(
                    "SKIP: run already ingested: %s/%s/%s",
                    manifest.tenant_id,
                    manifest.workspace,
                    manifest.run_id,
                )
                return IngestStats(
                    dataset_used=dataset_label,
                    dataset_dir=dataset_dir,
                    raw_present=raw_present,
                    correlated_present=correlated_present,
                    enriched_present=enriched_present,
                    presence_rows=0,
                    latest_rows=0,
                )

            with conn.cursor() as cur:
                cur.execute(
                    "DELETE FROM finding_presence WHERE tenant_id=%s AND workspace=%s AND run_id=%s",
                    (manifest.tenant_id, manifest.workspace, manifest.run_id),
                )

                cur.execute(
                    "CREATE TEMP TABLE tmp_presence (LIKE finding_presence INCLUDING DEFAULTS) ON COMMIT DROP"
                )
                cur.execute(
                    "CREATE TEMP TABLE tmp_latest (LIKE finding_latest INCLUDING DEFAULTS) ON COMMIT DROP"
                )

                presence_rows: List[Sequence[Any]] = []
                latest_rows: List[Sequence[Any]] = []
                seen_fingerprints: set[str] = set()

                def _flush_presence_copy() -> None:
                    nonlocal total_presence
                    if not presence_rows:
                        return
                    total_presence += _copy_rows(cur, "tmp_presence", presence_cols, presence_rows)
                    presence_rows.clear()

                def _flush_latest_copy() -> None:
                    nonlocal total_latest
                    if not latest_rows:
                        return
                    total_latest += _copy_rows(cur, "tmp_latest", latest_cols, latest_rows)
                    latest_rows.clear()

                for batch in scanner.to_batches():
                    rows = batch.to_pylist()
                    for rec in rows:
                        if not isinstance(rec, dict):
                            continue

                        if rec.get("tenant_id") != manifest.tenant_id:
                            continue
                        if rec.get("workspace_id") and rec.get("workspace_id") != manifest.workspace:
                            continue
                        if rec.get("run_id") and manifest.run_id and rec.get("run_id") != manifest.run_id:
                            continue

                        fp = str(rec.get("fingerprint") or "").strip()
                        if not fp:
                            continue
                        if fp in seen_fingerprints:
                            continue
                        seen_fingerprints.add(fp)

                        check_id, service, severity, title, savings_f, region, account_id, category, group_key = (
                            _guess_fields_from_record(rec)
                        )

                        detected_at = _parse_dt(rec.get("run_ts")) or run_ts

                        presence_rows.append(
                            (
                                manifest.tenant_id,
                                manifest.workspace,
                                manifest.run_id,
                                fp,
                                check_id,
                                service,
                                severity,
                                title,
                                savings_f,
                                region,
                                account_id,
                                detected_at,
                            )
                        )

                        payload_json = json.dumps(
                            rec,
                            ensure_ascii=False,
                            separators=(",", ":"),
                            default=_json_default,
                        )
                        latest_rows.append(
                            (
                                manifest.tenant_id,
                                manifest.workspace,
                                fp,
                                manifest.run_id,
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
                                detected_at,
                            )
                        )

                        if len(presence_rows) >= batch_size:
                            _flush_presence_copy()
                        if len(latest_rows) >= batch_size:
                            _flush_latest_copy()

                _flush_presence_copy()
                _flush_latest_copy()

                cur.execute(
                    """
                    INSERT INTO finding_presence
                    (tenant_id, workspace, run_id, fingerprint, check_id, service, severity, title,
                     estimated_monthly_savings, region, account_id, detected_at)
                    SELECT
                      tenant_id, workspace, run_id, fingerprint, check_id, service, severity, title,
                      estimated_monthly_savings, region, account_id, detected_at
                    FROM tmp_presence
                    """
                )

                cur.execute(
                    """
                    INSERT INTO finding_latest
                    (tenant_id, workspace, fingerprint, run_id,
                     check_id, service, severity, title,
                     estimated_monthly_savings, region, account_id,
                     category, group_key,
                     payload, detected_at)
                    SELECT
                      tenant_id, workspace, fingerprint, run_id,
                      check_id, service, severity, title,
                      estimated_monthly_savings, region, account_id,
                      category, group_key,
                      payload, detected_at
                    FROM tmp_latest
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
                    """
                )

                _refresh_aggregates_with_cursor(
                    cur,
                    tenant_id=manifest.tenant_id,
                    workspace=manifest.workspace,
                )

                transition_run_to_ready(
                    conn,
                    tenant_id=manifest.tenant_id,
                    workspace=manifest.workspace,
                    run_id=manifest.run_id,
                    actor=lock_owner,
                    raw_present=raw_present,
                    correlated_present=correlated_present,
                    enriched_present=enriched_present,
                )
                if lock_token:
                    released = release_run_lock(
                        conn,
                        tenant_id=manifest.tenant_id,
                        workspace=manifest.workspace,
                        run_id=manifest.run_id,
                        lock_token=lock_token,
                    )
                    if released:
                        append_run_event(
                            conn,
                            tenant_id=manifest.tenant_id,
                            workspace=manifest.workspace,
                            run_id=manifest.run_id,
                            event_type="run.lock.released",
                            actor=lock_owner,
                        )
                        lock_token = None

            conn.commit()
        except Exception as exc:
            try:
                conn.rollback()
            except Exception as rb_exc:
                logger.warning("Rollback failed after COPY ingest error: %s", rb_exc)
            try:
                transition_run_to_failed(
                    conn,
                    tenant_id=manifest.tenant_id,
                    workspace=manifest.workspace,
                    run_id=manifest.run_id,
                    run_ts=run_ts,
                    artifact_prefix=dataset_dir,
                    engine_version=manifest.engine_version,
                    pricing_version=manifest.pricing_version,
                    pricing_source=manifest.pricing_source,
                    actor=lock_owner,
                    reason=str(exc),
                )
                if lock_token:
                    released = release_run_lock(
                        conn,
                        tenant_id=manifest.tenant_id,
                        workspace=manifest.workspace,
                        run_id=manifest.run_id,
                        lock_token=lock_token,
                    )
                    if released:
                        append_run_event(
                            conn,
                            tenant_id=manifest.tenant_id,
                            workspace=manifest.workspace,
                            run_id=manifest.run_id,
                            event_type="run.lock.released",
                            actor=lock_owner,
                        )
                conn.commit()
            except Exception as state_exc:
                try:
                    conn.rollback()
                except Exception as rb_exc:
                    logger.warning("Rollback failed while persisting failed run state: %s", rb_exc)
                logger.warning("Failed to persist failed run state: %s", state_exc)
            raise

    logger.info(
        "OK: ingested %s items from %s as run %s/%s/%s (presence=%s, latest=%s)",
        total_presence,
        dataset_dir,
        manifest.tenant_id,
        manifest.workspace,
        manifest.run_id,
        total_presence,
        total_latest,
    )
    refreshed = _refresh_remediation_impacts_best_effort(
        tenant_id=manifest.tenant_id,
        workspace=manifest.workspace,
        run_id=manifest.run_id,
        actor=lock_owner,
    )
    if refreshed:
        logger.info(
            "Refreshed remediation impacts after run ready: %s/%s (%s rows)",
            manifest.tenant_id,
            manifest.workspace,
            refreshed,
        )

    return IngestStats(
        dataset_used=dataset_label,
        dataset_dir=dataset_dir,
        raw_present=raw_present,
        correlated_present=correlated_present,
        enriched_present=enriched_present,
        presence_rows=total_presence,
        latest_rows=total_latest,
    )


def _find_manifest_path(arg: Optional[str]) -> Path:
    """Resolve the manifest path from args, env, or cwd."""
    if arg:
        p = Path(arg).resolve()
        if not p.exists():
            raise SystemExit(f"manifest not found: {p}")
        return p

    env_path = get_settings(reload=True).worker.manifest_path
    if env_path:
        p = Path(env_path).resolve()
        if p.exists():
            return p
        raise SystemExit(f"manifest not found: {p}")

    found = find_manifest(Path.cwd())
    if found and found.exists():
        return found

    raise SystemExit("run_manifest.json not found (use --manifest or MANIFEST_PATH).")


def main(argv: Optional[List[str]] = None) -> None:
    """CLI entrypoint."""
    import argparse

    parser = argparse.ArgumentParser(description="Ingest findings from Parquet into Postgres.")
    parser.add_argument(
        "--manifest",
        default=None,
        help="Path to run_manifest.json (or set MANIFEST_PATH).",
    )
    args = parser.parse_args(argv)

    manifest_path = _find_manifest_path(args.manifest)
    ingest_from_manifest(manifest_path)


if __name__ == "__main__":
    main()
