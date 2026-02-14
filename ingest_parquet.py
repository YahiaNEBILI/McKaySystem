from __future__ import annotations

"""
ingest_parquet.py

Ingest findings from Parquet datasets into Postgres using run_manifest.json
as the single source of truth for tenant/workspace/run and dataset paths.
"""

import json
import os
import re
from dataclasses import dataclass
from datetime import date, datetime, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple

import pyarrow.dataset as ds

from db import execute, execute_many, fetch_one
from pipeline.run_manifest import find_manifest, load_manifest
from version import SCHEMA_VERSION


def _env_bool(name: str) -> bool:
    """Read a boolean env var."""
    v = os.getenv(name)
    if not v:
        return False
    return v.strip().lower() in {"1", "true", "yes", "y", "on"}


def _env_int(name: str, default: int) -> int:
    """Read an integer env var with a default."""
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return max(1, int(raw))
    except Exception:
        return default


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
        except Exception:
            return None

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


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
    except Exception:
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


def _dataset_candidates(manifest) -> List[tuple[str, str]]:
    """Return candidate dataset paths in priority order."""
    candidates: List[tuple[str, str]] = []
    if manifest.out_enriched:
        candidates.append((manifest.out_enriched, "enriched"))
    if manifest.out_correlated:
        candidates.append((manifest.out_correlated, "correlated"))
    if manifest.out_raw:
        candidates.append((manifest.out_raw, "raw"))
    return candidates


@dataclass(frozen=True)
class DbApi:
    execute: Callable[[str, Optional[Sequence[Any]]], None]
    execute_many: Callable[[str, List[Sequence[Any]]], None]
    fetch_one: Callable[[str, Optional[Sequence[Any]]], Optional[Tuple[Any, ...]]]


def _default_db_api() -> DbApi:
    """Return the default DB API backed by db.py helpers."""
    return DbApi(execute=execute, execute_many=execute_many, fetch_one=fetch_one)


@dataclass
class IngestStats:
    dataset_used: str
    dataset_dir: str
    raw_present: bool
    correlated_present: bool
    enriched_present: bool
    presence_rows: int
    latest_rows: int


def ingest_from_manifest(
    manifest_path: Path,
    *,
    db_api: Optional[DbApi] = None,
    batch_size: Optional[int] = None,
    parquet_batch_size: Optional[int] = None,
) -> IngestStats:
    """Ingest a Parquet dataset described by a run_manifest.json."""
    api = db_api or _default_db_api()
    batch_size = batch_size or _env_int("INGEST_BATCH_SIZE", 2000)
    parquet_batch_size = parquet_batch_size or _env_int("PARQUET_BATCH_SIZE", 10_000)

    manifest = load_manifest(manifest_path)
    expected_schema = int(SCHEMA_VERSION)
    if manifest.schema_version is not None:
        try:
            manifest_ver = int(manifest.schema_version)
        except (TypeError, ValueError):
            raise SystemExit(f"Invalid schema_version in manifest: {manifest.schema_version!r}") from None

        if manifest_ver != expected_schema and not _env_bool("ALLOW_SCHEMA_MISMATCH"):
            raise SystemExit(
                f"Schema mismatch: manifest={manifest_ver} expected={expected_schema}. "
                "Run `mckay migrate` (or `python db_migrate.py`) to update the DB, "
                "or set ALLOW_SCHEMA_MISMATCH=1 to override."
            )

    # Fail fast on mismatch: prevents ingesting with the wrong tenant/workspace.
    env_tenant = (os.getenv("TENANT_ID") or "").strip()
    env_ws = (os.getenv("WORKSPACE") or "").strip()
    if env_tenant and env_tenant != manifest.tenant_id:
        raise SystemExit(f"TENANT_ID mismatch: env={env_tenant!r} manifest={manifest.tenant_id!r}")
    if env_ws and env_ws != manifest.workspace:
        raise SystemExit(f"WORKSPACE mismatch: env={env_ws!r} manifest={manifest.workspace!r}")

    # Determine which dataset to ingest (prefer enriched -> correlated -> raw).
    dataset_dir = ""
    dataset_label = ""
    for path, label in _dataset_candidates(manifest):
        if path and _glob_has_files(path):
            dataset_dir = path
            dataset_label = label
            break
    if not dataset_dir:
        # If no files found, but paths exist, pick the first present path for a clearer error.
        for path, label in _dataset_candidates(manifest):
            if path:
                dataset_dir = path
                dataset_label = label
                break
        raise SystemExit("No parquet files found for manifest datasets.")

    raw_present = bool(manifest.out_raw and _glob_has_files(manifest.out_raw))
    correlated_present = bool(manifest.out_correlated and _glob_has_files(manifest.out_correlated))
    enriched_present = bool(manifest.out_enriched and _glob_has_files(manifest.out_enriched))

    run_ts = _parse_dt(manifest.run_ts) or datetime.now(timezone.utc)

    existing = api.fetch_one(
        "SELECT status FROM runs WHERE tenant_id=%s AND workspace=%s AND run_id=%s",
        (manifest.tenant_id, manifest.workspace, manifest.run_id),
    )
    if existing and existing[0] == "ready":
        print(f"SKIP: run already ingested: {manifest.tenant_id}/{manifest.workspace}/{manifest.run_id}")
        return IngestStats(
            dataset_used=dataset_label,
            dataset_dir=dataset_dir,
            raw_present=raw_present,
            correlated_present=correlated_present,
            enriched_present=enriched_present,
            presence_rows=0,
            latest_rows=0,
        )

    api.execute(
        """
        INSERT INTO runs (tenant_id, workspace, run_id, run_ts, status, artifact_prefix, ingested_at, engine_version,
                          raw_present, correlated_present, enriched_present)
        VALUES (%s, %s, %s, %s, 'ingesting', %s, NULL, %s, %s, %s, %s)
        ON CONFLICT (tenant_id, workspace, run_id) DO UPDATE SET
          run_ts = EXCLUDED.run_ts,
          status = 'ingesting',
          artifact_prefix = EXCLUDED.artifact_prefix,
          engine_version = EXCLUDED.engine_version,
          raw_present = EXCLUDED.raw_present,
          correlated_present = EXCLUDED.correlated_present,
          enriched_present = EXCLUDED.enriched_present
        """,
        (
            manifest.tenant_id,
            manifest.workspace,
            manifest.run_id,
            run_ts,
            dataset_dir,
            manifest.engine_version,
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

    parquet_files = _list_parquet_files(dataset_dir)
    if not parquet_files:
        raise SystemExit("No parquet files found for manifest datasets.")

    dataset = ds.dataset(parquet_files, format="parquet", partitioning="hive")
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

    print(
        f"OK: ingested {total_presence} items from {dataset_dir} as run "
        f"{manifest.tenant_id}/{manifest.workspace}/{manifest.run_id} "
        f"(presence={total_presence}, latest={total_latest})"
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

    env_path = os.getenv("MANIFEST_PATH")
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
