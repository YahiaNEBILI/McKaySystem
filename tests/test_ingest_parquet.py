from __future__ import annotations

"""Integration-style tests for Parquet ingestion."""

import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, List, Optional, Sequence, Tuple

import pytest

from apps.backend import db_migrate
from contracts.finops_contracts import build_ids_and_validate
from apps.backend.db import db_conn
from apps.worker.ingest_parquet import DbApi, ingest_from_manifest
from pipeline.run_manifest import RunManifest, write_manifest
from pipeline.writer_parquet import FindingsParquetWriter, ParquetWriterConfig
from version import SCHEMA_VERSION


def _wire_record() -> dict:
    """Return a minimal wire-format record for tests."""
    return {
        "tenant_id": "acme",
        "workspace_id": "prod",
        "run_id": "run-1",
        "run_ts": datetime.now(timezone.utc),
        "ingested_ts": "",
        "engine_name": "finopsanalyzer",
        "engine_version": "0.1.0",
        "rulepack_version": "0.1.0",
        "check_id": "aws.s3.lifecycle.missing",
        "check_name": "S3 lifecycle policy",
        "category": "waste",
        "sub_category": "",
        "frameworks": [],
        "status": "fail",
        "severity": {"level": "low", "score": 20},
        "scope": {
            "cloud": "aws",
            "billing_account_id": "123",
            "account_id": "123",
            "region": "eu-west-3",
            "availability_zone": "",
            "service": "AmazonS3",
            "resource_type": "s3_bucket",
            "resource_id": "my-bucket",
            "resource_arn": "",
        },
        "title": "Bucket missing lifecycle policy",
        "message": "",
        "recommendation": "Add lifecycle policy to transition/expire objects.",
        "remediation": "",
        "links": [],
        "estimated": {
            "monthly_savings": 5.0,
            "monthly_cost": None,
            "one_time_savings": None,
            "confidence": 50,
            "notes": "",
        },
        "actual": {
            "cost_7d": None,
            "cost_30d": None,
            "cost_mtd": None,
            "cost_prev_month": None,
            "savings_7d": None,
            "savings_30d": None,
            "model": {"currency": "USD", "cost_model": "", "granularity": "", "period_start": "", "period_end": ""},
            "attribution": {"method": "", "confidence": 0, "matched_keys": []},
        },
        "lifecycle": {"status": "open", "first_seen_ts": "", "last_seen_ts": "", "resolved_ts": "", "snooze_until_ts": ""},
        "tags": {},
        "labels": {},
        "dimensions": {},
        "metrics": {},
        "metadata_json": "",
        "source": {"source_type": "scanner", "source_ref": "test", "schema_version": 1},
    }


class _FakeDb:
    """Capture DB calls for ingest tests."""
    def __init__(self) -> None:
        self.executes: List[Tuple[str, Optional[Sequence[Any]]]] = []
        self.execute_many_calls: List[Tuple[str, List[Sequence[Any]]]] = []

    def execute(self, sql: str, params: Optional[Sequence[Any]] = None) -> None:
        self.executes.append((sql, params))

    def execute_many(self, sql: str, seq_of_params: List[Sequence[Any]]) -> None:
        self.execute_many_calls.append((sql, list(seq_of_params)))

    def fetch_one(self, sql: str, params: Optional[Sequence[Any]] = None) -> Optional[Tuple[Any, ...]]:
        return None


def test_ingest_parquet_from_manifest(tmp_path: Path) -> None:
    base_dir = tmp_path / "finops_findings"

    wire1 = build_ids_and_validate(_wire_record(), issue_key={"policy": "missing"})
    wire2 = build_ids_and_validate(_wire_record(), issue_key={"policy": "missing-2"})

    writer = FindingsParquetWriter(
        ParquetWriterConfig(
            base_dir=str(base_dir),
            drop_invalid_on_cast=False,
            max_rows_per_file=10,
            max_buffered_rows=10,
        )
    )
    writer.extend([wire1, wire2])
    writer.close()

    manifest = RunManifest(
        tenant_id="acme",
        workspace="prod",
        run_id="run-1",
        run_ts=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        engine_name="finopsanalyzer",
        engine_version="0.1.0",
        rulepack_version="0.1.0",
        schema_version=1,
        out_raw=str(base_dir),
    )
    manifest_path = write_manifest(base_dir, manifest)

    fake = _FakeDb()
    stats = ingest_from_manifest(
        manifest_path,
        db_api=DbApi(execute=fake.execute, execute_many=fake.execute_many, fetch_one=fake.fetch_one),
        batch_size=1,
        parquet_batch_size=1,
    )

    presence_count = sum(len(rows) for sql, rows in fake.execute_many_calls if "finding_presence" in sql)
    latest_count = sum(len(rows) for sql, rows in fake.execute_many_calls if "finding_latest" in sql)

    assert stats.dataset_used == "raw"
    assert stats.raw_present is True
    assert stats.presence_rows == 2
    assert stats.latest_rows == 2
    assert presence_count == 2
    assert latest_count == 2


def test_ingest_parquet_merges_raw_and_correlated_from_manifest(tmp_path: Path) -> None:
    raw_dir = tmp_path / "finops_findings_raw"
    corr_dir = tmp_path / "finops_findings_correlated"

    raw1 = build_ids_and_validate(_wire_record(), issue_key={"policy": "raw-1"})
    raw2 = build_ids_and_validate(_wire_record(), issue_key={"policy": "raw-2"})

    corr_rec = _wire_record()
    corr_rec["check_id"] = "aws.correlation.cost.meta"
    corr_rec["title"] = "Correlated optimization finding"
    corr = build_ids_and_validate(corr_rec, issue_key={"policy": "corr-1"})

    raw_writer = FindingsParquetWriter(
        ParquetWriterConfig(
            base_dir=str(raw_dir),
            drop_invalid_on_cast=False,
            max_rows_per_file=10,
            max_buffered_rows=10,
        )
    )
    raw_writer.extend([raw1, raw2])
    raw_writer.close()

    corr_writer = FindingsParquetWriter(
        ParquetWriterConfig(
            base_dir=str(corr_dir),
            drop_invalid_on_cast=False,
            max_rows_per_file=10,
            max_buffered_rows=10,
        )
    )
    corr_writer.extend([corr])
    corr_writer.close()

    manifest = RunManifest(
        tenant_id="acme",
        workspace="prod",
        run_id="run-1",
        run_ts=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        engine_name="finopsanalyzer",
        engine_version="0.1.0",
        rulepack_version="0.1.0",
        schema_version=1,
        out_raw=str(raw_dir),
        out_correlated=str(corr_dir),
    )
    manifest_path = write_manifest(raw_dir, manifest)

    fake = _FakeDb()
    stats = ingest_from_manifest(
        manifest_path,
        db_api=DbApi(execute=fake.execute, execute_many=fake.execute_many, fetch_one=fake.fetch_one),
        batch_size=1,
        parquet_batch_size=1,
    )

    presence_count = sum(len(rows) for sql, rows in fake.execute_many_calls if "finding_presence" in sql)
    latest_count = sum(len(rows) for sql, rows in fake.execute_many_calls if "finding_latest" in sql)

    assert stats.dataset_used == "raw+correlated"
    assert stats.raw_present is True
    assert stats.correlated_present is True
    assert stats.presence_rows == 3
    assert stats.latest_rows == 3
    assert presence_count == 3
    assert latest_count == 3


def test_ingest_parquet_persists_manifest_pricing_metadata(tmp_path: Path) -> None:
    """Ingest should persist manifest pricing metadata on runs upsert."""
    base_dir = tmp_path / "finops_findings"
    wire = build_ids_and_validate(_wire_record(), issue_key={"policy": "pricing-meta"})

    writer = FindingsParquetWriter(
        ParquetWriterConfig(
            base_dir=str(base_dir),
            drop_invalid_on_cast=False,
            max_rows_per_file=10,
            max_buffered_rows=10,
        )
    )
    writer.extend([wire])
    writer.close()

    manifest = RunManifest(
        tenant_id="acme",
        workspace="prod",
        run_id="run-1",
        run_ts=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        engine_name="finopsanalyzer",
        engine_version="0.1.0",
        rulepack_version="0.1.0",
        schema_version=1,
        pricing_version="aws_2026_06_01",
        pricing_source="snapshot",
        out_raw=str(base_dir),
    )
    manifest_path = write_manifest(base_dir, manifest)

    fake = _FakeDb()
    ingest_from_manifest(
        manifest_path,
        db_api=DbApi(execute=fake.execute, execute_many=fake.execute_many, fetch_one=fake.fetch_one),
        batch_size=1,
        parquet_batch_size=1,
    )

    run_upserts = [(sql, params) for sql, params in fake.executes if "INSERT INTO runs" in sql]
    assert run_upserts, "expected runs upsert during ingest"
    sql, params = run_upserts[0]
    assert "pricing_version" in sql
    assert "pricing_source" in sql
    params_list = list(params or ())
    assert "aws_2026_06_01" in params_list
    assert "snapshot" in params_list


def test_ingest_parquet_rejects_invalid_manifest_run_ts(tmp_path: Path) -> None:
    base_dir = tmp_path / "finops_findings"
    wire = build_ids_and_validate(_wire_record(), issue_key={"policy": "bad-ts"})

    writer = FindingsParquetWriter(
        ParquetWriterConfig(
            base_dir=str(base_dir),
            drop_invalid_on_cast=False,
            max_rows_per_file=10,
            max_buffered_rows=10,
        )
    )
    writer.extend([wire])
    writer.close()

    manifest = RunManifest(
        tenant_id="acme",
        workspace="prod",
        run_id="run-1",
        run_ts="not-an-iso-timestamp",
        engine_name="finopsanalyzer",
        engine_version="0.1.0",
        rulepack_version="0.1.0",
        schema_version=1,
        out_raw=str(base_dir),
    )
    manifest_path = write_manifest(base_dir, manifest)

    fake = _FakeDb()
    with pytest.raises(SystemExit, match="Invalid run_ts in manifest"):
        ingest_from_manifest(
            manifest_path,
            db_api=DbApi(execute=fake.execute, execute_many=fake.execute_many, fetch_one=fake.fetch_one),
            batch_size=1,
            parquet_batch_size=1,
        )


def test_ingest_parquet_copy_integration(tmp_path: Path) -> None:
    if not os.getenv("DB_URL") or not os.getenv("RUN_DB_TESTS"):
        pytest.skip("Set DB_URL and RUN_DB_TESTS=1 to enable integration test.")

    # Ensure migrations are applied.
    db_migrate.run_migrations(migrations_dir=Path("migrations"), dry_run=False)

    tenant_id = "test_ingest_parquet"
    workspace = "ci"
    run_id = f"run-{uuid.uuid4().hex}"

    base_dir = tmp_path / "finops_findings"

    def _mk_record(issue_key: str) -> dict:
        rec = _wire_record()
        rec["tenant_id"] = tenant_id
        rec["workspace_id"] = workspace
        rec["run_id"] = run_id
        rec["run_ts"] = datetime.now(timezone.utc)
        return build_ids_and_validate(rec, issue_key={"policy": issue_key})

    wire1 = _mk_record("missing")
    wire2 = _mk_record("missing-2")

    fingerprints = [wire1["fingerprint"], wire2["fingerprint"]]

    writer = FindingsParquetWriter(
        ParquetWriterConfig(
            base_dir=str(base_dir),
            drop_invalid_on_cast=False,
            max_rows_per_file=10,
            max_buffered_rows=10,
        )
    )
    writer.extend([wire1, wire2])
    writer.close()

    manifest = RunManifest(
        tenant_id=tenant_id,
        workspace=workspace,
        run_id=run_id,
        run_ts=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        engine_name="finopsanalyzer",
        engine_version="0.1.0",
        rulepack_version="0.1.0",
        schema_version=SCHEMA_VERSION,
        out_raw=str(base_dir),
    )
    manifest_path = write_manifest(base_dir, manifest)

    try:
        stats = ingest_from_manifest(manifest_path)
        assert stats.presence_rows == 2
        assert stats.latest_rows == 2

        with db_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT status FROM runs WHERE tenant_id=%s AND workspace=%s AND run_id=%s",
                    (tenant_id, workspace, run_id),
                )
                row = cur.fetchone()
                assert row and row[0] == "ready"

                cur.execute(
                    "SELECT COUNT(*) FROM finding_presence WHERE tenant_id=%s AND workspace=%s AND run_id=%s",
                    (tenant_id, workspace, run_id),
                )
                assert int(cur.fetchone()[0]) == 2

                cur.execute(
                    "SELECT COUNT(*) FROM finding_latest WHERE tenant_id=%s AND workspace=%s AND fingerprint = ANY(%s::text[])",
                    (tenant_id, workspace, fingerprints),
                )
                assert int(cur.fetchone()[0]) == 2
            conn.commit()
    finally:
        with db_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "DELETE FROM finding_presence WHERE tenant_id=%s AND workspace=%s AND run_id=%s",
                    (tenant_id, workspace, run_id),
                )
                cur.execute(
                    "DELETE FROM finding_latest WHERE tenant_id=%s AND workspace=%s AND fingerprint = ANY(%s::text[])",
                    (tenant_id, workspace, fingerprints),
                )
                cur.execute(
                    "DELETE FROM runs WHERE tenant_id=%s AND workspace=%s AND run_id=%s",
                    (tenant_id, workspace, run_id),
                )
            conn.commit()
