from __future__ import annotations

"""Integration-style tests for Parquet ingestion."""

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, List, Optional, Sequence, Tuple

from contracts.finops_contracts import build_ids_and_validate
from ingest_parquet import DbApi, ingest_from_manifest
from pipeline.run_manifest import RunManifest, write_manifest
from pipeline.writer_parquet import FindingsParquetWriter, ParquetWriterConfig


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
