"""Unit tests for the Parquet writer."""

from __future__ import annotations

import os
from datetime import datetime, timezone

import pyarrow.parquet as pq

from contracts.finops_contracts import build_ids_and_validate
from pipeline.writer_parquet import FindingsParquetWriter, ParquetWriterConfig


def _wire_record() -> dict:
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

        "estimated": {"monthly_savings": 5.0, "monthly_cost": None, "one_time_savings": None, "confidence": 50, "notes": ""},
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


def test_writer_writes_partitioned_parquet(tmp_path) -> None:
    base_dir = tmp_path / "finops_findings"

    wire = _wire_record()
    wire = build_ids_and_validate(wire, issue_key={"policy": "missing"})

    writer = FindingsParquetWriter(
        ParquetWriterConfig(
            base_dir=str(base_dir),
            drop_invalid_on_cast=False,
            max_rows_per_file=10,
            max_buffered_rows=10,
        )
    )
    writer.append(wire)
    stats = writer.close()

    assert stats.received == 1
    assert stats.written == 1

    # Expect partition folders exist
    # tenant_id=acme/run_date=YYYY-MM-DD/part-*.parquet
    tenant_dir = base_dir / "tenant_id=acme"
    assert tenant_dir.exists()

    # Find a parquet file recursively
    parquet_files = []
    for root, _, files in os.walk(base_dir):
        for f in files:
            if f.endswith(".parquet"):
                parquet_files.append(os.path.join(root, f))

    assert parquet_files, "No parquet files written"

    # Sanity read with pyarrow
    pf = pq.ParquetFile(parquet_files[0])
    table = pf.read()
    assert table.num_rows == 1
    assert "tenant_id" in table.schema.names
    assert "finding_id" in table.schema.names
