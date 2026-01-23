from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal

import pyarrow as pa
import pytest

from contracts.finops_contracts import build_ids_and_validate
from contracts.finops_contracts import ValidationError
from contracts.schema import FINOPS_FINDINGS_SCHEMA
from contracts.storage_cast import cast_for_storage


def _minimal_wire_record() -> dict:
    # This is WIRE format: strings are ok, "" allowed for optional fields
    return {
        "tenant_id": "acme",
        "workspace_id": "prod",
        "run_id": "run-1",
        "run_ts": datetime.now(timezone.utc),  # wire can be datetime or ISO string
        "ingested_ts": "",  # allowed in wire

        "engine_name": "finopsanalyzer",
        "engine_version": "0.1.0",
        "rulepack_version": "0.1.0",

        "check_id": "aws.ec2.rightsize.graviton",
        "check_name": "EC2 Graviton candidates",
        "category": "rightsizing",
        "sub_category": "",
        "frameworks": [],

        "status": "fail",
        "severity": {"level": "medium", "score": 60},

        "scope": {
            "cloud": "aws",
            "billing_account_id": "123",
            "account_id": "123",
            "region": "eu-west-3",
            "availability_zone": "",
            "service": "AmazonEC2",
            "resource_type": "ec2_instance",
            "resource_id": "i-abc",
            "resource_arn": "",
        },

        "title": "Graviton candidate",
        "message": "x86 instance appears compatible with Graviton.",
        "recommendation": "Try m7g/c7g/r7g.",
        "remediation": "",
        "links": [],

        # Estimated: in wire we allow numeric strings / empty strings
        "estimated": {
            "monthly_savings": "12.340000",
            "monthly_cost": "",
            "one_time_savings": "",
            "confidence": 70,
            "notes": "",
        },

        # Actual can be empty in wire
        "actual": {
            "cost_7d": "",
            "cost_30d": "",
            "cost_mtd": "",
            "cost_prev_month": "",
            "savings_7d": "",
            "savings_30d": "",
            "model": {
                "currency": "USD",
                "cost_model": "",
                "granularity": "",
                "period_start": "",
                "period_end": "",
            },
            "attribution": {
                "method": "",
                "confidence": 0,
                "matched_keys": [],
            },
        },

        "lifecycle": {
            "status": "open",
            "first_seen_ts": "",
            "last_seen_ts": "",
            "resolved_ts": "",
            "snooze_until_ts": "",
        },

        "tags": {"Name": "demo"},
        "labels": {},
        "dimensions": {},
        "metrics": {},
        "metadata_json": "",

        "source": {"source_type": "scanner", "source_ref": "test", "schema_version": 1},
    }


def test_wire_to_storage_cast_builds_arrow_table() -> None:
    wire = _minimal_wire_record()

    # Contract step: generates fingerprint + finding_id and validates required fields
    wire = build_ids_and_validate(
        wire,
        issue_key={"recommended_arch": "arm64"},
        finding_id_salt=None,
    )
    assert wire["finding_id"]
    assert wire["fingerprint"]

    # Storage boundary: cast to Arrow-compatible python types
    storage = cast_for_storage(wire, FINOPS_FINDINGS_SCHEMA)

    # Check a few important type conversions
    assert isinstance(storage["run_ts"], datetime)
    assert storage["run_ts"].tzinfo is not None

    assert isinstance(storage["estimated"]["monthly_savings"], Decimal)
    assert storage["estimated"]["monthly_cost"] is None  # "" -> None for Decimal fields

    # Arrow reality check: should build a table without type errors
    table = pa.Table.from_pylist([storage], schema=FINOPS_FINDINGS_SCHEMA)
    assert table.num_rows == 1


def test_cast_rejects_invalid_decimal() -> None:
    wire = _minimal_wire_record()
    wire["estimated"]["monthly_savings"] = "not-a-number"

    with pytest.raises(ValidationError):
        _ = build_ids_and_validate(wire, issue_key={"recommended_arch": "arm64"})
