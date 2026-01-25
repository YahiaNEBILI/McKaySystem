# tests/test_s3_storage.py
"""Unit tests for checks.aws.s3_storage.

These tests use minimal fake clients (no boto3).

Coverage:
- Lifecycle missing (original MVP behavior, now consolidated).
- Default encryption missing.
- Public Access Block missing/disabled.
- Storage cost estimate uses injected PricingService when available.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import pytest
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from botocore.exceptions import ClientError

from checks.aws.s3_storage import AwsAccountContext, S3StorageChecker


def _ce(code: str, op: str) -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": code}}, op)


class _FakeS3:
    def __init__(
        self,
        *,
        buckets: List[str],
        location_by_bucket: Optional[Dict[str, Optional[str]]] = None,
        lifecycle_present: Optional[Dict[str, bool]] = None,
        encryption_present: Optional[Dict[str, bool]] = None,
        pab_config_by_bucket: Optional[Dict[str, Optional[Dict[str, Any]]]] = None,
    ) -> None:
        self._buckets = buckets
        self._location_by_bucket = location_by_bucket or {}
        self._lifecycle_present = lifecycle_present or {}
        self._encryption_present = encryption_present or {}
        self._pab_config_by_bucket = pab_config_by_bucket or {}

    def list_buckets(self) -> Dict[str, Any]:
        return {"Buckets": [{"Name": b} for b in self._buckets]}

    def get_bucket_location(self, *, Bucket: str) -> Dict[str, Any]:
        # default: us-east-1 (None)
        return {"LocationConstraint": self._location_by_bucket.get(Bucket)}

    def get_bucket_lifecycle_configuration(self, *, Bucket: str) -> Dict[str, Any]:
        if self._lifecycle_present.get(Bucket, False):
            return {"Rules": []}
        raise _ce("NoSuchLifecycleConfiguration", "GetBucketLifecycleConfiguration")

    def get_bucket_encryption(self, *, Bucket: str) -> Dict[str, Any]:
        if self._encryption_present.get(Bucket, False):
            return {"ServerSideEncryptionConfiguration": {"Rules": []}}
        raise _ce("ServerSideEncryptionConfigurationNotFoundError", "GetBucketEncryption")

    def get_public_access_block(self, *, Bucket: str) -> Dict[str, Any]:
        cfg = self._pab_config_by_bucket.get(Bucket)
        if cfg is None:
            raise _ce("NoSuchPublicAccessBlockConfiguration", "GetPublicAccessBlock")
        return {"PublicAccessBlockConfiguration": cfg}



class _FakeCloudWatch:
    def __init__(self, *, avg_bytes_by_bucket_and_type: Dict[tuple, float]) -> None:
        # key: (bucket, storage_type)
        self._avg = avg_bytes_by_bucket_and_type

    def get_metric_statistics(self, **kwargs) -> Dict[str, Any]:
        dims = kwargs.get("Dimensions") or []
        bucket = ""
        storage_type = ""
        for d in dims:
            if d.get("Name") == "BucketName":
                bucket = str(d.get("Value") or "")
            if d.get("Name") == "StorageType":
                storage_type = str(d.get("Value") or "")

        avg = self._avg.get((bucket, storage_type))
        if avg is None:
            return {"Datapoints": []}

        return {
            "Datapoints": [
                {"Timestamp": datetime(2026, 1, 1, tzinfo=timezone.utc), "Average": float(avg)}
            ]
        }


class _FakePriceQuote:

    def __init__(self, *, unit_price_usd: float, unit: str = "GB-Mo", source: str = "cache") -> None:
        self.unit_price_usd = float(unit_price_usd)
        self.unit = unit
        self.source = source



class _FakePricing:
    def __init__(self, *, location: str, unit_price_by_storage_class: Dict[str, float]) -> None:
        self._location = location
        self._prices = {str(k): float(v) for k, v in unit_price_by_storage_class.items()}
        self.calls: List[Dict[str, Any]] = []

    def location_for_region(self, region: str) -> Optional[str]:
        _ = region
        return self._location

    def get_on_demand_unit_price(self, *, service_code: str, filters: Any, unit: str) -> Optional[_FakePriceQuote]:
        self.calls.append({"service_code": service_code, "filters": list(filters), "unit": unit})
        if service_code != "AmazonS3" or unit != "GB-Mo":
            return None

        storage_class = ""
        for f in list(filters):
            if f.get("Field") in ("storageClass", "volumeType"):
                storage_class = str(f.get("Value") or "")
                break

        if not storage_class:
            return None
        price = self._prices.get(storage_class)
        if price is None:
            return None
        return _FakePriceQuote(unit_price_usd=price, unit=unit, source="pricing_api")


@dataclass

class _FakeServices:
    s3: Any
    cloudwatch: Any = None
    pricing: Any = None


@dataclass
class _FakeCtx:
    cloud: str = "aws"
    services: Any = None


def _mk_checker() -> S3StorageChecker:
    return S3StorageChecker(account=AwsAccountContext(account_id="111111111111", billing_account_id="111111111111"))


def test_emits_lifecycle_encryption_and_pab_failures() -> None:
    checker = _mk_checker()

    s3 = _FakeS3(
        buckets=["b1"],
        location_by_bucket={"b1": "eu-west-3"},
        lifecycle_present={"b1": False},
        encryption_present={"b1": False},
        pab_config_by_bucket={"b1": None},
    )
    ctx = _FakeCtx(services=_FakeServices(s3=s3, cloudwatch=None, pricing=None))

    findings = list(checker.run(ctx))
    check_ids = sorted(f.check_id for f in findings)

    assert check_ids == sorted(
        [
            "aws.s3.governance.encryption_missing",
            "aws.s3.governance.lifecycle_missing",
            "aws.s3.governance.public_access_block_missing",
        ]
    )

    # region enrichment
    assert all(f.scope.region == "eu-west-3" for f in findings)
    # issue_key stable
    assert all(f.issue_key.get("bucket") == "b1" for f in findings)


def test_cost_estimate_uses_pricing_service_when_available() -> None:
    checker = _mk_checker()

    gib = 1024.0 ** 3
    # Sizes per storage class (GiB)
    sizes_gib = {
        ("b2", "StandardStorage"): 50.0,
        ("b2", "StandardIAStorage"): 25.0,
        ("b2", "OneZoneIAStorage"): 10.0,
        ("b2", "GlacierStorage"): 5.0,
        ("b2", "IntelligentTieringFAStorage"): 10.0,
    }
    sizes_bytes = {k: v * gib for k, v in sizes_gib.items()}

    s3 = _FakeS3(
        buckets=["b2"],
        location_by_bucket={"b2": "eu-west-3"},
        lifecycle_present={"b2": True},
        encryption_present={"b2": True},
        pab_config_by_bucket={
            "b2": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            }
        },
    )
    cw = _FakeCloudWatch(avg_bytes_by_bucket_and_type=sizes_bytes)

    pricing = _FakePricing(
        location="EU (Paris)",
        unit_price_by_storage_class={
            "Standard": 0.02,
            "Standard - Infrequent Access": 0.01,
            "One Zone - Infrequent Access": 0.008,
            "Glacier Flexible Retrieval": 0.004,
            "Intelligent-Tiering Frequent Access": 0.02,
        },
    )

    ctx = _FakeCtx(services=_FakeServices(s3=s3, cloudwatch=cw, pricing=pricing))

    findings = list(checker.run(ctx))
    cost = [f for f in findings if f.check_id == "aws.s3.cost.bucket_storage_estimate"]
    assert len(cost) == 1

    f = cost[0]

    # Expected total: 50*0.02 + 25*0.01 + 10*0.008 + 5*0.004 + 10*0.02
    expected = (50 * 0.02) + (25 * 0.01) + (10 * 0.008) + (5 * 0.004) + (10 * 0.02)
    assert f.estimated_monthly_cost is not None
    assert f.estimated_monthly_cost == pytest.approx(expected, abs=0.01)

    # Breakdown present and deterministic JSON
    assert "breakdown_json" in (f.dimensions or {})
    breakdown = json.loads(f.dimensions["breakdown_json"])
    assert isinstance(breakdown, list)
    # Should include at least the 5 classes we provided
    storage_types = {i.get("storage_type") for i in breakdown}
    assert {
        "StandardStorage",
        "StandardIAStorage",
        "OneZoneIAStorage",
        "GlacierStorage",
        "IntelligentTieringFAStorage",
    }.issubset(storage_types)

    assert pricing.calls, "Expected PricingService to be queried"
