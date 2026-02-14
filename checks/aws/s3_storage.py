"""checks/aws/s3_storage.py

S3 storage & governance checker.

This consolidates the original MVP check (missing lifecycle configuration) and
extends it into a real S3 storage checker with additional governance and cost
signals.

Emitted check_ids:
  - aws.s3.governance.lifecycle.missing
  - aws.s3.governance.encryption.missing
  - aws.s3.governance.public.access.block.missing
  - aws.s3.cost.bucket.storage.estimate
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

from botocore.client import BaseClient
from botocore.exceptions import ClientError

from checks.aws._common import (
    build_scope,
    AwsAccountContext,
    now_utc,
    get_logger,
)
from checks.aws.defaults import S3_DEFAULT_STORAGE_PRICE_GB_MONTH_USD, S3_METRIC_LOOKBACK_DAYS
from checks.registry import Bootstrap, register_checker
from contracts.finops_checker_pattern import FindingDraft, RunContext, Scope, Severity

# Logger for this module
_LOGGER = get_logger("s3_storage")


def _normalize_s3_location_constraint(value: Optional[str]) -> str:
    """Normalize S3 GetBucketLocation LocationConstraint values."""
    if not value:
        return "us-east-1"
    if value == "EU":
        return "eu-west-1"
    return str(value)


def _client_error_code(exc: ClientError) -> str:
    return str(exc.response.get("Error", {}).get("Code", "") or "")


def _bytes_to_gib(value: float) -> float:
    return float(value) / (1024.0 ** 3)


def _scope(
    ctx: Any,
    *,
    account_id: str,
    billing_account_id: str,
    region: str,
    bucket: str,
) -> Scope:
    return build_scope(
        ctx,
        account=AwsAccountContext(account_id=str(account_id), billing_account_id=str(billing_account_id)),
        region=str(region),
        service="AmazonS3",
        resource_type="s3_bucket",
        resource_id=str(bucket),
        resource_arn=f"arn:aws:s3:::{bucket}",
    )


class S3StorageChecker:
    """Consolidated S3 checker (governance + basic storage cost insight)."""

    checker_id = "aws.s3.storage"  # informational; emitted findings use per-signal check_id
    is_regional = False

    # check ids
    _CID_LIFECYCLE = "aws.s3.governance.lifecycle.missing"
    _CID_ENCRYPTION = "aws.s3.governance.encryption.missing"
    _CID_PAB = "aws.s3.governance.public.access.block.missing"
    _CID_COST = "aws.s3.cost.bucket.storage.estimate"

    def __init__(
        self,
        *,
        account: AwsAccountContext,
        default_storage_price_gb_month_usd: float = S3_DEFAULT_STORAGE_PRICE_GB_MONTH_USD,
        metric_lookback_days: int = S3_METRIC_LOOKBACK_DAYS,
    ) -> None:
        self._account = account
        self._default_price = float(default_storage_price_gb_month_usd)
        self._lookback_days = int(metric_lookback_days)

    def run(self, ctx: RunContext) -> Iterable[FindingDraft]:
        _LOGGER.info("Starting S3 storage check")
        if ctx.services is None:
            raise RuntimeError("S3StorageChecker requires ctx.services (AWS clients)")

        s3: BaseClient = ctx.services.s3
        cloudwatch: Optional[BaseClient] = getattr(ctx.services, "cloudwatch", None)
        pricing = getattr(ctx.services, "pricing", None)

        billing_account_id = self._account.billing_account_id or self._account.account_id

        resp = s3.list_buckets()
        _LOGGER.debug("Listed S3 buckets")
        bucket_count = len(resp.get("Buckets", []) or [])
        _LOGGER.info("S3 buckets found", extra={"bucket_count": bucket_count})
        for bucket in resp.get("Buckets", []) or []:
            name = str(bucket.get("Name") or "")
            if not name:
                continue

            bucket_region = self._bucket_region_best_effort(s3, name)
            scope = _scope(
                ctx,
                account_id=self._account.account_id,
                billing_account_id=billing_account_id,
                region=bucket_region,
                bucket=name,
            )

            # ------------------------------
            # Governance: lifecycle
            # ------------------------------
            lifecycle_state, lifecycle_note = self._has_lifecycle_best_effort(s3, name)
            if lifecycle_state == "missing":
                yield FindingDraft(
                    check_id=self._CID_LIFECYCLE,
                    check_name="S3 bucket missing lifecycle policy",
                    category="governance",
                    status="fail",
                    severity=Severity(level="medium", score=50),
                    title="S3 bucket has no lifecycle configuration",
                    message=f"Bucket {name} does not have a lifecycle policy.",
                    recommendation="Add lifecycle rules to transition or expire objects where appropriate.",
                    scope=scope,
                    issue_key={"check_id": self._CID_LIFECYCLE, "bucket": name},
                    estimated_monthly_savings=None,
                    estimate_confidence=0,
                    estimate_notes=lifecycle_note,
                )
            elif lifecycle_state == "unknown":
                yield FindingDraft(
                    check_id=self._CID_LIFECYCLE,
                    check_name="S3 lifecycle policy missing (unable to verify)",
                    category="governance",
                    status="info",
                    severity=Severity(level="low", score=10),
                    title="Cannot verify lifecycle policy (access denied)",
                    message=f"Access denied when reading lifecycle configuration for bucket {name}.",
                    recommendation="Grant s3:GetLifecycleConfiguration to the scanner role.",
                    scope=scope,
                    issue_key={"check_id": self._CID_LIFECYCLE, "bucket": name, "reason": "access_denied"},
                    estimated_monthly_savings=None,
                    estimate_confidence=0,
                    estimate_notes=lifecycle_note,
                )

            # ------------------------------
            # Governance: default encryption
            # ------------------------------
            enc_state, enc_note = self._has_default_encryption_best_effort(s3, name)
            if enc_state == "missing":
                yield FindingDraft(
                    check_id=self._CID_ENCRYPTION,
                    check_name="S3 bucket missing default encryption",
                    category="governance",
                    status="fail",
                    severity=Severity(level="high", score=80),
                    title="S3 bucket has no default encryption",
                    message=f"Bucket {name} has no default encryption configured (SSE).",
                    recommendation="Enable default encryption (SSE-S3 or SSE-KMS) for the bucket.",
                    scope=scope,
                    issue_key={"check_id": self._CID_ENCRYPTION, "bucket": name},
                    estimated_monthly_savings=None,
                    estimate_confidence=0,
                    estimate_notes=enc_note,
                )
            elif enc_state == "unknown":
                yield FindingDraft(
                    check_id=self._CID_ENCRYPTION,
                    check_name="S3 default encryption missing (unable to verify)",
                    category="governance",
                    status="info",
                    severity=Severity(level="low", score=10),
                    title="Cannot verify default encryption (access denied)",
                    message=f"Access denied when reading encryption configuration for bucket {name}.",
                    recommendation="Grant s3:GetEncryptionConfiguration to the scanner role.",
                    scope=scope,
                    issue_key={"check_id": self._CID_ENCRYPTION, "bucket": name, "reason": "access_denied"},
                    estimated_monthly_savings=None,
                    estimate_confidence=0,
                    estimate_notes=enc_note,
                )

            # ------------------------------
            # Governance: Public Access Block
            # ------------------------------
            pab_state, pab_note = self._public_access_block_state_best_effort(s3, name)
            if pab_state == "missing":
                yield FindingDraft(
                    check_id=self._CID_PAB,
                    check_name="S3 bucket missing Public Access Block",
                    category="governance",
                    status="fail",
                    severity=Severity(level="high", score=85),
                    title="S3 bucket public access block is missing/disabled",
                    message=(
                        f"Bucket {name} does not have a Public Access Block configuration, "
                        "or it is not fully enabled."
                    ),
                    recommendation="Enable S3 Public Access Block (all 4 settings) unless explicitly required.",
                    scope=scope,
                    issue_key={"check_id": self._CID_PAB, "bucket": name},
                    estimated_monthly_savings=None,
                    estimate_confidence=0,
                    estimate_notes=pab_note,
                )
            elif pab_state == "unknown":
                yield FindingDraft(
                    check_id=self._CID_PAB,
                    check_name="S3 Public Access Block missing (unable to verify)",
                    category="governance",
                    status="info",
                    severity=Severity(level="low", score=10),
                    title="Cannot verify Public Access Block (access denied)",
                    message=f"Access denied when reading Public Access Block for bucket {name}.",
                    recommendation="Grant s3:GetBucketPublicAccessBlock to the scanner role.",
                    scope=scope,
                    issue_key={"check_id": self._CID_PAB, "bucket": name, "reason": "access_denied"},
                    estimated_monthly_savings=None,
                    estimate_confidence=0,
                    estimate_notes=pab_note,
                )

            # ------------------------------
            # Cost: storage estimate (multi-class, best-effort)
            # ------------------------------

            if cloudwatch is not None:
                breakdown = self._bucket_storage_breakdown_best_effort(
                    cloudwatch,
                    pricing=pricing,
                    region=bucket_region,
                    bucket=name,
                )
                if breakdown is not None:
                    total_gib = float(breakdown.get("total_size_gib") or 0.0)

                    # Guard against "0.0 GiB" findings caused by rounding tiny non-zero values.
                    # CloudWatch S3 metrics can be sparse and/or small buckets may round to 0.0 at 1 decimal.
                    # If you want *any* storage estimate finding, it should at least be visibly > 0.0.
                    if total_gib < 0.05:  # ~51 MiB
                        continue

                    # Your policy: don't emit small buckets (noise). Keep as-is.
                    if total_gib < 10.0:
                        continue

                    total_cost = float(breakdown.get("total_monthly_cost_usd") or 0.0)

                    # Deterministic JSON breakdown (stable key ordering, stable rounding)
                    breakdown_items = breakdown.get("items") or []
                    classes = len(breakdown_items)
                    class_word = "class" if classes == 1 else "classes"
                    across_phrase = f"across {classes} {class_word}"

                    breakdown_json = json.dumps(
                        breakdown_items,
                        sort_keys=True,
                        separators=(",", ":"),
                        ensure_ascii=False,
                    )

                    yield FindingDraft(
                        check_id=self._CID_COST,
                        check_name="S3 bucket storage cost estimate",
                        category="cost",
                        sub_category="storage",
                        status="info",
                        severity=Severity(level="low", score=20),
                        title=(
                            f"S3 bucket storage estimate: {name} "
                            f"(~{total_gib:.1f} GiB {across_phrase})"
                        ),
                        message=(
                            f"Estimated storage size ≈ {total_gib:.1f} GiB {across_phrase}. "
                            f"Estimated cost ≈ ${total_cost:.2f}/month (storage-only)."
                        ),
                        recommendation=(
                            "Use this estimate to prioritize storage optimization (lifecycle, tiering, archival). "
                            "Confirm with AWS Cost Explorer / CUR for billing-accurate numbers."
                        ),
                        scope=scope,
                        issue_key={"check_id": self._CID_COST, "bucket": name, "mode": "multi_class"},
                        estimated_monthly_cost=round(total_cost, 2),
                        estimated_monthly_savings=None,
                        estimate_confidence=int(breakdown.get("estimate_confidence") or 0),
                        estimate_notes=str(breakdown.get("estimate_notes") or ""),
                        dimensions={
                            "currency": "USD",
                            "total_size_gib": f"{total_gib:.4f}",
                            "total_monthly_cost_usd": f"{total_cost:.4f}",
                            "breakdown_json": breakdown_json,
                        },
                    )


    # ------------------------------
    # Best-effort helpers
    # ------------------------------

    def _bucket_region_best_effort(self, s3: BaseClient, bucket: str) -> str:
        try:
            loc = s3.get_bucket_location(Bucket=bucket)
            return _normalize_s3_location_constraint(loc.get("LocationConstraint"))
        except ClientError as exc:
            code = _client_error_code(exc)
            if code in ("AccessDenied", "AllAccessDisabled"):
                return "unknown"
            raise

    def _has_lifecycle_best_effort(self, s3: BaseClient, bucket: str) -> Tuple[str, str]:
        """Return (state, note) where state is one of: present/missing/unknown."""
        try:
            s3.get_bucket_lifecycle_configuration(Bucket=bucket)
            return "present", ""
        except ClientError as exc:
            code = _client_error_code(exc)
            if code in ("NoSuchLifecycleConfiguration", "NoSuchLifecycleConfigurationException"):
                return "missing", "No lifecycle configuration."
            if code in ("AccessDenied", "AllAccessDisabled"):
                return "unknown", "Access denied while reading lifecycle configuration."
            raise

    def _has_default_encryption_best_effort(self, s3: BaseClient, bucket: str) -> Tuple[str, str]:
        try:
            s3.get_bucket_encryption(Bucket=bucket)
            return "present", ""
        except ClientError as exc:
            code = _client_error_code(exc)
            if code in ("ServerSideEncryptionConfigurationNotFoundError", "NoSuchEncryptionConfiguration"):
                return "missing", "No default encryption configuration."
            if code in ("AccessDenied", "AllAccessDisabled"):
                return "unknown", "Access denied while reading encryption configuration."
            raise

    def _public_access_block_state_best_effort(self, s3: BaseClient, bucket: str) -> Tuple[str, str]:
        try:
            resp = s3.get_public_access_block(Bucket=bucket)
            cfg = (resp or {}).get("PublicAccessBlockConfiguration") or {}
            required = [
                "BlockPublicAcls",
                "IgnorePublicAcls",
                "BlockPublicPolicy",
                "RestrictPublicBuckets",
            ]
            if all(bool(cfg.get(k)) for k in required):
                return "present", ""
            return "missing", "Public Access Block is not fully enabled."
        except ClientError as exc:
            code = _client_error_code(exc)
            if code in ("NoSuchPublicAccessBlockConfiguration", "NoSuchPublicAccessBlockConfigurationException"):
                return "missing", "No Public Access Block configuration."
            if code in ("AccessDenied", "AllAccessDisabled"):
                return "unknown", "Access denied while reading Public Access Block configuration."
            raise

    # ------------------------------
    # CloudWatch sizing helpers
    # ------------------------------
    def _bucket_size_gib_best_effort(
        self,
        cloudwatch: BaseClient,
        *,
        bucket: str,
        storage_type: str,
    ) -> Optional[float]:
        """Best-effort bucket size in GiB for a given CloudWatch StorageType.

        Uses AWS/S3 BucketSizeBytes (updated daily). We query a small lookback
        window and pick the latest datapoint by timestamp.

        Returns:
          - None: cannot query metric (permission or no datapoints)
          - 0.0: bucket has 0 bytes for this storage type
          - >0: GiB value
        """
        end = now_utc()
        start = end - timedelta(days=max(1, self._lookback_days))
        try:
            resp = cloudwatch.get_metric_statistics(
                Namespace="AWS/S3",
                MetricName="BucketSizeBytes",
                Dimensions=[
                    {"Name": "BucketName", "Value": bucket},
                    {"Name": "StorageType", "Value": storage_type},
                ],
                StartTime=start,
                EndTime=end,
                Period=86400,
                Statistics=["Average"],
            )
        except ClientError:
            return None

        datapoints = resp.get("Datapoints", []) or []
        if not datapoints:
            return None

        # Filter out None values and ensure we have valid timestamps
        valid_datapoints = [
            d for d in datapoints
            if isinstance(d, dict) and d.get("Timestamp") is not None
        ]
        if not valid_datapoints:
            return None

        latest = max(
            valid_datapoints,
            key=lambda d: d.get("Timestamp") or datetime.min.replace(tzinfo=timezone.utc),
        )
        avg = latest.get("Average")
        if avg is None:
            return None
        try:
            avg_f = float(avg)
        except (TypeError, ValueError):
            return None

        if avg_f <= 0:
            return 0.0
        return _bytes_to_gib(avg_f)

    # ------------------------------
    # Pricing helpers (best-effort)
    # ------------------------------
    def _storage_price_best_effort(
        self,
        *,
        pricing: Any,
        region: str,
        pricing_storage_class: str,
        fallback_usd_per_gb_month: float,
    ) -> Tuple[float, str, int, str]:
        """Return (usd_per_gb_month, notes, confidence, price_source)."""
        fallback = (
            float(fallback_usd_per_gb_month),
            f"Fallback pricing used (no PricingService quote) for {pricing_storage_class}.",
            55,
            "fallback",
        )
        if pricing is None:
            return fallback

        location = getattr(pricing, "location_for_region", lambda _r: None)(region)
        if not location:
            return fallback

        # Pricing API can be finicky; try a small set of common attributes deterministically.
        attempts: List[List[Dict[str, str]]] = [
            [
                {"Field": "location", "Value": location},
                {"Field": "productFamily", "Value": "Storage"},
                {"Field": "storageClass", "Value": pricing_storage_class},
            ],
            [
                {"Field": "location", "Value": location},
                {"Field": "productFamily", "Value": "Storage"},
                {"Field": "volumeType", "Value": pricing_storage_class},
            ],
        ]

        for flt in attempts:
            quote = pricing.get_on_demand_unit_price(
                service_code="AmazonS3",
                filters=flt,
                unit="GB-Mo",
            )
            if quote is None:
                continue
            unit_price = float(getattr(quote, "unit_price_usd", fallback_usd_per_gb_month))
            if unit_price <= 0:
                continue
            return (
                unit_price,
                f"PricingService quote for S3 {pricing_storage_class} in {location} ({quote.source}).",
                80,
                str(getattr(quote, "source", "pricing_service") or "pricing_service"),
            )

        return fallback

    def _bucket_storage_breakdown_best_effort(
        self,
        cloudwatch: BaseClient,
        *,
        pricing: Any,
        region: str,
        bucket: str,
    ) -> Optional[Dict[str, Any]]:
        """Compute a deterministic multi-class storage breakdown for a bucket.

        Uses CloudWatch storage metrics for multiple storage classes and estimates cost
        using PricingService when possible (fallback otherwise).
        """
        # Fixed order for determinism.
        # CloudWatch StorageType -> Pricing storageClass -> fallback $/GB-Mo
        storage_matrix: List[Tuple[str, str, float]] = [
            ("StandardStorage", "Standard", self._default_price),
            ("StandardIAStorage", "Standard - Infrequent Access", 0.0125),
            ("OneZoneIAStorage", "One Zone - Infrequent Access", 0.0100),
            ("IntelligentTieringFAStorage", "Intelligent-Tiering Frequent Access", self._default_price),
            ("IntelligentTieringIAStorage", "Intelligent-Tiering Infrequent Access", 0.0125),
            ("IntelligentTieringAAStorage", "Intelligent-Tiering Archive Access", 0.0040),
            ("GlacierStorage", "Glacier Flexible Retrieval", 0.0040),
            ("GlacierIRStorage", "Glacier Instant Retrieval", 0.0050),
            ("DeepArchiveStorage", "Glacier Deep Archive", 0.00099),
        ]

        items: List[Dict[str, str]] = []
        total_size = 0.0
        total_cost = 0.0
        confidences: List[int] = []
        notes_parts: List[str] = []

        for cw_storage_type, pricing_storage_class, fallback_price in storage_matrix:
            size_gib = self._bucket_size_gib_best_effort(
                cloudwatch,
                bucket=bucket,
                storage_type=cw_storage_type,
            )
            if size_gib is None or size_gib <= 0:
                continue

            usd_per_gb_month, note, conf, source = self._storage_price_best_effort(
                pricing=pricing,
                region=region,
                pricing_storage_class=pricing_storage_class,
                fallback_usd_per_gb_month=fallback_price,
            )
            monthly_cost = float(size_gib) * float(usd_per_gb_month)

            items.append(
                {
                    "storage_type": cw_storage_type,
                    "pricing_storage_class": pricing_storage_class,
                    "size_gib": f"{float(size_gib):.6f}",
                    "usd_per_gb_month": f"{float(usd_per_gb_month):.6f}",
                    "monthly_cost_usd": f"{float(monthly_cost):.6f}",
                    "price_source": source,
                }
            )
            total_size += float(size_gib)
            total_cost += float(monthly_cost)
            confidences.append(int(conf))
            notes_parts.append(note)

        if not items:
            return None

        est_conf = min(confidences) if confidences else 50
        uniq_notes: List[str] = []
        for n in notes_parts:
            if n and n not in uniq_notes:
                uniq_notes.append(n)
        summary_notes = "; ".join(uniq_notes[:3])

        return {
            "items": items,
            "total_size_gib": float(total_size),
            "total_monthly_cost_usd": float(total_cost),
            "estimate_confidence": int(est_conf),
            "estimate_notes": summary_notes,
        }


@register_checker("checks.aws.s3_storage:S3StorageChecker")
def _factory(ctx: RunContext, bootstrap: Bootstrap) -> S3StorageChecker:
    """Instantiate this checker from runtime bootstrap data."""
    account_id = str(bootstrap.get("aws_account_id") or "")
    if not account_id:
        raise RuntimeError("aws_account_id missing from bootstrap (required for S3StorageChecker)")

    billing_account_id = str(bootstrap.get("aws_billing_account_id") or account_id)
    return S3StorageChecker(
        account=AwsAccountContext(account_id=account_id, billing_account_id=billing_account_id),
    )
