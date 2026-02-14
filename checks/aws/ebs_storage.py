"""
checks/aws/ebs_storage.py

EBS storage optimization checker (DI-friendly, FindingDraft-based).

Signals (cost):
1) Unattached EBS volumes older than N days
2) gp2 -> gp3 migration candidates (storage-only savings estimate; fallback pricing)
3) Old EBS snapshots older than N days NOT referenced by any AMI (tag suppress supported)
    + guardrails to skip AWS Backup-managed snapshots (tag/description patterns)

Signals (governance):
4) Unencrypted EBS volumes
5) Unencrypted EBS snapshots
    + guardrails to skip AWS Backup-managed snapshots

Caveat:
- This checker runs in the single region configured for ctx.services.ec2.
  For multi-region, prefer adding a region-aware client factory to Services.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Dict, Iterable, List, Mapping, Optional, Set, Tuple

from botocore.exceptions import BotoCoreError, ClientError

import checks.aws._common as common
from checks.aws.defaults import (
    EBS_MAX_FINDINGS_PER_TYPE,
    EBS_SNAPSHOT_OLD_AGE_DAYS,
    EBS_SUPPRESS_TAG_KEYS,
    EBS_SUPPRESS_TAG_VALUES,
    EBS_SUPPRESS_VALUE_PREFIXES,
    EBS_UNATTACHED_MIN_AGE_DAYS,
)

from checks.registry import Bootstrap, register_checker
from contracts.finops_checker_pattern import Checker, FindingDraft, RunContext, Scope, Severity



# -----------------------------
# Config
# -----------------------------


@dataclass(frozen=True)
class EBSStorageConfig:
    unattached_min_age_days: int = EBS_UNATTACHED_MIN_AGE_DAYS
    snapshot_old_age_days: int = EBS_SNAPSHOT_OLD_AGE_DAYS

    suppress_tag_keys: Tuple[str, ...] = EBS_SUPPRESS_TAG_KEYS
    suppress_tag_values: Tuple[str, ...] = EBS_SUPPRESS_TAG_VALUES
    # Prefix-based suppression for common retention tags such as:
    #   retention_policy=keep-90-days
    #   purpose=backup-prod
    # This keeps strict equality matching but also treats any value starting with
    # one of these prefixes as a suppress signal when the key is in suppress_tag_keys.
    suppress_value_prefixes: Tuple[str, ...] = EBS_SUPPRESS_VALUE_PREFIXES


    max_findings_per_type: int = EBS_MAX_FINDINGS_PER_TYPE


# -----------------------------
# Pricing
# -----------------------------

# Conservative USD/GB-month defaults.
# If you later inject a Pricing client into Services, replace this with a cached lookup.
_FALLBACK_USD_PER_GB_MONTH: Dict[str, float] = {
    "gp2": 0.10,
    "gp3": 0.08,
    "io1": 0.125,
    "io2": 0.125,
    "st1": 0.045,
    "sc1": 0.025,
    "standard": 0.05,
}


def _usd_per_gb_month(volume_type: str) -> float:
    return float(_FALLBACK_USD_PER_GB_MONTH.get(str(volume_type or "gp2"), 0.10))


def _resolve_ebs_volume_storage_price_usd_per_gb_month(
    ctx: RunContext,
    *,
    region: str,
    volume_type: str,
) -> tuple[float, str, int]:
    """Resolve EBS volume storage unit price (GB-Mo) best-effort.

    Returns: (usd_per_gb_month, notes, confidence)
    """
    default_price = _usd_per_gb_month(volume_type)
    pricing = common.pricing_service(ctx)
    if pricing is None:
        return (default_price, "PricingService unavailable; using fallback pricing.", 30)

    location = common.pricing_location_for_region(pricing, region)
    if not location:
        return (default_price, "Pricing region mapping missing; using fallback pricing.", 30)

    # Pricing API attributes for EBS can change; we attempt common usageType patterns.
    vt = str(volume_type or "gp2").strip().lower()
    usage_types: List[str] = []
    if vt == "gp2":
        usage_types = ["EBS:VolumeUsage.gp2", "EBS:VolumeUsage"]
    elif vt == "gp3":
        usage_types = ["EBS:VolumeUsage.gp3", "EBS:VolumeUsage"]
    elif vt in ("io1", "io2"):
        # Some catalogs use piops naming for io1.
        usage_types = ["EBS:VolumeUsage.piops", "EBS:VolumeUsage.io2", "EBS:VolumeUsage"]
    elif vt == "st1":
        usage_types = ["EBS:VolumeUsage.st1", "EBS:VolumeUsage"]
    elif vt == "sc1":
        usage_types = ["EBS:VolumeUsage.sc1", "EBS:VolumeUsage"]
    else:
        usage_types = ["EBS:VolumeUsage"]

    attempts = [
        (
            "GB-Mo",
            [
                {"Field": "location", "Value": location},
                {"Field": "productFamily", "Value": "Storage"},
                {"Field": "usagetype", "Value": ut},
            ],
        )
        for ut in usage_types
    ]
    price, quote = common.pricing_on_demand_first_positive(
        pricing,
        service_code="AmazonEC2",
        attempts=attempts,
        call_exceptions=(AttributeError, TypeError, ValueError, ClientError),
    )
    if price is not None and quote is not None:
        source = str(getattr(quote, "source", "pricing_service") or "pricing_service")
        as_of = getattr(quote, "as_of", None)
        unit = str(getattr(quote, "unit", "GB-Mo") or "GB-Mo")
        as_of_txt = as_of.isoformat() if hasattr(as_of, "isoformat") else "unknown"
        return (
            float(price),
            f"PricingService {source} as_of={as_of_txt} unit={unit}",
            60 if source == "cache" else 70,
        )

    return (default_price, "Pricing lookup failed/unknown; using fallback pricing.", 30)


def _resolve_ebs_snapshot_storage_price_usd_per_gb_month(
    ctx: RunContext,
    *,
    region: str,
) -> tuple[float, str, int]:
    """Resolve EBS snapshot storage unit price (GB-Mo) best-effort."""
    default_price = _usd_per_gb_month("gp2")
    pricing = common.pricing_service(ctx)
    if pricing is None:
        return (default_price, "PricingService unavailable; using fallback pricing.", 30)
    location = common.pricing_location_for_region(pricing, region)
    if not location:
        return (default_price, "Pricing region mapping missing; using fallback pricing.", 30)

    price, quote = common.pricing_on_demand_first_positive(
        pricing,
        service_code="AmazonEC2",
        attempts=(
            (
                "GB-Mo",
                [
                    {"Field": "location", "Value": location},
                    {"Field": "productFamily", "Value": "Storage"},
                    {"Field": "usagetype", "Value": "EBS:SnapshotUsage"},
                ],
            ),
        ),
        call_exceptions=(AttributeError, TypeError, ValueError, ClientError),
    )
    if price is not None and quote is not None:
        source = str(getattr(quote, "source", "pricing_service") or "pricing_service")
        as_of = getattr(quote, "as_of", None)
        unit = str(getattr(quote, "unit", "GB-Mo") or "GB-Mo")
        as_of_txt = as_of.isoformat() if hasattr(as_of, "isoformat") else "unknown"
        return (
            float(price),
            f"PricingService {source} as_of={as_of_txt} unit={unit}",
            60 if source == "cache" else 70,
        )

    return (default_price, "Pricing lookup failed/unknown; using fallback pricing.", 30)


# -----------------------------
# Helpers
# -----------------------------


# Guardrail: volumes can be briefly created "available" during automation (ASG churn, IaC retries).
# Skipping very recent volumes reduces false positives.
_RECENT_UNATTACHED_VOLUME_GRACE_HOURS = 24



def _days_ago(ts: datetime, now: datetime) -> int:
    return max(0, int((now - ts).total_seconds() // 86400))


def _tags_to_dict(tags: Any) -> Dict[str, str]:
    if isinstance(tags, dict):
        return {str(k): str(v) for k, v in tags.items()}
    if isinstance(tags, list):
        out: Dict[str, str] = {}
        for t in tags:
            if not isinstance(t, dict):
                continue
            k = t.get("Key")
            v = t.get("Value")
            if k is None:
                continue
            out[str(k)] = "" if v is None else str(v)
        return out
    return {}


def _is_suppressed(tags: Mapping[str, str], cfg: EBSStorageConfig) -> bool:
    keys = {str(k).strip().lower() for k in cfg.suppress_tag_keys}
    values = {str(v).strip().lower() for v in cfg.suppress_tag_values}
    prefixes = tuple(str(p).strip().lower() for p in getattr(cfg, "suppress_value_prefixes", ()))

    # EBS suppression is intentionally conservative: only treat values/prefixes as a suppress
    # signal when the tag key is one of the configured suppression keys.
    return common.is_suppressed(
        tags,
        suppress_keys=keys,
        suppress_values=values,
        value_prefixes=prefixes,
        value_only_if_key_suppressed=True,
        prefix_only_if_key_suppressed=True,
    )


def _is_aws_backup_snapshot(snapshot: Mapping[str, Any], tags: Mapping[str, str]) -> bool:
    """
    Guardrail: AWS Backup-managed snapshots should not be recommended for deletion/copy actions
    by this generic checker, to avoid breaking backup plans / compliance.
    """
    # Most reliable: aws:backup:* tags
    for k in tags.keys():
        if str(k).strip().lower().startswith("aws:backup:"):
            return True

    # Common value hints
    for v in tags.values():
        if isinstance(v, str) and "aws backup" in v.lower():
            return True

    # Description hint (fallback)
    desc = snapshot.get("Description")
    if isinstance(desc, str) and "aws backup" in desc.lower():
        return True

    return False


def _region_from_ec2(ec2: Any) -> str:
    region = getattr(getattr(ec2, "meta", None), "region_name", None)
    return str(region or "")


def _paginate(paginator: Any, **kwargs: Any) -> Iterable[Mapping[str, Any]]:
    for page in paginator.paginate(**kwargs):
        if isinstance(page, Mapping):
            yield page


def _collect_ami_snapshot_ids(ec2: Any) -> Set[str]:
    """
    Collect snapshot IDs referenced by self-owned AMIs (strong false-positive guardrail).
    """
    referenced: Set[str] = set()
    paginator = ec2.get_paginator("describe_images")
    for page in _paginate(paginator, Owners=["self"]):
        for img in page.get("Images", []) or []:
            for bdm in img.get("BlockDeviceMappings", []) or []:
                ebs = bdm.get("Ebs") or {}
                sid = ebs.get("SnapshotId")
                if sid:
                    referenced.add(str(sid))
    return referenced


def _scope(ctx: RunContext, account_id: str, region: str, service: str, resource_type: str, resource_id: str) -> Scope:
    return common.build_scope(
        ctx,
        account=common.AwsAccountContext(account_id=str(account_id), billing_account_id=str(account_id)),
        region=str(region),
        service=str(service),
        resource_type=str(resource_type),
        resource_id=str(resource_id),
        resource_arn="",
    )


def _money_val(val: float) -> float:
    """Money values must be numeric for storage; formatting is presentation-only."""
    return round(float(val), 6)


# -----------------------------
# Checker
# -----------------------------


class EBSStorageChecker(Checker):
    checker_id = "checks.aws.ebs_storage"

    def __init__(self, *, account_id: str, cfg: Optional[EBSStorageConfig] = None) -> None:
        self._account_id = str(account_id)
        self._cfg = cfg or EBSStorageConfig()


    def _access_error(self, ctx: RunContext, *, region: str, operation: str, exc: Exception) -> FindingDraft:
        """Emit an informational finding when required permissions/APIs are missing."""
        check_id = "aws.ec2.ebs.access_error"
        return FindingDraft(
            check_id=check_id,
            check_name="EBS inventory access error",
            category="governance",
            sub_category="iam",
            status="unknown",
            severity=Severity(level="info", score=120),
            title=f"Unable to evaluate EBS resources ({operation})",
            message=str(exc),
            recommendation=(
                "Ensure the scanning role has required EC2 permissions (DescribeVolumes, DescribeSnapshots, "
                "DescribeImages) and re-run the scan."
            ),
            scope=_scope(
                ctx,
                account_id=self._account_id,
                region=region,
                service="AmazonEC2",
                resource_type="permission",
                resource_id=operation,
            ),
            estimate_confidence=100,
            estimate_notes="Inventory access errors are governance signals; no cost estimate.",
            tags={},
            dimensions={"operation": operation},
            issue_key={
                "check_id": check_id,
                "account_id": self._account_id,
                "region": region,
                "operation": operation,
            },
        )

    def run(self, ctx: RunContext) -> Iterable[FindingDraft]:
        if ctx.services is None or getattr(ctx.services, "ec2", None) is None:
            return
        ec2 = ctx.services.ec2
        region = _region_from_ec2(ec2) or "unknown"
        now_ts = common.now_utc()
        cfg = self._cfg

        # Resolve storage prices best-effort (PricingService if available, else fallback).
        # Keep lookups cached to avoid repeated Pricing API calls.
        volume_price_cache: Dict[str, Tuple[float, str, int]] = {}
        snapshot_price_usd_per_gb_month, snapshot_pricing_notes, snapshot_pricing_conf = (
            _resolve_ebs_snapshot_storage_price_usd_per_gb_month(ctx, region=region)
        )

        def _vol_price(vol_type: str) -> Tuple[float, str, int]:
            key = str(vol_type or "gp2").strip().lower()
            cached = volume_price_cache.get(key)
            if cached is not None:
                return cached
            resolved = _resolve_ebs_volume_storage_price_usd_per_gb_month(
                ctx, region=region, volume_type=key
            )
            volume_price_cache[key] = resolved
            return resolved

        # Pre-resolve gp2/gp3 storage prices once for gp2->gp3 candidate logic.
        gp2_price, gp2_notes, gp2_conf = _vol_price("gp2")
        gp3_price, gp3_notes, gp3_conf = _vol_price("gp3")

        # Snapshot guardrail set (AMI-referenced snapshots) is used by the "old snapshot" rule.
        try:
            referenced_by_ami = _collect_ami_snapshot_ids(ec2)
        except (ClientError, BotoCoreError) as exc:
            referenced_by_ami = set()
            yield self._access_error(ctx, region=region, operation="ec2:DescribeImages", exc=exc)

                # =========================================================
        # Volumes (single pass)
        # =========================================================
        try:
            vol_paginator = ec2.get_paginator("describe_volumes")
        except (ClientError, BotoCoreError) as exc:
            yield self._access_error(ctx, region=region, operation="ec2:DescribeVolumes", exc=exc)
            vol_paginator = None

        emitted_unattached = 0
        emitted_gp2_to_gp3 = 0
        emitted_vol_unencrypted = 0

        if vol_paginator is not None:
            for page in _paginate(vol_paginator):
                for vol in sorted(
                    page.get("Volumes", []) or [],
                    key=lambda v: str((v or {}).get("VolumeId") or ""),
                ):
                    vol_id = str(vol.get("VolumeId") or "")
                    if not vol_id:
                        continue

                    tags = _tags_to_dict(vol.get("Tags") or [])
                    if _is_suppressed(tags, cfg):
                        continue

                    vol_type = str(vol.get("VolumeType") or "gp2")
                    size_gb = int(vol.get("Size") or 0)

                    # -------------------------
                    # COST: 1) Unattached volumes older than N days
                    # -------------------------
                    if emitted_unattached < cfg.max_findings_per_type:
                        attachments = vol.get("Attachments") or []
                        state = str(vol.get("State") or "").lower()
                        # "available" + no attachments => unattached
                        if (not attachments) and state in ("available", ""):
                            create_time = vol.get("CreateTime")
                            if isinstance(create_time, datetime):
                                if now_ts - create_time >= timedelta(hours=_RECENT_UNATTACHED_VOLUME_GRACE_HOURS):
                                    age_days = _days_ago(create_time, now_ts)
                                    if age_days >= int(cfg.unattached_min_age_days):
                                        usd_per_gb_month, pricing_notes, pricing_conf = _vol_price(vol_type)
                                        monthly_cost = float(size_gb) * float(usd_per_gb_month)
                                        severity = (
                                            Severity(level="medium", score=700)
                                            if monthly_cost < 50.0
                                            else Severity(level="high", score=850)
                                        )

                                        if pricing_conf <= 30:
                                            pricing_conf_out = 55
                                            pricing_notes_out = (
                                                "Uses conservative fallback pricing (Pricing client not injected)."
                                            )
                                            pricing_hint = "(fallback pricing)"
                                        else:
                                            pricing_conf_out = pricing_conf
                                            pricing_notes_out = pricing_notes
                                            pricing_hint = "(PricingService)"

                                        check_id = "aws.ec2.ebs.unattached_volume"
                                        yield FindingDraft(
                                            check_id=check_id,
                                            check_name="Unattached EBS volume",
                                            category="cost",
                                            sub_category="storage",
                                            status="fail",
                                            severity=severity,
                                            title=f"Unattached EBS volume {vol_id} ({size_gb} GB {vol_type})",
                                            message=(
                                                f"Volume {vol_id} is unattached (state={state}) and appears idle for ~{age_days} days. "
                                                f"Estimated storage cost ≈ ${monthly_cost:.2f}/month {pricing_hint}."
                                            ),
                                            recommendation="Delete if unused, or attach to an instance. If unsure, snapshot then delete.",
                                            scope=_scope(
                                                ctx,
                                                account_id=self._account_id,
                                                region=region,
                                                service="AmazonEC2",
                                                resource_type="ebs_volume",
                                                resource_id=vol_id,
                                            ),
                                            estimated_monthly_cost=_money_val(monthly_cost),
                                            estimated_monthly_savings=_money_val(monthly_cost),
                                            estimate_confidence=int(pricing_conf_out),
                                            estimate_notes=pricing_notes_out,
                                            tags=tags,
                                            dimensions={
                                                "volume_type": vol_type,
                                                "size_gb": str(size_gb),
                                                "age_days": str(age_days),
                                            },
                                            issue_key={
                                                "check_id": check_id,
                                                "account_id": self._account_id,
                                                "region": region,
                                                "resource_type": "ebs_volume",
                                                "resource_id": vol_id,
                                            },
                                        )
                                        emitted_unattached += 1

                    # -------------------------
                    # COST: 2) gp2 -> gp3 migration candidates (storage-only)
                    # -------------------------
                    if emitted_gp2_to_gp3 < cfg.max_findings_per_type:
                        if vol_type == "gp2" and float(gp2_price) > float(gp3_price):
                            monthly_savings = float(size_gb) * (float(gp2_price) - float(gp3_price))
                            if monthly_savings > 0:
                                if min(gp2_conf, gp3_conf) <= 30:
                                    pricing_conf_out = 50
                                    pricing_notes_out = (
                                        "Storage-only estimate using fallback pricing (excludes gp3 IOPS/throughput add-ons)."
                                    )
                                    pricing_hint = "(fallback pricing)"
                                else:
                                    pricing_conf_out = int(min(gp2_conf, gp3_conf))
                                    pricing_notes_out = f"gp2: {gp2_notes}; gp3: {gp3_notes}"
                                    pricing_hint = "(PricingService)"

                                check_id = "aws.ec2.ebs.gp2_to_gp3"
                                yield FindingDraft(
                                    check_id=check_id,
                                    check_name="gp2 to gp3 migration opportunity",
                                    category="cost",
                                    sub_category="storage",
                                    status="fail",
                                    severity=Severity(level="medium", score=650),
                                    title=f"gp2 → gp3 candidate: {vol_id} ({size_gb} GB)",
                                    message=(
                                        f"Volume {vol_id} is gp2. Migrating to gp3 can reduce storage $/GB-month. "
                                        f"Estimated savings ≈ ${monthly_savings:.2f}/month (storage-only) {pricing_hint}."
                                    ),
                                    recommendation="Modify the EBS volume to gp3 and validate required IOPS/throughput settings.",
                                    scope=_scope(
                                        ctx,
                                        account_id=self._account_id,
                                        region=region,
                                        service="AmazonEC2",
                                        resource_type="ebs_volume",
                                        resource_id=vol_id,
                                    ),
                                    estimated_monthly_savings=_money_val(monthly_savings),
                                    estimate_confidence=int(pricing_conf_out),
                                    estimate_notes=str(pricing_notes_out),
                                    tags=tags,
                                    dimensions={
                                        "size_gb": str(size_gb),
                                        "source_volume_type": "gp2",
                                        "target_volume_type": "gp3",
                                    },
                                    issue_key={
                                        "check_id": check_id,
                                        "account_id": self._account_id,
                                        "region": region,
                                        "resource_type": "ebs_volume",
                                        "resource_id": vol_id,
                                        "source": "gp2",
                                        "target": "gp3",
                                    },
                                )
                                emitted_gp2_to_gp3 += 1

                    # -------------------------
                    # GOVERNANCE: 4) Unencrypted volumes
                    # -------------------------
                    if emitted_vol_unencrypted < cfg.max_findings_per_type:
                        if vol.get("Encrypted") is not True:
                            check_id = "aws.ec2.ebs.volume_unencrypted"
                            yield FindingDraft(
                                check_id=check_id,
                                check_name="Unencrypted EBS volume",
                                category="governance",
                                sub_category="encryption",
                                status="fail",
                                severity=Severity(level="high", score=900),
                                title=f"Unencrypted EBS volume {vol_id}",
                                message=f"EBS volume {vol_id} ({size_gb} GB, {vol_type}) is not encrypted at rest.",
                                recommendation=(
                                    "Create a snapshot, copy it with encryption enabled, then create a new encrypted volume "
                                    "and replace the original volume."
                                ),
                                scope=_scope(
                                    ctx,
                                    account_id=self._account_id,
                                    region=region,
                                    service="AmazonEC2",
                                    resource_type="ebs_volume",
                                    resource_id=vol_id,
                                ),
                                estimate_confidence=100,
                                estimate_notes="Encryption is a binary compliance requirement.",
                                tags=tags,
                                dimensions={
                                    "volume_type": vol_type,
                                    "size_gb": str(size_gb),
                                    "encrypted": "false",
                                },
                                issue_key={
                                    "check_id": check_id,
                                    "account_id": self._account_id,
                                    "region": region,
                                    "resource_type": "ebs_volume",
                                    "resource_id": vol_id,
                                },
                            )
                            emitted_vol_unencrypted += 1

                # If all three volume-related rule counters hit their cap, stop paging volumes.
                if (
                    emitted_unattached >= cfg.max_findings_per_type
                    and emitted_gp2_to_gp3 >= cfg.max_findings_per_type
                    and emitted_vol_unencrypted >= cfg.max_findings_per_type
                ):
                    break
        # =========================================================
        # Snapshots (single pass)
        # =========================================================
        try:
            snap_paginator = ec2.get_paginator("describe_snapshots")
        except (ClientError, BotoCoreError) as exc:
            yield self._access_error(ctx, region=region, operation="ec2:DescribeSnapshots", exc=exc)
            snap_paginator = None

        emitted_old_snap = 0
        emitted_snap_unencrypted = 0

        cutoff = now_ts - timedelta(days=int(cfg.snapshot_old_age_days))

        if snap_paginator is not None:
            for page in _paginate(snap_paginator, OwnerIds=["self"]):
                for snap in sorted(
                    page.get("Snapshots", []) or [],
                    key=lambda s: str((s or {}).get("SnapshotId") or ""),
                ):
                    snap_id = str(snap.get("SnapshotId") or "")
                    if not snap_id:
                        continue

                    tags = _tags_to_dict(snap.get("Tags") or [])
                    if _is_suppressed(tags, cfg):
                        continue

                    # Guardrail: AWS Backup-managed snapshots are handled elsewhere; do not recommend delete/copy here.
                    if _is_aws_backup_snapshot(snap, tags):
                        continue

                    size_gb = int(snap.get("VolumeSize") or 0)

                    # -------------------------
                    # COST: 3) Old snapshots not referenced by AMIs
                    # -------------------------
                    if emitted_old_snap < cfg.max_findings_per_type:
                        start_time = snap.get("StartTime")
                        if isinstance(start_time, datetime) and start_time <= cutoff:
                            # Guardrail: referenced by AMIs
                            if referenced_by_ami and snap_id in referenced_by_ami:
                                continue

                            age_days = _days_ago(start_time, now_ts)

                            # Shared snapshot status is not exposed by DescribeSnapshots. We treat it as unknown
                            # (no extra API calls) and rely on tag suppression + AMI reference guardrails.
                            shared_status = "unknown"

                            # More explicit, conservative cost model:
                            # - EBS snapshot billing is incremental (changed blocks).
                            # - Without CUR enrichment or EBS Direct APIs, we cannot know actual billed GB-month.
                            # - We therefore estimate using the *maximum possible* (full volume size) and
                            #   mark it as conservative with reduced confidence.
                            monthly_cost = float(size_gb) * float(snapshot_price_usd_per_gb_month)
                            severity = (
                                Severity(level="low", score=420)
                                if monthly_cost < 20.0
                                else Severity(level="medium", score=620)
                            )

                            check_id = "aws.ec2.ebs.old_snapshot"
                            yield FindingDraft(
                                check_id=check_id,
                                check_name="Old EBS snapshot (not referenced by AMI)",
                                category="cost",
                                sub_category="storage",
                                status="fail",
                                severity=severity,
                                title=f"Old EBS snapshot {snap_id} (~{size_gb} GB, {age_days} days)",
                                message=(
                                    f"Snapshot {snap_id} is older than {cfg.snapshot_old_age_days} days and is not referenced by any AMI "
                                    f"in this account/region. Conservative cost ceiling ≈ ${monthly_cost:.2f}/month "
                                    f"({'fallback pricing' if snapshot_pricing_conf <= 30 else 'PricingService'})."
                                ),
                                recommendation="Review retention needs. If not required, delete the snapshot to reduce storage cost.",
                                scope=_scope(
                                    ctx,
                                    account_id=self._account_id,
                                    region=region,
                                    service="AmazonEC2",
                                    resource_type="ebs_snapshot",
                                    resource_id=snap_id,
                                ),
                                estimated_monthly_cost=_money_val(monthly_cost),
                                estimated_monthly_savings=_money_val(monthly_cost),
                                estimate_confidence=(
                                    25 if snapshot_pricing_conf <= 30 else int(min(45, snapshot_pricing_conf))
                                ),
                                estimate_notes=(
                                    "Snapshot storage is billed incrementally (changed blocks). "
                                    "This estimate uses full VolumeSize as a conservative upper bound. "
                                    + ("Uses fallback pricing." if snapshot_pricing_conf <= 30 else snapshot_pricing_notes)
                                ),
                                tags=tags,
                                dimensions={
                                    "snapshot_id": snap_id,
                                    "volume_size_gb": str(size_gb),
                                    "age_days": str(age_days),
                                    "referenced_by_ami": "false",
                                    "aws_backup_managed": "false",
                                    "shared_status": shared_status,
                                    "cost_model": "conservative_full_volume_size",
                                },
                                issue_key={
                                    "check_id": check_id,
                                    "account_id": self._account_id,
                                    "region": region,
                                    "resource_type": "ebs_snapshot",
                                    "resource_id": snap_id,
                                },
                            )
                            emitted_old_snap += 1

                    # -------------------------
                    # GOVERNANCE: 5) Unencrypted snapshots
                    # -------------------------
                    if emitted_snap_unencrypted < cfg.max_findings_per_type:
                        if snap.get("Encrypted") is not True:
                            check_id = "aws.ec2.ebs.snapshot_unencrypted"
                            yield FindingDraft(
                                check_id=check_id,
                                check_name="Unencrypted EBS snapshot",
                                category="governance",
                                sub_category="encryption",
                                status="fail",
                                severity=Severity(level="medium", score=750),
                                title=f"Unencrypted EBS snapshot {snap_id}",
                                message=f"EBS snapshot {snap_id} (~{size_gb} GB) is not encrypted at rest.",
                                recommendation=(
                                    "Copy the snapshot with encryption enabled, then delete the unencrypted snapshot "
                                    "if it is no longer required."
                                ),
                                scope=_scope(
                                    ctx,
                                    account_id=self._account_id,
                                    region=region,
                                    service="AmazonEC2",
                                    resource_type="ebs_snapshot",
                                    resource_id=snap_id,
                                ),
                                estimate_confidence=100,
                                estimate_notes="Encryption is a binary compliance requirement.",
                                tags=tags,
                                dimensions={
                                    "volume_size_gb": str(size_gb),
                                    "encrypted": "false",
                                    "aws_backup_managed": "false",
                                },
                                issue_key={
                                    "check_id": check_id,
                                    "account_id": self._account_id,
                                    "region": region,
                                    "resource_type": "ebs_snapshot",
                                    "resource_id": snap_id,
                                },
                            )
                            emitted_snap_unencrypted += 1

                if emitted_old_snap >= cfg.max_findings_per_type and emitted_snap_unencrypted >= cfg.max_findings_per_type:
                    break
# -----------------------------
# Registry wiring
# -----------------------------


@register_checker("checks.aws.ebs_storage:EBSStorageChecker")
def _factory(ctx: RunContext, bootstrap: Bootstrap) -> Checker:
    account_id = str(bootstrap.get("aws_account_id") or "")
    if not account_id:
        raise ValueError("bootstrap['aws_account_id'] is required for EBSStorageChecker")
    return EBSStorageChecker(account_id=account_id)
