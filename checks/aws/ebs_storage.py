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
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional, Set, Tuple

from botocore.exceptions import BotoCoreError

from checks.registry import Bootstrap, register_checker
from contracts.finops_checker_pattern import Checker, FindingDraft, RunContext, Scope, Severity



# -----------------------------
# Config
# -----------------------------


@dataclass(frozen=True)
class EBSStorageConfig:
    unattached_min_age_days: int = 7
    snapshot_old_age_days: int = 45

    suppress_tag_keys: Tuple[str, ...] = (
        "retain",
        "retention",
        "keep",
        "do_not_delete",
        "donotdelete",
        "backup",
        "purpose",
        "lifecycle",
    )
    suppress_tag_values: Tuple[str, ...] = (
        "retain",
        "retained",
        "keep",
        "true",
        "yes",
        "1",
        "permanent",
        "legal-hold",
    )
    # Prefix-based suppression for common retention tags such as:
    #   retention_policy=keep-90-days
    #   purpose=backup-prod
    # This keeps strict equality matching but also treats any value starting with
    # one of these prefixes as a suppress signal when the key is in suppress_tag_keys.
    suppress_value_prefixes: Tuple[str, ...] = (
        "keep",
        "retain",
        "do-not-delete",
        "do_not_delete",
        "donotdelete",
    )


    max_findings_per_type: int = 50_000


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


def _pricing_service(ctx: RunContext) -> Any:
    """Return PricingService if injected in ctx.services, else None."""
    return getattr(getattr(ctx, "services", None), "pricing", None)


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
    pricing = _pricing_service(ctx)
    if pricing is None:
        return (default_price, "PricingService unavailable; using fallback pricing.", 30)

    location = getattr(pricing, "location_for_region", None)
    if callable(location):
        try:
            if not pricing.location_for_region(region):
                return (default_price, "Pricing region mapping missing; using fallback pricing.", 30)
        except Exception:
            return (default_price, "Pricing lookup failed; using fallback pricing.", 30)

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

    try:
        for ut in usage_types:
            quote = pricing.get_on_demand_unit_price(
                service_code="AmazonEC2",
                filters=[
                    {"Field": "location", "Value": pricing.location_for_region(region) or ""},
                    {"Field": "productFamily", "Value": "Storage"},
                    {"Field": "usagetype", "Value": ut},
                ],
                unit="GB-Mo",
            )
            if quote is not None:
                return (
                    float(quote.unit_price_usd),
                    f"PricingService {quote.source} as_of={quote.as_of.isoformat()} unit={quote.unit}",
                    60 if quote.source == "cache" else 70,
                )
    except Exception:
        # Pricing is best-effort; never fail the checker.
        pass

    return (default_price, "Pricing lookup failed/unknown; using fallback pricing.", 30)


def _resolve_ebs_snapshot_storage_price_usd_per_gb_month(
    ctx: RunContext,
    *,
    region: str,
) -> tuple[float, str, int]:
    """Resolve EBS snapshot storage unit price (GB-Mo) best-effort."""
    default_price = _usd_per_gb_month("gp2")
    pricing = _pricing_service(ctx)
    if pricing is None:
        return (default_price, "PricingService unavailable; using fallback pricing.", 30)

    try:
        quote = pricing.get_on_demand_unit_price(
            service_code="AmazonEC2",
            filters=[
                {"Field": "location", "Value": pricing.location_for_region(region) or ""},
                {"Field": "productFamily", "Value": "Storage"},
                {"Field": "usagetype", "Value": "EBS:SnapshotUsage"},
            ],
            unit="GB-Mo",
        )
        if quote is not None:
            return (
                float(quote.unit_price_usd),
                f"PricingService {quote.source} as_of={quote.as_of.isoformat()} unit={quote.unit}",
                60 if quote.source == "cache" else 70,
            )
    except Exception:
        pass

    return (default_price, "Pricing lookup failed/unknown; using fallback pricing.", 30)


# -----------------------------
# Helpers
# -----------------------------


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)

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
    keys = {k.lower() for k in cfg.suppress_tag_keys}
    values = {v.lower() for v in cfg.suppress_tag_values}
    prefixes = tuple(str(p).strip().lower() for p in getattr(cfg, "suppress_value_prefixes", ()))

    for k, v in tags.items():
        kl = str(k).strip().lower()
        vl = str(v).strip().lower()

        if kl not in keys:
            continue

        # Key-only suppression: retain tags are sometimes boolean/empty.
        if not vl:
            return True

        if vl in values:
            return True

        if prefixes and any(vl.startswith(p) for p in prefixes):
            return True

    return False


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
    return Scope(
        cloud=ctx.cloud,
        billing_account_id=str(account_id),
        account_id=str(account_id),
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

    def run(self, ctx: RunContext) -> Iterable[FindingDraft]:
        if ctx.services is None or getattr(ctx.services, "ec2", None) is None:
            return
            yield  # pragma: no cover

        ec2 = ctx.services.ec2
        region = _region_from_ec2(ec2) or "unknown"
        now_ts = _utc_now()
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

        # =========================================================
        # COST: 1) Unattached volumes older than N days
        # =========================================================
        check_id = "aws.ec2.ebs.unattached_volume"
        emitted = 0

        paginator = ec2.get_paginator("describe_volumes")
        for page in _paginate(paginator):
            for vol in page.get("Volumes", []) or []:
                vol_id = str(vol.get("VolumeId") or "")
                if not vol_id:
                    continue

                attachments = vol.get("Attachments") or []
                state = str(vol.get("State") or "").lower()
                # "available" + no attachments => unattached
                if attachments or state not in ("available", ""):
                    continue

                create_time = vol.get("CreateTime")
                if not isinstance(create_time, datetime):
                    continue
                if now_ts - create_time < timedelta(hours=_RECENT_UNATTACHED_VOLUME_GRACE_HOURS):
                    # Common during automation; avoid noisy false positives.
                    continue

                age_days = _days_ago(create_time, now_ts)
                if age_days < int(cfg.unattached_min_age_days):
                    continue

                tags = _tags_to_dict(vol.get("Tags") or [])
                if _is_suppressed(tags, cfg):
                    continue

                vol_type = str(vol.get("VolumeType") or "gp2")
                size_gb = int(vol.get("Size") or 0)

                usd_per_gb_month, pricing_notes, pricing_conf = _vol_price(vol_type)
                monthly_cost = float(size_gb) * float(usd_per_gb_month)
                severity = (
                    Severity(level="medium", score=700)
                    if monthly_cost < 50.0
                    else Severity(level="high", score=850)
                )

                if pricing_conf <= 30:
                    pricing_conf_out = 55
                    pricing_notes_out = "Uses conservative fallback pricing (Pricing client not injected)."
                    pricing_hint = "(fallback pricing)"
                else:
                    pricing_conf_out = pricing_conf
                    pricing_notes_out = pricing_notes
                    pricing_hint = "(PricingService)"

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
                    issue_key={"check_id": check_id, "volume_id": vol_id},
                )

                emitted += 1
                if emitted >= cfg.max_findings_per_type:
                    break
            if emitted >= cfg.max_findings_per_type:
                break

        # =========================================================
        # COST: 2) gp2 -> gp3 migration candidates (storage-only)
        # =========================================================
        check_id = "aws.ec2.ebs.gp2_to_gp3"
        gp2_price, gp2_notes, gp2_conf = _vol_price("gp2")
        gp3_price, gp3_notes, gp3_conf = _vol_price("gp3")

        if float(gp2_price) > float(gp3_price):
            emitted = 0
            paginator = ec2.get_paginator("describe_volumes")
            for page in _paginate(paginator):
                for vol in page.get("Volumes", []) or []:
                    vol_id = str(vol.get("VolumeId") or "")
                    if not vol_id:
                        continue
                    if str(vol.get("VolumeType") or "") != "gp2":
                        continue

                    tags = _tags_to_dict(vol.get("Tags") or [])
                    if _is_suppressed(tags, cfg):
                        continue

                    size_gb = int(vol.get("Size") or 0)
                    monthly_savings = float(size_gb) * (float(gp2_price) - float(gp3_price))
                    if monthly_savings <= 0:
                        continue

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
                        issue_key={"check_id": check_id, "volume_id": vol_id},
                    )

                    emitted += 1
                    if emitted >= cfg.max_findings_per_type:
                        break
                if emitted >= cfg.max_findings_per_type:
                    break

        # =========================================================
        # COST: 3) Old snapshots not referenced by AMIs
        #      + AWS Backup guardrail
        # =========================================================
        check_id = "aws.ec2.ebs.old_snapshot"
        cutoff = now_ts - timedelta(days=int(cfg.snapshot_old_age_days))

        try:
            referenced_by_ami = _collect_ami_snapshot_ids(ec2)
        except BotoCoreError:
            referenced_by_ami = set()

        emitted = 0
        paginator = ec2.get_paginator("describe_snapshots")
        for page in _paginate(paginator, OwnerIds=["self"]):
            for snap in page.get("Snapshots", []) or []:
                snap_id = str(snap.get("SnapshotId") or "")
                if not snap_id:
                    continue

                start_time = snap.get("StartTime")
                if not isinstance(start_time, datetime):
                    continue
                if start_time > cutoff:
                    continue

                tags = _tags_to_dict(snap.get("Tags") or [])
                if _is_suppressed(tags, cfg):
                    continue

                # Guardrail: AWS Backup-managed snapshots are not "cleanup candidates" here.
                if _is_aws_backup_snapshot(snap, tags):
                    continue


                # Guardrail: shared snapshots may be intentionally retained.
                # Some integrations include CreateVolumePermissions inline; if present and non-empty, skip.
                perms = snap.get("CreateVolumePermissions")
                if perms:
                    if isinstance(perms, list) and len(perms) > 0:
                        continue
                    if not isinstance(perms, list):
                        # Any truthy non-list value indicates potential sharing; be conservative.
                        continue

                # Guardrail: referenced by AMIs
                if referenced_by_ami and snap_id in referenced_by_ami:
                    continue

                size_gb = int(snap.get("VolumeSize") or 0)
                age_days = _days_ago(start_time, now_ts)

                # Conservative: approximate snapshot as full GB-month (may overestimate; snapshot storage is incremental).
                monthly_cost = float(size_gb) * float(snapshot_price_usd_per_gb_month)
                severity = (
                    Severity(level="low", score=450)
                    if monthly_cost < 20.0
                    else Severity(level="medium", score=650)
                )

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
                        f"in this account/region. Approx. cost ≈ ${monthly_cost:.2f}/month "
                        f"({'fallback pricing' if snapshot_pricing_conf <= 30 else 'PricingService'}, conservative)."
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
                    estimate_confidence=40 if snapshot_pricing_conf <= 30 else int(snapshot_pricing_conf),
                    estimate_notes=(
                        "Conservative estimate; snapshot storage may be lower (incremental blocks). "
                        + ("Uses fallback pricing." if snapshot_pricing_conf <= 30 else snapshot_pricing_notes)
                    ),
                    tags=tags,
                    dimensions={
                        "snapshot_id": snap_id,
                        "volume_size_gb": str(size_gb),
                        "age_days": str(age_days),
                        "referenced_by_ami": "false",
                        "aws_backup_managed": "false",
                    },
                    issue_key={"check_id": check_id, "snapshot_id": snap_id},
                )

                emitted += 1
                if emitted >= cfg.max_findings_per_type:
                    break
            if emitted >= cfg.max_findings_per_type:
                break

        # =========================================================
        # GOVERNANCE: 4) Unencrypted volumes
        # =========================================================
        check_id = "aws.ec2.ebs.volume_unencrypted"
        emitted = 0

        paginator = ec2.get_paginator("describe_volumes")
        for page in _paginate(paginator):
            for vol in page.get("Volumes", []) or []:
                vol_id = str(vol.get("VolumeId") or "")
                if not vol_id:
                    continue

                if vol.get("Encrypted") is True:
                    continue

                tags = _tags_to_dict(vol.get("Tags") or [])
                if _is_suppressed(tags, cfg):
                    continue

                size_gb = int(vol.get("Size") or 0)
                vol_type = str(vol.get("VolumeType") or "unknown")

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
                    issue_key={"check_id": check_id, "volume_id": vol_id},
                )

                emitted += 1
                if emitted >= cfg.max_findings_per_type:
                    break
            if emitted >= cfg.max_findings_per_type:
                break

        # =========================================================
        # GOVERNANCE: 5) Unencrypted snapshots
        #            + AWS Backup guardrail
        # =========================================================
        check_id = "aws.ec2.ebs.snapshot_unencrypted"
        emitted = 0

        paginator = ec2.get_paginator("describe_snapshots")
        for page in _paginate(paginator, OwnerIds=["self"]):
            for snap in page.get("Snapshots", []) or []:
                snap_id = str(snap.get("SnapshotId") or "")
                if not snap_id:
                    continue

                if snap.get("Encrypted") is True:
                    continue

                tags = _tags_to_dict(snap.get("Tags") or [])
                if _is_suppressed(tags, cfg):
                    continue

                # Guardrail: do not flag AWS Backup-managed snapshots here (usually governed elsewhere).
                if _is_aws_backup_snapshot(snap, tags):
                    continue

                size_gb = int(snap.get("VolumeSize") or 0)

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
                    issue_key={"check_id": check_id, "snapshot_id": snap_id},
                )

                emitted += 1
                if emitted >= cfg.max_findings_per_type:
                    break
            if emitted >= cfg.max_findings_per_type:
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
