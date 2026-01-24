"""
checks/aws/ebs_storage.py

EBS storage optimization checker (DI-friendly, FindingDraft-based).

Signals:
1) Unattached EBS volumes older than N days
2) gp2 -> gp3 migration candidates (storage-only savings estimate; fallback pricing)
3) Old EBS snapshots older than N days NOT referenced by any AMI (tag suppress supported)

Notes:
- Uses ctx.services.ec2 (injected by runner).
- Does NOT build final dict records and does NOT call build_ids_and_validate().
  The CheckerRunner does that.

Caveat:
- This checker runs in the single region configured for ctx.services.ec2.
  For multi-region, prefer adding a region-aware client factory to Services.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, Mapping, Optional, Set, Tuple

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

    max_findings_per_type: int = 50_000


# -----------------------------
# Pricing (fallback-only for now)
# -----------------------------

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


# -----------------------------
# Helpers
# -----------------------------


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


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

    for k, v in tags.items():
        kl = str(k).strip().lower()
        vl = str(v).strip().lower()
        if kl in keys and (not vl or vl in values):
            return True
        if kl in keys and vl in values:
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


def _money_str(val: float) -> str:
    return f"{val:.6f}"


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

        # 1) Unattached volumes
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
                if attachments or state not in ("available", ""):
                    continue

                create_time = vol.get("CreateTime")
                if not isinstance(create_time, datetime):
                    continue

                age_days = _days_ago(create_time, now_ts)
                if age_days < int(cfg.unattached_min_age_days):
                    continue

                tags = _tags_to_dict(vol.get("Tags") or [])
                if _is_suppressed(tags, cfg):
                    continue

                vol_type = str(vol.get("VolumeType") or "gp2")
                size_gb = int(vol.get("Size") or 0)

                monthly_cost = float(size_gb) * _usd_per_gb_month(vol_type)
                sev = Severity(level="medium", score=700) if monthly_cost < 50.0 else Severity(level="high", score=850)

                yield FindingDraft(
                    check_id=check_id,
                    check_name="Unattached EBS volume",
                    category="cost",
                    sub_category="storage",
                    status="fail",
                    severity=sev,
                    title=f"Unattached EBS volume {vol_id} ({size_gb} GB {vol_type})",
                    message=(
                        f"Volume {vol_id} is unattached (state={state}) and appears idle for ~{age_days} days. "
                        f"Estimated storage cost ≈ ${monthly_cost:.2f}/month (fallback pricing)."
                    ),
                    recommendation="Delete if unused, or attach to an instance. If unsure, snapshot then delete.",
                    scope=_scope(ctx, self._account_id, region, "AmazonEC2", "ebs_volume", vol_id),
                    estimated_monthly_cost=_money_str(monthly_cost),
                    estimated_monthly_savings=_money_str(monthly_cost),
                    estimate_confidence=55,
                    estimate_notes="Uses conservative fallback pricing (Pricing client not injected).",
                    tags=tags,
                    dimensions={"volume_type": vol_type, "size_gb": str(size_gb), "age_days": str(age_days)},
                    issue_key={"check_id": check_id, "volume_id": vol_id},
                )

                emitted += 1
                if emitted >= cfg.max_findings_per_type:
                    break
            if emitted >= cfg.max_findings_per_type:
                break

        # 2) gp2 -> gp3 candidates (storage-only)
        check_id = "aws.ec2.ebs.gp2_to_gp3"
        gp2_price = _usd_per_gb_month("gp2")
        gp3_price = _usd_per_gb_month("gp3")

        if gp2_price > gp3_price:
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
                    monthly_savings = float(size_gb) * (gp2_price - gp3_price)
                    if monthly_savings <= 0:
                        continue

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
                            f"Estimated savings ≈ ${monthly_savings:.2f}/month (storage-only; fallback pricing)."
                        ),
                        recommendation="Modify the EBS volume to gp3 and validate required IOPS/throughput settings.",
                        scope=_scope(ctx, self._account_id, region, "AmazonEC2", "ebs_volume", vol_id),
                        estimated_monthly_savings=_money_str(monthly_savings),
                        estimate_confidence=50,
                        estimate_notes="Storage-only estimate using fallback pricing (excludes gp3 add-ons).",
                        tags=tags,
                        dimensions={"size_gb": str(size_gb), "source_volume_type": "gp2", "target_volume_type": "gp3"},
                        issue_key={"check_id": check_id, "volume_id": vol_id},
                    )

                    emitted += 1
                    if emitted >= cfg.max_findings_per_type:
                        break
                if emitted >= cfg.max_findings_per_type:
                    break

        # 3) Old snapshots not referenced by AMIs
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
                if referenced_by_ami and snap_id in referenced_by_ami:
                    continue

                size_gb = int(snap.get("VolumeSize") or 0)
                age_days = _days_ago(start_time, now_ts)

                monthly_cost = float(size_gb) * _usd_per_gb_month("gp2")
                sev = Severity(level="low", score=450) if monthly_cost < 20.0 else Severity(level="medium", score=650)

                yield FindingDraft(
                    check_id=check_id,
                    check_name="Old EBS snapshot (not referenced by AMI)",
                    category="cost",
                    sub_category="storage",
                    status="fail",
                    severity=sev,
                    title=f"Old EBS snapshot {snap_id} (~{size_gb} GB, {age_days} days)",
                    message=(
                        f"Snapshot {snap_id} is older than {cfg.snapshot_old_age_days} days and is not referenced by any AMI "
                        f"in this account/region. Approx. cost ≈ ${monthly_cost:.2f}/month (fallback, conservative)."
                    ),
                    recommendation="Review retention needs. If not required, delete the snapshot to reduce storage cost.",
                    scope=_scope(ctx, self._account_id, region, "AmazonEC2", "ebs_snapshot", snap_id),
                    estimated_monthly_cost=_money_str(monthly_cost),
                    estimated_monthly_savings=_money_str(monthly_cost),
                    estimate_confidence=40,
                    estimate_notes="Conservative estimate; snapshot storage may be lower (incremental blocks).",
                    tags=tags,
                    dimensions={
                        "snapshot_id": snap_id,
                        "volume_size_gb": str(size_gb),
                        "age_days": str(age_days),
                        "referenced_by_ami": "false",
                    },
                    issue_key={"check_id": check_id, "snapshot_id": snap_id},
                )

                emitted += 1
                if emitted >= cfg.max_findings_per_type:
                    break
            if emitted >= cfg.max_findings_per_type:
                break


# -----------------------------
# Registry factory
# -----------------------------


@register_checker("checks.aws.ebs_storage:EBSStorageChecker")
def _factory(ctx: RunContext, bootstrap: Bootstrap) -> Checker:
    account_id = str(bootstrap.get("aws_account_id") or "")
    if not account_id:
        raise ValueError("bootstrap['aws_account_id'] is required for EBSStorageChecker")
    return EBSStorageChecker(account_id=account_id)
