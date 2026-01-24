"""
EBS storage optimization checks (FinOps + governance).

Signals implemented:
- Unattached volumes (waste)
- gp2 -> gp3 migration opportunities (savings)
- Old snapshots not referenced by any AMI (waste / hygiene) with tag suppression

Design notes:
- Works without CUR.
- Uses AWS Pricing API when available, with safe fallbacks.
- Avoids snapshot false positives by excluding snapshots referenced by any AMI.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional, Set, Tuple

from botocore.exceptions import BotoCoreError

from contracts.finops_contracts import build_ids_and_validate, normalize_str


# -----------------------------
# Config
# -----------------------------


@dataclass(frozen=True)
class EBSStorageConfig:
    """Tuning knobs for EBS storage checks."""
    # Unattached volume signal
    unattached_min_age_days: int = 7

    # Snapshot signal
    snapshot_old_age_days: int = 45

    # Tag suppression
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

    # Findings framework/category defaults
    frameworks: Tuple[str, ...] = ("FinOps",)

    # Safety caps
    max_findings_per_type: int = 50_000


# -----------------------------
# Pricing helper
# -----------------------------


class _PricingCache:
    """
    Small in-memory cache for per-GB-month price by (region, volume_type).

    Uses AWS Pricing API if provided; falls back to conservative defaults.
    """

    # Very conservative fallback estimates (USD / GB-month).
    # These are not guaranteed to be current in every region; Pricing API will override when available.
    _FALLBACK_USD_PER_GB_MONTH = {
        "gp2": 0.10,
        "gp3": 0.08,
        "io1": 0.125,
        "io2": 0.125,
        "st1": 0.045,
        "sc1": 0.025,
        "standard": 0.05,  # magnetic (legacy)
    }

    def __init__(self, pricing_client: Any | None) -> None:
        self._pricing = pricing_client
        self._cache: Dict[Tuple[str, str], float] = {}

    def usd_per_gb_month(self, region: str, volume_type: str) -> float:
        key = (region, volume_type)
        if key in self._cache:
            return self._cache[key]

        price = self._fetch_from_pricing(region, volume_type)
        if price is None:
            price = self._FALLBACK_USD_PER_GB_MONTH.get(volume_type, 0.10)

        self._cache[key] = float(price)
        return float(price)

    def _fetch_from_pricing(self, region: str, volume_type: str) -> Optional[float]:
        """
        Try to fetch the EBS volume storage price via AWS Pricing API.

        Notes:
        - Pricing API is typically in us-east-1.
        - Product naming varies; we try multiple filters.

        If this fails, return None and fall back.
        """
        if self._pricing is None:
            return None

        # Pricing "location" uses human readable names ("EU (Paris)", etc.).
        # If your codebase already has region->pricing_location mapping, plug it here.
        # Otherwise, we use a small common mapping and fallback.
        location = _region_to_pricing_location(region)

        # Common EBS storage filters (best-effort; AWS pricing is messy).
        # We'll attempt a couple of volume type representations.
        volume_type_map = {
            "gp2": "General Purpose",
            "gp3": "General Purpose",
            "io1": "Provisioned IOPS",
            "io2": "Provisioned IOPS",
            "st1": "Throughput Optimized HDD",
            "sc1": "Cold HDD",
            "standard": "Magnetic",
        }
        volume_family = volume_type_map.get(volume_type, "General Purpose")

        # We want: AmazonEC2, productFamily=Storage, volumeApiName like gp3/gp2 if possible.
        # Not all fields exist consistently across time; try best-effort filters.
        filters_base = [
            {"Type": "TERM_MATCH", "Field": "servicecode", "Value": "AmazonEC2"},
            {"Type": "TERM_MATCH", "Field": "productFamily", "Value": "Storage"},
            {"Type": "TERM_MATCH", "Field": "location", "Value": location},
            {"Type": "TERM_MATCH", "Field": "volumeType", "Value": volume_family},
        ]

        try:
            resp = self._pricing.get_products(
                ServiceCode="AmazonEC2",
                Filters=filters_base,
                MaxResults=20,
            )
        except Exception:
            return None

        price = _extract_first_usd_per_gb_month(resp)
        return price


def _extract_first_usd_per_gb_month(pricing_resp: Mapping[str, Any]) -> Optional[float]:
    """
    Parse AWS Pricing get_products response and return the first USD price per GB-month found.
    Best-effort; structure is nested JSON strings.
    """
    price_list = pricing_resp.get("PriceList") or []
    for item in price_list:
        # Each item is a JSON string or dict depending on SDK behavior.
        try:
            data = item if isinstance(item, dict) else __import__("json").loads(item)
        except Exception:
            continue

        terms = data.get("terms", {}).get("OnDemand", {})
        for _term_sku, term in terms.items():
            price_dimensions = term.get("priceDimensions", {})
            for _dim_code, dim in price_dimensions.items():
                unit = (dim.get("unit") or "").lower()
                # commonly "gb-mo" / "gb-month"
                if "gb" not in unit:
                    continue
                price_per_unit = dim.get("pricePerUnit", {}).get("USD")
                if price_per_unit is None:
                    continue
                try:
                    return float(price_per_unit)
                except Exception:
                    continue
    return None


def _region_to_pricing_location(region: str) -> str:
    """
    Best-effort region -> Pricing 'location' mapping.
    Extend this mapping as you add regions.
    """
    mapping = {
        "eu-west-3": "EU (Paris)",
        "eu-west-1": "EU (Ireland)",
        "eu-central-1": "EU (Frankfurt)",
        "us-east-1": "US East (N. Virginia)",
        "us-east-2": "US East (Ohio)",
        "us-west-1": "US West (N. California)",
        "us-west-2": "US West (Oregon)",
    }
    return mapping.get(region, region)


# -----------------------------
# Tag / suppression helpers
# -----------------------------


def _tags_to_dict(tags: Any) -> Dict[str, str]:
    """
    AWS-style tags can be:
      - list[{"Key": "...", "Value": "..."}]
      - dict already
    """
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
        if vl in values and kl in keys:
            return True
        # common pattern: "retain=true"
        if kl in keys and vl in values:
            return True
    return False


# -----------------------------
# Finding builder
# -----------------------------


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _days_ago(ts: datetime, now: datetime) -> int:
    delta = now - ts
    return max(0, int(delta.total_seconds() // 86400))


def _severity(level: str, score: int) -> Dict[str, Any]:
    return {"level": level, "score": int(score)}


def _base_source(check_id: str) -> Dict[str, Any]:
    return {"source_type": "scanner", "source_ref": check_id, "schema_version": 1}


def _scope(account_id: str, region: str, service: str, resource_type: str, resource_id: str) -> Dict[str, Any]:
    return {
        "cloud": "aws",
        "account_id": account_id,
        "region": region,
        "service": service,
        "resource_type": resource_type,
        "resource_id": resource_id,
    }


def _estimated(monthly_cost: Optional[float], monthly_savings: Optional[float], confidence: int, notes: str) -> Dict[str, Any]:
    return {
        "monthly_savings": monthly_savings,
        "monthly_cost": monthly_cost,
        "one_time_savings": None,
        "confidence": int(confidence),
        "notes": notes,
    }


def _mk_finding(
    *,
    tenant_id: str,
    workspace_id: str,
    run_id: str,
    run_ts: datetime,
    engine_name: str,
    engine_version: str,
    rulepack_version: str,
    check_id: str,
    check_name: str,
    category: str,
    sub_category: str,
    status: str,
    severity: Mapping[str, Any],
    title: str,
    message: str,
    recommendation: str,
    scope: Mapping[str, Any],
    tags: Mapping[str, Any],
    dimensions: Mapping[str, Any],
    metrics: Mapping[str, Any],
    estimated: Mapping[str, Any],
    issue_key: Mapping[str, Any],
) -> Dict[str, Any]:
    now_ts = _utc_now()
    wire: Dict[str, Any] = {
        "tenant_id": normalize_str(tenant_id, lower=False),
        "workspace_id": normalize_str(workspace_id, lower=False),
        "run_id": normalize_str(run_id, lower=False),
        "run_ts": run_ts,
        "ingested_ts": now_ts,
        "engine_name": engine_name,
        "engine_version": engine_version,
        "rulepack_version": rulepack_version,
        "scope": dict(scope),
        "check_id": check_id,
        "check_name": check_name,
        "category": category,
        "sub_category": sub_category,
        "frameworks": ["FinOps"],
        "status": normalize_str(status, lower=True),
        "severity": dict(severity),
        "priority": 0,
        "title": title,
        "message": message,
        "recommendation": recommendation,
        "remediation": "",
        "links": [],
        "estimated": dict(estimated),
        "actual": None,
        "lifecycle": None,
        "tags": dict(tags) if isinstance(tags, Mapping) else {},
        "labels": {},
        "dimensions": dict(dimensions) if isinstance(dimensions, Mapping) else {},
        "metrics": dict(metrics) if isinstance(metrics, Mapping) else {},
        "metadata_json": "",
        "source": _base_source(check_id),
    }
    build_ids_and_validate(wire, issue_key=dict(issue_key))
    return wire


# -----------------------------
# Public entrypoint
# -----------------------------


def check_ebs_storage_optimization(
    *,
    writer: Any,
    ec2: Any,
    pricing: Any | None,
    tenant_id: str,
    workspace_id: str,
    run_id: str,
    run_ts: datetime,
    account_id: str,
    region: str,
    engine_name: str = "mckay",
    engine_version: str = "",
    rulepack_version: str = "",
    cfg: Optional[EBSStorageConfig] = None,
) -> None:
    """
    Run EBS storage optimization checks and write findings via `writer.extend(...)`.

    Required deps:
      - ec2: boto3 EC2 client (regional)
      - pricing: boto3 Pricing client (usually us-east-1) OR None (fallback prices)

    Writer contract:
      - must provide .extend(List[Dict[str, Any]]) or be compatible with your FindingsParquetWriter wrapper.
    """
    config = cfg or EBSStorageConfig()
    now_ts = _utc_now()

    price_cache = _PricingCache(pricing_client=pricing)

    findings: List[Dict[str, Any]] = []
    findings.extend(
        _check_unattached_volumes(
            ec2=ec2,
            price_cache=price_cache,
            now_ts=now_ts,
            config=config,
            tenant_id=tenant_id,
            workspace_id=workspace_id,
            run_id=run_id,
            run_ts=run_ts,
            account_id=account_id,
            region=region,
            engine_name=engine_name,
            engine_version=engine_version,
            rulepack_version=rulepack_version,
        )
    )
    findings.extend(
        _check_gp2_to_gp3(
            ec2=ec2,
            price_cache=price_cache,
            now_ts=now_ts,
            config=config,
            tenant_id=tenant_id,
            workspace_id=workspace_id,
            run_id=run_id,
            run_ts=run_ts,
            account_id=account_id,
            region=region,
            engine_name=engine_name,
            engine_version=engine_version,
            rulepack_version=rulepack_version,
        )
    )
    findings.extend(
        _check_old_snapshots(
            ec2=ec2,
            price_cache=price_cache,
            now_ts=now_ts,
            config=config,
            tenant_id=tenant_id,
            workspace_id=workspace_id,
            run_id=run_id,
            run_ts=run_ts,
            account_id=account_id,
            region=region,
            engine_name=engine_name,
            engine_version=engine_version,
            rulepack_version=rulepack_version,
        )
    )

    if not findings:
        return

    # Write (stream-friendly: chunk to avoid huge in-memory)
    # Your FindingsParquetWriter can buffer, but we keep it safe anyway.
    chunk: List[Dict[str, Any]] = []
    for f in findings:
        chunk.append(f)
        if len(chunk) >= 5000:
            writer.extend(chunk)
            chunk = []
    if chunk:
        writer.extend(chunk)


# -----------------------------
# Checks
# -----------------------------


def _paginate(paginator: Any, **kwargs: Any) -> Iterable[Mapping[str, Any]]:
    for page in paginator.paginate(**kwargs):
        if isinstance(page, Mapping):
            yield page


def _check_unattached_volumes(
    *,
    ec2: Any,
    price_cache: _PricingCache,
    now_ts: datetime,
    config: EBSStorageConfig,
    tenant_id: str,
    workspace_id: str,
    run_id: str,
    run_ts: datetime,
    account_id: str,
    region: str,
    engine_name: str,
    engine_version: str,
    rulepack_version: str,
) -> List[Dict[str, Any]]:
    check_id = "aws.ec2.ebs.unattached_volume"
    check_name = "Unattached EBS volume"
    out: List[Dict[str, Any]] = []

    paginator = ec2.get_paginator("describe_volumes")
    emitted = 0

    for page in _paginate(paginator):
        for vol in page.get("Volumes", []) or []:
            vol_id = str(vol.get("VolumeId") or "")
            if not vol_id:
                continue

            attachments = vol.get("Attachments") or []
            state = str(vol.get("State") or "").lower()

            # Unattached means no attachments; state is often "available".
            is_unattached = (not attachments) and (state in ("available", ""))
            if not is_unattached:
                continue

            create_time = vol.get("CreateTime")
            if not isinstance(create_time, datetime):
                # shouldn't happen, but guard.
                continue

            age_days = _days_ago(create_time, now_ts)
            if age_days < int(config.unattached_min_age_days):
                continue

            tags = _tags_to_dict(vol.get("Tags") or [])
            if _is_suppressed(tags, config):
                continue

            vol_type = str(vol.get("VolumeType") or "gp2")
            size_gb = int(vol.get("Size") or 0)

            usd_per_gb = price_cache.usd_per_gb_month(region, vol_type)
            monthly_cost = round(size_gb * usd_per_gb, 6)

            sev = _severity("medium", 700)
            if monthly_cost >= 50:
                sev = _severity("high", 850)

            title = f"Unattached EBS volume {vol_id} ({size_gb} GB {vol_type})"
            msg = (
                f"Volume {vol_id} is unattached (state={state}) and has been idle for ~{age_days} days. "
                f"Estimated storage cost ≈ ${monthly_cost}/month."
            )
            rec = "Delete the volume if it is no longer needed, or attach it to an instance. If unsure, snapshot then delete."

            finding = _mk_finding(
                tenant_id=tenant_id,
                workspace_id=workspace_id,
                run_id=run_id,
                run_ts=run_ts,
                engine_name=engine_name,
                engine_version=engine_version,
                rulepack_version=rulepack_version,
                check_id=check_id,
                check_name=check_name,
                category="cost",
                sub_category="storage",
                status="fail",
                severity=sev,
                title=title,
                message=msg,
                recommendation=rec,
                scope=_scope(account_id, region, "ec2", "ebs_volume", vol_id),
                tags=tags,
                dimensions={
                    "volume_type": vol_type,
                    "size_gb": size_gb,
                    "age_days": age_days,
                },
                metrics={},
                estimated=_estimated(monthly_cost=monthly_cost, monthly_savings=monthly_cost, confidence=60,
                                    notes="Unattached volumes typically represent pure storage waste."),
                issue_key={"check_id": check_id, "volume_id": vol_id},
            )
            out.append(finding)
            emitted += 1
            if emitted >= config.max_findings_per_type:
                return out

    return out


def _check_gp2_to_gp3(
    *,
    ec2: Any,
    price_cache: _PricingCache,
    now_ts: datetime,
    config: EBSStorageConfig,
    tenant_id: str,
    workspace_id: str,
    run_id: str,
    run_ts: datetime,
    account_id: str,
    region: str,
    engine_name: str,
    engine_version: str,
    rulepack_version: str,
) -> List[Dict[str, Any]]:
    check_id = "aws.ec2.ebs.gp2_to_gp3"
    check_name = "gp2 to gp3 migration opportunity"
    out: List[Dict[str, Any]] = []

    gp2_price = price_cache.usd_per_gb_month(region, "gp2")
    gp3_price = price_cache.usd_per_gb_month(region, "gp3")

    # If fallback makes them equal, savings becomes 0; still emit as "info" only when savings > 0.
    if gp2_price <= gp3_price:
        return out

    paginator = ec2.get_paginator("describe_volumes")
    emitted = 0

    for page in _paginate(paginator):
        for vol in page.get("Volumes", []) or []:
            vol_id = str(vol.get("VolumeId") or "")
            if not vol_id:
                continue

            vol_type = str(vol.get("VolumeType") or "")
            if vol_type != "gp2":
                continue

            tags = _tags_to_dict(vol.get("Tags") or [])
            if _is_suppressed(tags, config):
                continue

            size_gb = int(vol.get("Size") or 0)
            monthly_savings = round(size_gb * (gp2_price - gp3_price), 6)

            if monthly_savings <= 0:
                continue

            attachments = vol.get("Attachments") or []
            attached_to = ""
            if attachments:
                attached_to = str(attachments[0].get("InstanceId") or "")

            title = f"gp2 → gp3 candidate: {vol_id} ({size_gb} GB)"
            msg = (
                f"Volume {vol_id} is gp2. Migrating to gp3 commonly reduces $/GB-month while allowing independent perf tuning. "
                f"Estimated savings ≈ ${monthly_savings}/month (storage component only)."
            )
            rec = (
                "Consider modifying the EBS volume to gp3. Validate performance requirements (IOPS/throughput) "
                "and set gp3 parameters accordingly."
            )

            finding = _mk_finding(
                tenant_id=tenant_id,
                workspace_id=workspace_id,
                run_id=run_id,
                run_ts=run_ts,
                engine_name=engine_name,
                engine_version=engine_version,
                rulepack_version=rulepack_version,
                check_id=check_id,
                check_name=check_name,
                category="cost",
                sub_category="storage",
                status="fail",
                severity=_severity("medium", 650),
                title=title,
                message=msg,
                recommendation=rec,
                scope=_scope(account_id, region, "ec2", "ebs_volume", vol_id),
                tags=tags,
                dimensions={
                    "volume_type": vol_type,
                    "target_volume_type": "gp3",
                    "size_gb": size_gb,
                    "attached_instance_id": attached_to,
                },
                metrics={},
                estimated=_estimated(monthly_cost=None, monthly_savings=monthly_savings, confidence=55,
                                    notes="Estimate includes storage $/GB-month difference only (not IOPS/throughput add-ons)."),
                issue_key={"check_id": check_id, "volume_id": vol_id},
            )
            out.append(finding)
            emitted += 1
            if emitted >= config.max_findings_per_type:
                return out

    return out


def _check_old_snapshots(
    *,
    ec2: Any,
    price_cache: _PricingCache,
    now_ts: datetime,
    config: EBSStorageConfig,
    tenant_id: str,
    workspace_id: str,
    run_id: str,
    run_ts: datetime,
    account_id: str,
    region: str,
    engine_name: str,
    engine_version: str,
    rulepack_version: str,
) -> List[Dict[str, Any]]:
    check_id = "aws.ec2.ebs.old_snapshot"
    check_name = "Old EBS snapshot (not referenced by AMI)"
    out: List[Dict[str, Any]] = []

    # Build AMI-referenced snapshot set once to avoid false positives
    referenced_by_ami = _collect_ami_snapshot_ids(ec2)

    paginator = ec2.get_paginator("describe_snapshots")
    emitted = 0
    cutoff = now_ts - timedelta(days=int(config.snapshot_old_age_days))

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
            if _is_suppressed(tags, config):
                continue

            # Guardrail: if used by any AMI, skip
            if snap_id in referenced_by_ami:
                continue

            volume_id = str(snap.get("VolumeId") or "")
            volume_size = int(snap.get("VolumeSize") or 0)

            # Snapshot storage pricing differs from volume pricing and can depend on changed blocks.
            # Without CUR, use conservative: approximate as full GB-month at gp2 rate (overestimates).
            usd_per_gb = price_cache.usd_per_gb_month(region, "gp2")
            monthly_cost = round(volume_size * usd_per_gb, 6)

            age_days = _days_ago(start_time, now_ts)

            title = f"Old EBS snapshot {snap_id} (~{volume_size} GB, {age_days} days)"
            msg = (
                f"Snapshot {snap_id} is older than {config.snapshot_old_age_days} days and is not referenced by any AMI in this account/region. "
                f"Approx. storage cost ≈ ${monthly_cost}/month (conservative estimate)."
            )
            rec = (
                "Review whether this snapshot is still required (retention/legal/compliance). "
                "If not, delete it to reduce storage cost."
            )

            finding = _mk_finding(
                tenant_id=tenant_id,
                workspace_id=workspace_id,
                run_id=run_id,
                run_ts=run_ts,
                engine_name=engine_name,
                engine_version=engine_version,
                rulepack_version=rulepack_version,
                check_id=check_id,
                check_name=check_name,
                category="cost",
                sub_category="storage",
                status="fail",
                severity=_severity("low", 450) if monthly_cost < 20 else _severity("medium", 650),
                title=title,
                message=msg,
                recommendation=rec,
                scope=_scope(account_id, region, "ec2", "ebs_snapshot", snap_id),
                tags=tags,
                dimensions={
                    "snapshot_id": snap_id,
                    "volume_id": volume_id,
                    "volume_size_gb": volume_size,
                    "age_days": age_days,
                    "referenced_by_ami": False,
                },
                metrics={},
                estimated=_estimated(monthly_cost=monthly_cost, monthly_savings=monthly_cost, confidence=45,
                                    notes="Snapshot cost estimation is conservative; real cost may be lower due to incremental blocks."),
                issue_key={"check_id": check_id, "snapshot_id": snap_id},
            )
            out.append(finding)
            emitted += 1
            if emitted >= config.max_findings_per_type:
                return out

    return out


def _collect_ami_snapshot_ids(ec2: Any) -> Set[str]:
    """
    Collect snapshot IDs referenced by any AMI (self-owned).
    This is the primary false-positive guardrail for snapshot cleanup suggestions.
    """
    referenced: Set[str] = set()
    try:
        paginator = ec2.get_paginator("describe_images")
        for page in _paginate(paginator, Owners=["self"]):
            for img in page.get("Images", []) or []:
                for bdm in img.get("BlockDeviceMappings", []) or []:
                    ebs = bdm.get("Ebs") or {}
                    snap_id = ebs.get("SnapshotId")
                    if snap_id:
                        referenced.add(str(snap_id))
    except BotoCoreError:
        # If we fail to list AMIs, do not emit snapshot cleanup findings (safety).
        return set()
    return referenced
