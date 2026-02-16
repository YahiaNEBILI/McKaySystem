"""
checks/aws/fsx_filesystems.py

FSx optimization + governance checker.

Signals (cost / optimization):
1) Possibly unused FSx file systems (best-effort)
   - No observed CloudWatch activity over N days (bytes / utilization)
2) Underutilized throughput capacity (best-effort)
   - Compare configured throughput vs observed p95 utilization (when available)
   - Fallback to p95 read+write throughput (MiB/s) when utilization metric absent
3) Over-provisioned storage (heuristic)
   - Large provisioned storage + low activity

Signals (expensive deployment choices):
4) Multi-AZ in non-prod (Windows, ONTAP) when tags suggest dev/test

Signals (governance):
5) Windows backups disabled / retention low / copy tags disabled
6) Windows maintenance window missing / likely business hours (best-effort)
7) Missing required tags (basic hygiene)

Signals (Windows cost/perf):
8) SSD when HDD likely sufficient (best-effort)
   - SSD + low IO/throughput utilization over lookback => suggest HDD
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from botocore.exceptions import ClientError

from checks.aws._common import (
    AwsAccountContext,
    PricingResolver,
    build_scope,
    get_logger,
    money,
    normalize_tags,
    now_utc,
    percentile,
    safe_region_from_client,
)
from checks.aws.defaults import (
    FSX_LARGE_STORAGE_GIB_THRESHOLD,
    FSX_MAX_FINDINGS_PER_TYPE,
    FSX_REQUIRED_TAG_KEYS,
    FSX_THROUGHPUT_LOOKBACK_DAYS,
    FSX_UNDERUTILIZED_P95_UTIL_THRESHOLD_PCT,
    FSX_UNUSED_LOOKBACK_DAYS,
    FSX_WINDOWS_BACKUP_LOW_RETENTION_DAYS,
)
from checks.registry import Bootstrap, register_checker
from contracts.finops_checker_pattern import Checker, FindingDraft, RunContext, Severity

# Logger for this module
_LOGGER = get_logger("fsx_filesystems")


# -----------------------------
# Config
# -----------------------------


@dataclass(frozen=True)
class FSxFileSystemsConfig:
    """Configuration knobs for FSxFileSystemsChecker."""

    # "Unused" heuristics
    unused_lookback_days: int = FSX_UNUSED_LOOKBACK_DAYS

    # Throughput utilization lookback
    throughput_lookback_days: int = FSX_THROUGHPUT_LOOKBACK_DAYS
    underutilized_p95_util_threshold_pct: float = FSX_UNDERUTILIZED_P95_UTIL_THRESHOLD_PCT

    # Storage heuristic (GiB)
    large_storage_gib_threshold: int = FSX_LARGE_STORAGE_GIB_THRESHOLD

    # Windows backup governance
    windows_backup_low_retention_days: int = FSX_WINDOWS_BACKUP_LOW_RETENTION_DAYS

    # Governance tags (tags are lowercased by normalize_tags)
    required_tag_keys: tuple[str, ...] = FSX_REQUIRED_TAG_KEYS

    # Safety valve
    max_findings_per_type: int = FSX_MAX_FINDINGS_PER_TYPE


# -----------------------------
# Helpers (type-safe)
# -----------------------------


# -----------------------------
# Pricing (best-effort, cached via PricingService)
# -----------------------------

# Conservative fallback USD prices.
# These are only used when PricingService is not available or the catalog query fails.
# Tune later with real resolved quotes once you observe stable filter patterns.
_FALLBACK_FSX_STORAGE_USD_PER_GB_MONTH: dict[str, dict[str, float]] = {
    # FSx for Windows
    "WINDOWS": {"SSD": 0.13, "HDD": 0.04},
    # FSx for ONTAP (storage is generally SSD-backed; keep one fallback)
    "ONTAP": {"SSD": 0.13},
    # FSx for Lustre (varies by deployment/throughput tier; keep one safe fallback)
    "LUSTRE": {"SSD": 0.14, "HDD": 0.04},
}

# Throughput capacity often priced per MB/s-month (catalog unit commonly "MBps-Mo").
# Fallbacks are deliberately conservative; treat as "ballpark".
_FALLBACK_FSX_THROUGHPUT_USD_PER_MBPS_MONTH: dict[str, float] = {
    "WINDOWS": 2.0,
    "ONTAP": 0.3,
    "LUSTRE": 0.0,  # often bundled/varies; keep 0 by default unless you confirm a stable quote
}

_NONPROD_HINTS = ("dev", "test", "staging", "sbx", "nprod", "qa", "nonprod")


def _fallback_storage_usd_per_gb_month(*, fs_type: str, storage_type: str) -> float:
    t = str(fs_type or "").upper()
    st = str(storage_type or "").upper()
    by_type = _FALLBACK_FSX_STORAGE_USD_PER_GB_MONTH.get(t, {})
    if st in by_type:
        return float(by_type[st])
    # default per type, then global fallback
    if by_type:
        return float(next(iter(by_type.values())))
    return 0.12


def _fallback_throughput_usd_per_mbps_month(*, fs_type: str) -> float:
    return float(_FALLBACK_FSX_THROUGHPUT_USD_PER_MBPS_MONTH.get(str(fs_type or "").upper(), 0.0))


def _resolve_fsx_storage_price_usd_per_gb_month(
    ctx: RunContext,
    *,
    region: str,
    fs_type: str,
    storage_type: str,
) -> tuple[float, str, int]:
    """
    Best-effort FSx storage unit price (USD per GB-Mo).

    Returns: (usd_per_gb_month, notes, confidence_int)
    """
    default_price = _fallback_storage_usd_per_gb_month(fs_type=fs_type, storage_type=storage_type)
    return PricingResolver(ctx).resolve_fsx_storage_price(
        region=region,
        fs_type=fs_type,
        storage_type=storage_type,
        default_price=default_price,
        call_exceptions=(AttributeError, TypeError, ValueError, ClientError),
    )


def _resolve_fsx_throughput_price_usd_per_mbps_month(
    ctx: RunContext,
    *,
    region: str,
    fs_type: str,
) -> tuple[float, str, int]:
    """
    Best-effort FSx throughput capacity price (USD per MBps-Mo).

    Returns: (usd_per_mbps_month, notes, confidence_int)
    """
    default_price = _fallback_throughput_usd_per_mbps_month(fs_type=fs_type)
    return PricingResolver(ctx).resolve_fsx_throughput_price(
        region=region,
        fs_type=fs_type,
        default_price=default_price,
        units=("MBps-Mo", "MBps-month", "MB/s-Mo"),
        call_exceptions=(AttributeError, TypeError, ValueError, ClientError),
    )


def _to_str(v: Any) -> str:
    if v is None:
        return ""
    try:
        return str(v)
    except Exception:
        return ""


def _to_int(v: Any) -> int | None:
    if v is None:
        return None
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _to_float(v: Any) -> float | None:
    if v is None:
        return None
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _age_days(created: Any, *, now_ts: datetime) -> int | None:
    if not isinstance(created, datetime):
        return None
    dt = created
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    else:
        dt = dt.astimezone(UTC)
    return int((now_ts - dt).total_seconds() // 86400)


def _is_nonprod(tags: dict[str, str]) -> bool:
    for k in ("env", "environment", "stage", "tier"):
        v = (tags.get(k) or "").strip().lower()
        if v and any(h in v for h in _NONPROD_HINTS):
            return True
    name = (tags.get("name") or "").strip().lower()
    if name and any(h in name for h in _NONPROD_HINTS):
        return True
    return False


def _extract_deployment_type(fs: dict[str, Any]) -> str:
    # Many FSx types embed DeploymentType under their specific config blocks
    for key in ("WindowsConfiguration", "OntapConfiguration", "LustreConfiguration"):
        cfg = fs.get(key)
        if isinstance(cfg, dict):
            dep = _to_str(cfg.get("DeploymentType"))
            if dep:
                return dep
    return ""


def _extract_throughput_capacity(fs: dict[str, Any]) -> int | None:
    top = _to_int(fs.get("ThroughputCapacity"))
    if top is not None:
        return top

    for key in ("WindowsConfiguration", "OntapConfiguration", "LustreConfiguration"):
        cfg = fs.get(key)
        if isinstance(cfg, dict):
            tc = _to_int(cfg.get("ThroughputCapacity"))
            if tc is not None:
                return tc
    return None


def _extract_windows_cfg(fs: dict[str, Any]) -> dict[str, Any]:
    cfg = fs.get("WindowsConfiguration")
    if isinstance(cfg, dict):
        return cfg
    return {}


# -----------------------------
# CloudWatch metric helpers (best-effort)
# -----------------------------


def _cw_get(
    ctx: RunContext,
    *,
    fs_id: str,
    metric_name: str,
    start: datetime,
    end: datetime,
    period: int,
    statistics: Sequence[str],
) -> list[dict[str, Any]]:
    cw = getattr(ctx.services, "cloudwatch", None) if ctx.services is not None else None
    if cw is None:
        return []

    try:
        resp = cw.get_metric_statistics(
            Namespace="AWS/FSx",
            MetricName=metric_name,
            Dimensions=[{"Name": "FileSystemId", "Value": fs_id}],
            StartTime=start,
            EndTime=end,
            Period=period,
            Statistics=list(statistics),
        )
        dps = resp.get("Datapoints", [])
        if isinstance(dps, list):
            return [dp for dp in dps if isinstance(dp, dict)]
        return []
    except ClientError:
        return []
    except (AttributeError, TypeError, ValueError):
        return []


def _p95(values: list[float]) -> float | None:
    return percentile(values, 95.0, method="floor")


def _activity_signal(ctx: RunContext, *, fs_id: str, days: int) -> tuple[bool, dict[str, Any]]:
    """
    Returns (active, evidence).
    active=True if any known metric shows >0 activity.
    """
    end = now_utc()
    start = end - timedelta(days=days)

    candidates: list[tuple[str, str]] = [
        ("DataReadBytes", "Sum"),
        ("DataWriteBytes", "Sum"),
        ("ThroughputUtilization", "Average"),
        ("NetworkThroughputUtilization", "Average"),
        ("DiskIopsUtilization", "Average"),
    ]

    any_metric_seen = False
    evidence: dict[str, Any] = {
        "window_days": days,
        "seen_metrics": [],
        "any_metric_seen": False,
        "nonzero": {},
    }

    for metric, stat in candidates:
        dps = _cw_get(
            ctx,
            fs_id=fs_id,
            metric_name=metric,
            start=start,
            end=end,
            period=86400,
            statistics=[stat],
        )
        if dps:
            any_metric_seen = True
            evidence["seen_metrics"].append(metric)

        if stat == "Sum":
            for dp in dps:
                if (_to_float(dp.get("Sum")) or 0.0) > 0.0:
                    evidence["nonzero"][metric] = True
                    evidence["any_metric_seen"] = any_metric_seen
                    return True, evidence
        else:
            for dp in dps:
                if (_to_float(dp.get("Average")) or 0.0) > 0.0:
                    evidence["nonzero"][metric] = True
                    evidence["any_metric_seen"] = any_metric_seen
                    return True, evidence

    evidence["any_metric_seen"] = any_metric_seen
    return False, evidence


def _p95_utilization_pct(ctx: RunContext, *, fs_id: str, days: int) -> tuple[float | None, dict[str, Any]]:
    """
    Best-effort: returns p95 utilization percentage from known utilization metrics.
    """
    end = now_utc()
    start = end - timedelta(days=days)

    for metric in ("ThroughputUtilization", "NetworkThroughputUtilization"):
        dps = _cw_get(
            ctx,
            fs_id=fs_id,
            metric_name=metric,
            start=start,
            end=end,
            period=3600,
            statistics=["Average"],
        )
        if not dps:
            continue
        vals: list[float] = []
        for dp in dps:
            v = _to_float(dp.get("Average"))
            if v is not None:
                vals.append(v)
        p95v = _p95(vals)
        if p95v is not None:
            return p95v, {"metric": metric, "period_s": 3600, "window_days": days}

    return None, {"window_days": days, "reason": "no_util_metrics"}


def _p95_rw_mib_per_s(ctx: RunContext, *, fs_id: str, days: int) -> tuple[float | None, dict[str, Any]]:
    """
    Fallback: approximate p95 throughput via DataReadBytes+DataWriteBytes (Sum per hour).
    Returns MiB/s.
    """
    end = now_utc()
    start = end - timedelta(days=days)

    read = _cw_get(ctx, fs_id=fs_id, metric_name="DataReadBytes", start=start, end=end, period=3600, statistics=["Sum"])
    write = _cw_get(ctx, fs_id=fs_id, metric_name="DataWriteBytes", start=start, end=end, period=3600, statistics=["Sum"])

    if not read and not write:
        return None, {"window_days": days, "reason": "no_rw_metrics"}

    read_vals: list[float] = [(_to_float(dp.get("Sum")) or 0.0) for dp in read]
    write_vals: list[float] = [(_to_float(dp.get("Sum")) or 0.0) for dp in write]

    p95_read = _p95(read_vals) or 0.0
    p95_write = _p95(write_vals) or 0.0
    p95_total_bytes_per_hour = p95_read + p95_write
    mib_per_s = (p95_total_bytes_per_hour / 3600.0) / (1024.0 * 1024.0)

    return mib_per_s, {"window_days": days, "fallback": "rw_bytes", "period_s": 3600}


# -----------------------------
# Checker
# -----------------------------


class FSxFileSystemsChecker(Checker):
    checker_id = "aws.fsx.filesystems"

    def __init__(self, *, account_id: str, cfg: FSxFileSystemsConfig | None = None) -> None:
        self._account_id = str(account_id)
        self._cfg = cfg or FSxFileSystemsConfig()

    @staticmethod
    def _list_file_systems_best_effort(fsx: Any) -> list[dict[str, Any]]:
        file_systems: list[dict[str, Any]] = []
        # Prefer paginator for correctness (API is paginated).
        try:
            paginator = fsx.get_paginator("describe_file_systems")
            for page in paginator.paginate():
                page_fs = page.get("FileSystems", []) or []
                if isinstance(page_fs, list):
                    for fs_any in page_fs:
                        if isinstance(fs_any, dict):
                            file_systems.append(fs_any)
            return file_systems
        except (AttributeError, TypeError, ValueError, ClientError):
            pass

        # Fallback: single call (older mocks / unusual clients / edge cases).
        try:
            resp = fsx.describe_file_systems()
            page_fs = resp.get("FileSystems", []) or []
            if isinstance(page_fs, list):
                for fs_any in page_fs:
                    if isinstance(fs_any, dict):
                        file_systems.append(fs_any)
        except (AttributeError, TypeError, ValueError, ClientError):
            return []
        return file_systems

    def _pricing_baseline_for_file_system(
        self,
        *,
        ctx: RunContext,
        region: str,
        fs_type: str,
        storage_type: str,
        storage_gib: int | None,
        throughput_cfg: int | None,
    ) -> tuple[float, float, str, int]:
        storage_price, storage_notes, storage_conf = _resolve_fsx_storage_price_usd_per_gb_month(
            ctx,
            region=region,
            fs_type=fs_type,
            storage_type=storage_type or "SSD",
        )
        throughput_price, throughput_notes, throughput_conf = _resolve_fsx_throughput_price_usd_per_mbps_month(
            ctx,
            region=region,
            fs_type=fs_type,
        )

        storage_cost = 0.0
        if storage_gib is not None and storage_gib > 0:
            storage_cost = float(storage_gib) * float(storage_price)

        throughput_cost = 0.0
        if throughput_cfg is not None and throughput_cfg > 0:
            throughput_cost = float(throughput_cfg) * float(throughput_price)

        baseline_monthly_cost = money(storage_cost + throughput_cost)
        pricing_notes = "; ".join([n for n in (storage_notes, throughput_notes) if n]).strip()
        pricing_conf = int(min(storage_conf, throughput_conf))
        return baseline_monthly_cost, throughput_cost, pricing_notes, pricing_conf

    def run(self, ctx: RunContext) -> Iterable[FindingDraft]:
        _LOGGER.info("Starting FSx filesystems check")
        if ctx.services is None or getattr(ctx.services, "fsx", None) is None:
            _LOGGER.warning("FSx client not available in services")
            return

        fsx = ctx.services.fsx
        region = safe_region_from_client(fsx) or "unknown"
        _LOGGER.debug("FSx check running", extra={"region": region})
        cfg = self._cfg

        account = AwsAccountContext(account_id=self._account_id)

        file_systems = self._list_file_systems_best_effort(fsx)

        if not file_systems:
            return

        _LOGGER.info("Listed FSx filesystems", extra={"count": len(file_systems), "region": region})

        # Counters per check_id to enforce max_findings_per_type
        emitted: dict[str, int] = {}

        for fs_any in file_systems:
            if not isinstance(fs_any, dict):
                continue
            fs = fs_any

            fs_id = _to_str(fs.get("FileSystemId"))
            if not fs_id:
                continue
            fs_arn = _to_str(fs.get("ResourceARN"))
            fs_type = _to_str(fs.get("FileSystemType")).upper()
            tags = normalize_tags(fs.get("Tags"))

            dep = _extract_deployment_type(fs)
            throughput_cfg = _extract_throughput_capacity(fs)
            storage_gib = _to_int(fs.get("StorageCapacity"))

            # Determine storage_type for pricing
            storage_type = ""
            if fs_type == "WINDOWS":
                win = _extract_windows_cfg(fs)
                storage_type = _to_str(win.get("StorageType")).upper() or "SSD"
            elif fs_type in ("ONTAP", "LUSTRE"):
                # FSx APIs differ; keep default as SSD for safety
                storage_type = "SSD"

            baseline_monthly_cost, throughput_cost, pricing_notes, pricing_conf = self._pricing_baseline_for_file_system(
                ctx=ctx,
                region=region,
                fs_type=fs_type,
                storage_type=storage_type,
                storage_gib=storage_gib,
                throughput_cfg=throughput_cfg,
            )


            base_scope = build_scope(
                ctx,
                account=account,
                region=region,
                service="fsx",
                resource_type="filesystem",
                resource_id=fs_id,
                resource_arn=fs_arn,
            )

            # -----------------------------
            # Governance: missing required tags
            # -----------------------------
            missing = [k for k in cfg.required_tag_keys if not (tags.get(k, "") or "").strip()]
            if missing:
                check_id = "aws.fsx.filesystems.missing.required.tags"
                if emitted.get(check_id, 0) < cfg.max_findings_per_type:
                    emitted[check_id] = emitted.get(check_id, 0) + 1
                    yield FindingDraft(
                        check_id=check_id,
                        check_name="FSx missing required tags",
                        category="governance",
                        status="fail",
                        severity=Severity(level="low", score=300),
                        title="FSx file system missing required tags",
                        scope=base_scope,
                        message="FSx file system is missing required tags used for allocation/governance.",
                        recommendation="Add the required tags (e.g., env, owner) to improve chargeback and policy controls.",
                        tags=tags,
                        issue_key={"fs_id": fs_id, "missing": ",".join(sorted(missing))},
                        labels={"service": "fsx"},
                        dimensions={"fs_type": fs_type},
                    )

            # -----------------------------
            # 1) Possibly unused (best-effort)
            # -----------------------------
            active, evidence = _activity_signal(ctx, fs_id=fs_id, days=cfg.unused_lookback_days)
            if not active:
                check_id = "aws.fsx.filesystems.possible.unused"
                if emitted.get(check_id, 0) < cfg.max_findings_per_type:
                    emitted[check_id] = emitted.get(check_id, 0) + 1
                    conf = 60 if bool(evidence.get("any_metric_seen")) else 35
                    yield FindingDraft(
                        check_id=check_id,
                        check_name="FSx possible unused file system",
                        category="waste",
                        status="fail",
                        severity=Severity(level="medium", score=650),
                        title="FSx file system may be unused",
                        scope=base_scope,
                        message=f"No observed FSx activity in the last {cfg.unused_lookback_days} days (best-effort CloudWatch).",
                        recommendation="Validate clients/mounts and workload ownership. If unused, delete the file system or stop the workload.",
                        tags=tags,
                        issue_key={"fs_id": fs_id, "signal": "no_activity"},
                        estimated_monthly_cost=baseline_monthly_cost if baseline_monthly_cost > 0 else None,
                        estimated_monthly_savings=baseline_monthly_cost if baseline_monthly_cost > 0 else None,
                        estimate_confidence=min(int(conf), pricing_conf),
                        estimate_notes=f"{pricing_notes} | Unused heuristic is best-effort via CloudWatch; verify mounts/clients before deletion.",
                        labels={"service": "fsx"},
                        dimensions={"fs_type": fs_type},
                    )

            # -----------------------------
            # 2) Underutilized throughput (best-effort)
            # -----------------------------
            if throughput_cfg is not None and throughput_cfg > 0:
                p95_util, util_dbg = _p95_utilization_pct(ctx, fs_id=fs_id, days=cfg.throughput_lookback_days)

                if p95_util is not None and p95_util < cfg.underutilized_p95_util_threshold_pct:
                    check_id = "aws.fsx.filesystems.underutilized.throughput"
                    if emitted.get(check_id, 0) < cfg.max_findings_per_type:
                        emitted[check_id] = emitted.get(check_id, 0) + 1
                        yield FindingDraft(
                            check_id=check_id,
                            check_name="FSx underutilized throughput capacity",
                            category="cost",
                            status="fail",
                            severity=Severity(level="medium", score=700),
                            title="FSx throughput capacity appears over-provisioned",
                            scope=base_scope,
                            message=f"Observed p95 throughput utilization is low ({p95_util:.1f}%) vs configured throughput capacity.",
                            recommendation="Consider downsizing throughput capacity after validating peak workload requirements.",
                            tags=tags,
                            issue_key={"fs_id": fs_id, "signal": "p95_util_low"},
                            estimated_monthly_cost=money(throughput_cost) if throughput_cost > 0 else None,
                            estimated_monthly_savings=None,
                            estimate_confidence=min(65, pricing_conf),
                            estimate_notes=f"{pricing_notes} | Savings depends on target throughput tier; compute delta once you implement tier mapping.",
                            labels={"service": "fsx"},
                            dimensions={"fs_type": fs_type},
                            # keep numeric notes in details
                            links=[],
                        ).with_issue(p95_util_pct=p95_util)  # stable discriminator

                else:
                    # Fallback signal: bytes/sec approximation (no check emission by default; kept as details for Windows checks)
                    _ = util_dbg

            # -----------------------------
            # 2b) large and inactive storage (heuristic)
            # -----------------------------
            if storage_gib is not None and storage_gib >= cfg.large_storage_gib_threshold and not active:
                check_id = "aws.fsx.filesystems.large.and.inactive"
                if emitted.get(check_id, 0) < cfg.max_findings_per_type:
                    emitted[check_id] = emitted.get(check_id, 0) + 1
                    yield FindingDraft(
                        check_id=check_id,
                        check_name="FSx over-provisioned storage (heuristic)",
                        category="cost",
                        status="fail",
                        severity=Severity(level="low", score=350),
                        title="FSx provisioned storage may be over-sized",
                        scope=base_scope,
                        message="Large provisioned storage combined with low activity suggests potential over-provisioning.",
                        recommendation="Review used capacity (FSx-type-specific) and resize if consistently underutilized.",
                        tags=tags,
                        issue_key={"fs_id": fs_id, "signal": "large_storage_low_activity"},
                        estimated_monthly_cost=baseline_monthly_cost if baseline_monthly_cost > 0 else None,
                        estimated_monthly_savings=None,  # do not guess resize delta without used-capacity metrics
                        estimate_confidence=min(40, pricing_conf),
                        estimate_notes=f"{pricing_notes} | Storage overprovision is heuristic until per-type used-capacity metrics are integrated.",
                        labels={"service": "fsx"},
                        dimensions={"fs_type": fs_type},
                    )

            # -----------------------------
            # 3) Multi-AZ in nonprod (Windows/ONTAP)
            # -----------------------------
            if dep and "MULTI_AZ" in dep.upper() and _is_nonprod(tags) and fs_type in ("WINDOWS", "ONTAP"):
                check_id = "aws.fsx.filesystems.multi.az.in.nonprod"
                if emitted.get(check_id, 0) < cfg.max_findings_per_type:
                    emitted[check_id] = emitted.get(check_id, 0) + 1
                    yield FindingDraft(
                        check_id=check_id,
                        check_name="FSx Multi-AZ in non-production",
                        category="cost",
                        status="fail",
                        severity=Severity(level="medium", score=650),
                        title="Multi-AZ FSx in non-production environment",
                        scope=base_scope,
                        message="Multi-AZ deployment detected in a non-production environment (based on tags).",
                        recommendation="If HA is not required for non-prod, consider Single-AZ to reduce cost.",
                        tags=tags,
                        issue_key={"fs_id": fs_id, "signal": "multi_az_nonprod"},
                        estimate_confidence=70,
                        labels={"service": "fsx"},
                        dimensions={"fs_type": fs_type},
                    )

            # -----------------------------
            # Windows-specific governance / cost checks
            # -----------------------------
            if fs_type == "WINDOWS":
                yield from self._windows_findings(
                    ctx,
                    fs=fs,
                    base_scope=base_scope,
                    tags=tags,
                    region=region,
                    storage_gib=storage_gib,
                    storage_type=storage_type,
                    baseline_monthly_cost=baseline_monthly_cost,
                    pricing_conf=pricing_conf,
                    pricing_notes=pricing_notes,
                    emitted=emitted,
                )

    # -----------------------------
    # Windows patched helper (ctx-aware)
    # -----------------------------

    def _windows_findings(
        self,
        ctx: RunContext,
        *,
        fs: dict[str, Any],
        base_scope: Any,
        tags: dict[str, str],
        region: str,
        storage_gib: int | None,
        storage_type: str,
        baseline_monthly_cost: float,
        pricing_conf: int,
        pricing_notes: str,
        emitted: dict[str, int],
    ) -> Iterable[FindingDraft]:
        cfg = self._cfg
        fs_id = _to_str(fs.get("FileSystemId"))

        win = _extract_windows_cfg(fs)
        backup_days = _to_int(win.get("AutomaticBackupRetentionDays"))
        copy_tags = win.get("CopyTagsToBackups") if isinstance(win.get("CopyTagsToBackups"), bool) else None
        maint = _to_str(win.get("WeeklyMaintenanceStartTime"))
        # Keep the passed-in storage_type as the source of truth; fill from API only if missing.
        if not storage_type:
            storage_type = _to_str(win.get("StorageType")).upper()


        # Backups disabled
        if backup_days == 0:
            check_id = "aws.fsx.windows.backups.disabled"
            if emitted.get(check_id, 0) < cfg.max_findings_per_type:
                emitted[check_id] = emitted.get(check_id, 0) + 1
                yield FindingDraft(
                    check_id=check_id,
                    check_name="FSx Windows backups disabled",
                    category="governance",
                    status="fail",
                    severity=Severity(level="high", score=850),
                    title="FSx Windows automatic backups are disabled",
                    scope=base_scope,
                    message="AutomaticBackupRetentionDays is 0 (backups disabled).",
                    recommendation="Enable automatic backups and set retention based on RPO/RTO requirements.",
                    tags=tags,
                    issue_key={"fs_id": fs_id, "signal": "backups_disabled"},
                    estimate_confidence=90,
                    labels={"service": "fsx"},
                    dimensions={"fs_type": "WINDOWS"},
                )

        # Backup retention low
        if backup_days is not None and backup_days > 0 and backup_days < cfg.windows_backup_low_retention_days:
            check_id = "aws.fsx.windows.backup.retention.low"
            if emitted.get(check_id, 0) < cfg.max_findings_per_type:
                emitted[check_id] = emitted.get(check_id, 0) + 1
                yield FindingDraft(
                    check_id=check_id,
                    check_name="FSx Windows backup retention low",
                    category="governance",
                    status="fail",
                    severity=Severity(level="medium", score=650),
                    title="FSx Windows backup retention is low",
                    scope=base_scope,
                    message=f"Automatic backup retention is {backup_days} day(s).",
                    recommendation="Increase retention if recovery and compliance requirements demand it.",
                    tags=tags,
                    issue_key={"fs_id": fs_id, "signal": "retention_low"},
                    estimate_confidence=80,
                    labels={"service": "fsx"},
                    dimensions={"fs_type": "WINDOWS"},
                ).with_issue(retention_days=backup_days)

        # Copy tags to backups disabled
        if copy_tags is False:
            check_id = "aws.fsx.windows.copy.tags.to.backups.disabled"
            if emitted.get(check_id, 0) < cfg.max_findings_per_type:
                emitted[check_id] = emitted.get(check_id, 0) + 1
                yield FindingDraft(
                    check_id=check_id,
                    check_name="FSx Windows copy tags to backups disabled",
                    category="governance",
                    status="fail",
                    severity=Severity(level="low", score=300),
                    title="FSx Windows does not copy tags to backups",
                    scope=base_scope,
                    message="CopyTagsToBackups is false; backup artifacts will miss allocation tags.",
                    recommendation="Enable CopyTagsToBackups for better chargeback, discovery, and policy controls.",
                    tags=tags,
                    issue_key={"fs_id": fs_id, "signal": "copy_tags_disabled"},
                    estimate_confidence=90,
                    labels={"service": "fsx"},
                    dimensions={"fs_type": "WINDOWS"},
                )

        # Maintenance window missing / business hours (best-effort)
        if not maint:
            check_id = "aws.fsx.windows.maintenance.window.missing"
            if emitted.get(check_id, 0) < cfg.max_findings_per_type:
                emitted[check_id] = emitted.get(check_id, 0) + 1
                yield FindingDraft(
                    check_id=check_id,
                    check_name="FSx Windows maintenance window missing",
                    category="governance",
                    status="fail",
                    severity=Severity(level="low", score=250),
                    title="FSx Windows maintenance window not set",
                    scope=base_scope,
                    message="WeeklyMaintenanceStartTime is not configured.",
                    recommendation="Set a maintenance window appropriate for your workload (off-hours for production).",
                    tags=tags,
                    issue_key={"fs_id": fs_id, "signal": "maintenance_missing"},
                    estimate_confidence=70,
                    labels={"service": "fsx"},
                    dimensions={"fs_type": "WINDOWS"},
                )
        else:
            # Format usually "d:HH:MM" or "d:HH:MM:SS"; parse HH best-effort
            hour: int | None = None
            try:
                parts = maint.split(":")
                if len(parts) >= 2:
                    hour = int(parts[1])
            except (AttributeError, TypeError, ValueError):
                hour = None

            if hour is not None and 8 <= hour <= 18 and not _is_nonprod(tags):
                check_id = "aws.fsx.windows.maintenance.window.business.hours"
                if emitted.get(check_id, 0) < cfg.max_findings_per_type:
                    emitted[check_id] = emitted.get(check_id, 0) + 1
                    yield FindingDraft(
                        check_id=check_id,
                        check_name="FSx Windows maintenance window during business hours",
                        category="governance",
                        status="fail",
                        severity=Severity(level="low", score=250),
                        title="FSx Windows maintenance window may be during business hours",
                        scope=base_scope,
                        message=f"WeeklyMaintenanceStartTime='{maint}' (parsed hour={hour}).",
                        recommendation="Move the maintenance window to off-hours for production workloads.",
                        tags=tags,
                        issue_key={"fs_id": fs_id, "signal": "maintenance_business_hours"},
                        estimate_confidence=55,
                        estimate_notes="Parsing is best-effort; confirm timezone/format in AWS console.",
                        labels={"service": "fsx"},
                        dimensions={"fs_type": "WINDOWS"},
                    ).with_issue(parsed_hour_utc=hour)

        # Windows SSD vs HDD mismatch (patched: ctx-aware metrics)
        # Heuristic: if SSD and observed activity is low, suggest HDD
        if storage_type == "SSD":
            active, evidence = _activity_signal(ctx, fs_id=fs_id, days=cfg.unused_lookback_days)
            p95_util, _util_dbg = _p95_utilization_pct(ctx, fs_id=fs_id, days=cfg.throughput_lookback_days)
            p95_rw_mib_s, _rw_dbg = _p95_rw_mib_per_s(ctx, fs_id=fs_id, days=cfg.throughput_lookback_days)

            low_util = (p95_util is not None and p95_util < 10.0)
            low_rw = (p95_rw_mib_s is not None and p95_rw_mib_s < 1.0)  # ~1 MiB/s p95

            if (not active) or low_util or low_rw:
                # storage_gib is Optional[int]; we must guard it for type-checkers and runtime safety.
                if storage_gib is None or storage_gib <= 0:
                    # Cannot compute a meaningful SSD→HDD delta without storage capacity
                    check_id = "aws.fsx.windows.storage.type.mismatch"
                    if emitted.get(check_id, 0) < cfg.max_findings_per_type:
                        emitted[check_id] = emitted.get(check_id, 0) + 1
                        yield FindingDraft(
                            check_id=check_id,
                            check_name="FSx Windows storage type mismatch",
                            category="cost",
                            status="fail",
                            severity=Severity(level="low", score=350),
                            title="FSx Windows SSD may be unnecessary for observed workload",
                            scope=base_scope,
                            message="Windows file system uses SSD storage type but observed activity/utilization is low (best-effort).",
                            recommendation="If performance requirements are low, consider HDD storage type to reduce cost.",
                            tags=tags,
                            issue_key={"fs_id": fs_id, "signal": "ssd_low_activity"},
                            estimate_confidence=min(pricing_conf, 40),
                            estimate_notes=f"{pricing_notes} | StorageCapacity missing; cannot compute SSD→HDD savings.",
                            labels={"service": "fsx"},
                            dimensions={"fs_type": "WINDOWS"},
                        ).with_issue(
                            p95_util_pct=p95_util if p95_util is not None else "",
                            p95_rw_mib_s=p95_rw_mib_s if p95_rw_mib_s is not None else "",
                        )
                    return

                gib = int(storage_gib)

                hdd_price, hdd_notes, hdd_conf = _resolve_fsx_storage_price_usd_per_gb_month(
                    ctx,
                    region=region,
                    fs_type="WINDOWS",
                    storage_type="HDD",
                )

                ssd_price, ssd_notes, ssd_conf = _resolve_fsx_storage_price_usd_per_gb_month(
                    ctx,
                    region=region,
                    fs_type="WINDOWS",
                    storage_type="SSD",
                )

                ssd_cost = float(gib) * float(ssd_price)
                hdd_cost = float(gib) * float(hdd_price)

                savings = max(0.0, ssd_cost - hdd_cost)

                check_id = "aws.fsx.windows.storage.type.mismatch"
                if emitted.get(check_id, 0) < cfg.max_findings_per_type:
                    emitted[check_id] = emitted.get(check_id, 0) + 1
                    yield FindingDraft(
                        check_id=check_id,
                        check_name="FSx Windows storage type mismatch",
                        category="cost",
                        status="fail",
                        severity=Severity(level="low", score=350),
                        title="FSx Windows SSD may be unnecessary for observed workload",
                        scope=base_scope,
                        message="Windows file system uses SSD storage type but observed activity/utilization is low (best-effort).",
                        recommendation="If performance requirements are low, consider HDD storage type to reduce cost.",
                        tags=tags,
                        issue_key={"fs_id": fs_id, "signal": "ssd_low_activity"},
                        estimated_monthly_cost=money(ssd_cost),
                        estimated_monthly_savings=money(savings) if savings > 0 else None,
                        estimate_confidence=min(pricing_conf, hdd_conf, ssd_conf),
                        estimate_notes=f"{pricing_notes}; {ssd_notes}; {hdd_notes} | Validate IO before SSD→HDD switch.",
                        labels={"service": "fsx"},
                        dimensions={"fs_type": "WINDOWS"},
                        links=[],
                    ).with_issue(
                        p95_util_pct=p95_util if p95_util is not None else "",
                        p95_rw_mib_s=p95_rw_mib_s if p95_rw_mib_s is not None else "",
                        storage_gib=gib,
                    )


# -----------------------------
# Registry wiring
# -----------------------------


@register_checker("checks.aws.fsx_filesystems:FSxFileSystemsChecker")
def _factory(ctx: RunContext, bootstrap: Bootstrap) -> Checker:
    account_id = str(bootstrap.get("aws_account_id") or "")
    if not account_id:
        raise ValueError("bootstrap['aws_account_id'] is required for FSxFileSystemsChecker")
    return FSxFileSystemsChecker(account_id=account_id)
