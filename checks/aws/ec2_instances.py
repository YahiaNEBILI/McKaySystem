"""
checks/aws/ec2_instances.py

EC2 optimization, cost-efficiency, and hygiene checker.

Signals (cost / optimization):
1) Underutilized running instances
   - Low average CPU utilization
   - Low average network I/O
2) Stopped instances for a long time
   - Best-effort stop time parsing from instance state transition reason
3) Old generation instance families
   - Legacy families with poor price/performance compared to current generations
4) Burstable (T-family) CPU credit issues
   - Low CPUCreditBalance and/or surplus credits charged, indicating throttling
     or inefficient use of burstable instances

Signals (governance / security / hygiene):
5) Unused security groups
   - Not attached to any ENI
   - Excludes security groups that reference or are referenced by other SG rules
   - Excludes the default security group
6) IMDSv1 allowed
   - Instance metadata service does not enforce IMDSv2 (HttpTokens != required)
7) Administrative ports open to the Internet
   - SSH (22) and/or RDP (3389) exposed to 0.0.0.0/0 or ::/0
8) Missing required instance tags
   - Enforces basic FinOps hygiene (e.g. Application, Environment)

Notes
-----
- Metrics-based signals rely on best-effort CloudWatch data and will silently
  skip emission if metrics are unavailable.
- Cost and savings estimates are approximate and intended for directional
  guidance; CUR-based enrichment is expected to refine them downstream.
- This checker runs in the region configured by ``ctx.services.ec2``.
  For multi-region runs, the runner is expected to create one RunContext per
  region (or to iterate regions and re-invoke checkers with a region-specific
  Services bag).
"""


from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import re
from typing import Any, Dict, Iterable, Iterator, List, Mapping, Optional, Sequence, Set, Tuple

from botocore.exceptions import BotoCoreError, ClientError

from checks.aws._common import AwsAccountContext, PricingResolver, build_scope, get_logger, money, now_utc, safe_region_from_client, utc, normalize_tags
from checks.aws.defaults import (
    EC2_MAX_FINDINGS_PER_TYPE,
    EC2_REQUIRED_INSTANCE_TAG_KEYS,
    EC2_STOPPED_LONG_AGE_DAYS,
    EC2_T_CREDIT_BALANCE_MIN_THRESHOLD,
    EC2_T_CREDIT_LOOKBACK_DAYS,
    EC2_UNDERUTILIZED_CPU_AVG_THRESHOLD,
    EC2_UNDERUTILIZED_LOOKBACK_DAYS,
    EC2_UNDERUTILIZED_NET_AVG_KIB_PER_HOUR_THRESHOLD,
)
from checks.registry import Bootstrap, register_checker
from contracts.finops_checker_pattern import FindingDraft, RunContext, Severity

# Logger for this module
_LOGGER = get_logger("ec2_instances")


# -----------------------------
# Config
# -----------------------------


@dataclass(frozen=True)
class EC2InstancesConfig:
    """Configuration knobs for :class:`EC2InstancesChecker`."""

    underutilized_lookback_days: int = EC2_UNDERUTILIZED_LOOKBACK_DAYS
    underutilized_cpu_avg_threshold: float = EC2_UNDERUTILIZED_CPU_AVG_THRESHOLD
    underutilized_net_avg_kib_per_hour_threshold: float = EC2_UNDERUTILIZED_NET_AVG_KIB_PER_HOUR_THRESHOLD  # ~12 MiB/day

    stopped_long_age_days: int = EC2_STOPPED_LONG_AGE_DAYS

    # Safety valve for environments with millions of resources.
    max_findings_per_type: int = EC2_MAX_FINDINGS_PER_TYPE

    # CPU credit signals (T-family)
    t_credit_lookback_days: int = EC2_T_CREDIT_LOOKBACK_DAYS
    t_credit_balance_min_threshold: float = EC2_T_CREDIT_BALANCE_MIN_THRESHOLD

    # Tag governance
    required_instance_tag_keys: Tuple[str, ...] = EC2_REQUIRED_INSTANCE_TAG_KEYS

# -----------------------------
# Pricing helpers
# -----------------------------


_FALLBACK_EBS_USD_PER_GB_MONTH: Dict[str, float] = {
    "gp2": 0.10,
    "gp3": 0.08,
    "standard": 0.05,
    "st1": 0.045,
    "sc1": 0.025,
}


def _estimate_instance_monthly_cost_usd(ctx: RunContext, *, region: str, instance_type: str) -> Tuple[Optional[float], int, str]:
    """Best-effort on-demand Linux shared instance monthly cost estimate.

    Returns: (monthly_cost, confidence_0_100, notes)
    """
    return PricingResolver(ctx).resolve_ec2_instance_monthly_cost(
        region=region,
        instance_type=instance_type,
        call_exceptions=(AttributeError, TypeError, ValueError, BotoCoreError, ClientError),
    )


def _estimate_ebs_monthly_cost_usd(size_gib: float, volume_type: str) -> float:
    return PricingResolver(None).estimate_ebs_monthly_cost(
        size_gib=float(size_gib),
        volume_type=volume_type,
        fallback_prices=_FALLBACK_EBS_USD_PER_GB_MONTH,
        default_price=0.10,
    )


# -----------------------------
# Stop time parsing
# -----------------------------


_STOP_REASON_RE = re.compile(r"\((?P<ts>\d{4}-\d{2}-\d{2}(?: \d{2}:\d{2}:\d{2})?)\)")


def _parse_stop_time(state_transition_reason: str) -> Optional[datetime]:
    """Parse stop time from AWS' StateTransitionReason string (best-effort)."""

    m = _STOP_REASON_RE.search(str(state_transition_reason or ""))
    if not m:
        return None
    raw = m.group("ts")
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(raw, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


# -----------------------------
# Old generation detection
# -----------------------------


# Conservative list: flag only families that are unequivocally old/previous-gen.
_OLD_FAMILIES: Set[str] = {
    "t1",
    "t2",
    "m1",
    "m2",
    "m3",
    "c1",
    "c3",
    "r3",
    "i2",
    "d2",
    "g2",
    "p2",
    "x1",
    "x1e",
}


_INSTANCE_SIZE_ORDER: Tuple[str, ...] = (
    "nano",
    "micro",
    "small",
    "medium",
    "large",
    "xlarge",
    "2xlarge",
    "3xlarge",
    "4xlarge",
    "6xlarge",
    "8xlarge",
    "9xlarge",
    "10xlarge",
    "12xlarge",
    "16xlarge",
    "18xlarge",
    "24xlarge",
    "32xlarge",
    "48xlarge",
    "56xlarge",
)
_INSTANCE_SIZE_INDEX: Dict[str, int] = {name: idx for idx, name in enumerate(_INSTANCE_SIZE_ORDER)}


def _instance_family(instance_type: str) -> str:
    t = str(instance_type or "").strip().lower()
    if not t:
        return ""
    return t.split(".", 1)[0]


def _split_instance_type(instance_type: str) -> Tuple[str, str]:
    """Split an EC2 instance type into (family, size), e.g. m5.2xlarge."""
    t = str(instance_type or "").strip().lower()
    if "." not in t:
        return "", ""
    family, size = t.split(".", 1)
    if not family or not size:
        return "", ""
    return family, size


def _previous_instance_size(size: str) -> Optional[str]:
    """Return the next-smaller known size token, if one exists."""
    idx = _INSTANCE_SIZE_INDEX.get(str(size or "").strip().lower())
    if idx is None or idx <= 0:
        return None
    return _INSTANCE_SIZE_ORDER[idx - 1]


def _recommended_smaller_instance_type(instance_type: str) -> Optional[str]:
    """Return a deterministic same-family one-step downsize recommendation."""
    family, size = _split_instance_type(instance_type)
    if not family or not size:
        return None
    prev_size = _previous_instance_size(size)
    if not prev_size:
        return None
    return f"{family}.{prev_size}"


def _to_int(value: Any) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        s = value.strip()
        if not s:
            return None
        try:
            return int(s)
        except ValueError:
            return None
    return None


# -----------------------------
# CloudWatch metrics (batched)
# -----------------------------


def _chunked(items: Sequence[str], size: int) -> Iterator[List[str]]:
    buf: List[str] = []
    for it in items:
        buf.append(it)
        if len(buf) >= size:
            yield buf
            buf = []
    if buf:
        yield buf


def _metric_query(query_id: str, *, metric: str, namespace: str, dimensions: List[Dict[str, str]], stat: str) -> Dict[str, Any]:
    return {
        "Id": query_id,
        "MetricStat": {
            "Metric": {"Namespace": namespace, "MetricName": metric, "Dimensions": dimensions},
            "Period": 3600,
            "Stat": stat,
        },
        "ReturnData": True,
    }


def _fetch_t_credit_metrics(
    ctx: RunContext,
    *,
    instance_ids: Sequence[str],
    lookback_days: int,
) -> Dict[str, Dict[str, float]]:
    """Return per-instance CPU credit summary for T-family instances.

    Result shape: {instance_id: {"credit_balance_min": ..., "surplus_charged_sum": ...}}
    """

    cw = getattr(getattr(ctx, "services", None), "cloudwatch", None)
    if cw is None:
        return {}

    end = now_utc()
    start = end - timedelta(days=int(max(1, lookback_days)))

    out: Dict[str, Dict[str, float]] = {}

    # 2 queries per instance -> 200 instances/request (leaving safety margin under 500 limit).
    for batch in _chunked(list(instance_ids), 200):
        queries: List[Dict[str, Any]] = []
        for i, iid in enumerate(batch):
            dims = [{"Name": "InstanceId", "Value": iid}]
            queries.append(_metric_query(f"cb{i}", metric="CPUCreditBalance", namespace="AWS/EC2", dimensions=dims, stat="Minimum"))
            queries.append(_metric_query(f"sc{i}", metric="CPUSurplusCreditsCharged", namespace="AWS/EC2", dimensions=dims, stat="Sum"))

        try:
            resp = cw.get_metric_data(
                MetricDataQueries=queries,
                StartTime=start,
                EndTime=end,
                ScanBy="TimestampDescending",
                MaxDatapoints=5000,
            )
        except (BotoCoreError, ClientError):
            continue

        results = {r.get("Id"): r for r in (resp or {}).get("MetricDataResults", [])}
        for i, iid in enumerate(batch):
            cb_vals = list(results.get(f"cb{i}", {}).get("Values", []) or [])
            sc_vals = list(results.get(f"sc{i}", {}).get("Values", []) or [])
            if not cb_vals and not sc_vals:
                continue
            credit_balance_min = float(min(cb_vals)) if cb_vals else 0.0
            surplus_charged_sum = float(sum(sc_vals)) if sc_vals else 0.0
            out[iid] = {"credit_balance_min": credit_balance_min, "surplus_charged_sum": surplus_charged_sum}

    return out


def _fetch_utilization_metrics(
    ctx: RunContext,
    *,
    region: str,
    instance_ids: Sequence[str],
    lookback_days: int,
) -> Dict[str, Dict[str, float]]:
    """Return per-instance utilization summary.

    Result shape: {instance_id: {"cpu_avg": ..., "net_kib_per_hour": ...}}
    """

    cw = getattr(getattr(ctx, "services", None), "cloudwatch", None)
    if cw is None:
        return {}

    end = now_utc()
    start = end - timedelta(days=int(max(1, lookback_days)))

    out: Dict[str, Dict[str, float]] = {}

    # CloudWatch GetMetricData limit is 500 MetricDataQueries per request.
    # We use 3 queries per instance (cpu, netin, netout) -> 50 instances per request.
    for batch in _chunked(list(instance_ids), 50):
        queries: List[Dict[str, Any]] = []
        for i, iid in enumerate(batch):
            dims = [{"Name": "InstanceId", "Value": iid}]
            queries.append(_metric_query(f"cpu{i}", metric="CPUUtilization", namespace="AWS/EC2", dimensions=dims, stat="Average"))
            queries.append(_metric_query(f"ni{i}", metric="NetworkIn", namespace="AWS/EC2", dimensions=dims, stat="Sum"))
            queries.append(_metric_query(f"no{i}", metric="NetworkOut", namespace="AWS/EC2", dimensions=dims, stat="Sum"))

        try:
            resp = cw.get_metric_data(
                MetricDataQueries=queries,
                StartTime=start,
                EndTime=end,
                ScanBy="TimestampDescending",
                MaxDatapoints=5000,
            )
        except (BotoCoreError, ClientError):
            continue

        results = {r.get("Id"): r for r in (resp or {}).get("MetricDataResults", [])}
        for i, iid in enumerate(batch):
            cpu_vals = list(results.get(f"cpu{i}", {}).get("Values", []) or [])
            ni_vals = list(results.get(f"ni{i}", {}).get("Values", []) or [])
            no_vals = list(results.get(f"no{i}", {}).get("Values", []) or [])
            if not cpu_vals and not ni_vals and not no_vals:
                continue
            cpu_avg = float(sum(cpu_vals) / max(1, len(cpu_vals))) if cpu_vals else 0.0
            # Network is in bytes per period (Sum over 1 hour). Convert to KiB/hour.
            net_total_bytes = float(sum(ni_vals) + sum(no_vals)) if (ni_vals or no_vals) else 0.0
            datapoints = max(len(ni_vals), len(no_vals), 1)
            net_kib_per_hour = (net_total_bytes / 1024.0) / float(datapoints)
            out[iid] = {"cpu_avg": cpu_avg, "net_kib_per_hour": net_kib_per_hour}

    return out


# -----------------------------
# Checker
# -----------------------------


class EC2InstancesChecker:
    """EC2 optimization + hygiene checks."""

    checker_id = "aws.ec2.instances"

    def __init__(
        self,
        *,
        account: AwsAccountContext,
        cfg: Optional[EC2InstancesConfig] = None,
    ) -> None:
        self._account = account
        self._cfg = cfg or EC2InstancesConfig()

    def run(self, ctx: RunContext) -> Iterable[FindingDraft]:
        _LOGGER.info("Starting EC2 instances check", extra={"region": "unknown"})
        ec2 = getattr(getattr(ctx, "services", None), "ec2", None)
        if ec2 is None:
            _LOGGER.warning("EC2 client not available in services")
            return []

        region = safe_region_from_client(ec2)
        _LOGGER.debug("EC2 check running", extra={"region": region})

        try:
            instances = list(self._list_instances(ec2))
        except (BotoCoreError, ClientError) as e:
            _LOGGER.error("Failed to list EC2 instances", extra={"error": str(e)})
            return []

        _LOGGER.info("Listed EC2 instances", extra={"count": len(instances), "region": region})

        by_state = self._group_instances_by_state(instances)

        # NEW: load security inventory once (best-effort)
        sgs, enis = self._load_security_inventory(ec2)

        sg_by_id: Dict[str, Mapping[str, Any]] = {str(sg.get("GroupId") or ""): sg for sg in sgs if sg.get("GroupId")}

        findings: List[FindingDraft] = []
        findings.extend(self._emit_underutilized(ctx, region=region, instances=by_state["running"]))
        findings.extend(self._emit_stopped_long(ctx, region=region, ec2=ec2, instances=by_state["stopped"]))
        findings.extend(self._emit_old_generation(ctx, region=region, instances=by_state["running"] + by_state["stopped"]))
        findings.extend(self._emit_imdsv1_allowed(ctx, region=region, instances=by_state["running"] + by_state["stopped"]))
        findings.extend(self._emit_public_admin_ports(ctx, region=region, instances=by_state["running"] + by_state["stopped"], sg_by_id=sg_by_id))
        findings.extend(self._emit_t_family_credit_issues(ctx, region=region, instances=by_state["running"]))
        findings.extend(self._emit_missing_tags(ctx, region=region, instances=by_state["running"] + by_state["stopped"]))
        findings.extend(self._emit_unused_security_groups(ctx, region=region, sgs=sgs, enis=enis))

        _LOGGER.info("EC2 check complete", extra={"findings_count": len(findings), "region": region})

        return findings

    @staticmethod
    def _group_instances_by_state(instances: Sequence[Mapping[str, Any]]) -> Dict[str, List[Mapping[str, Any]]]:
        grouped: Dict[str, List[Mapping[str, Any]]] = {"running": [], "stopped": []}
        for ins in instances:
            state = str(((ins.get("State") or {}) if isinstance(ins, Mapping) else {}).get("Name") or "").lower()
            if state in grouped:
                grouped[state].append(ins)
        return grouped

    def _load_security_inventory(self, ec2: Any) -> Tuple[List[Mapping[str, Any]], List[Mapping[str, Any]]]:
        try:
            return list(self._list_security_groups(ec2)), list(self._list_network_interfaces(ec2))
        except (BotoCoreError, ClientError):
            return [], []

    # -------------------------
    # Instance listing
    # -------------------------

    def _list_instances(self, ec2: Any) -> Iterator[Mapping[str, Any]]:
        _LOGGER.debug("Fetching EC2 instances via describe_instances")
        paginator = ec2.get_paginator("describe_instances")
        for page in paginator.paginate():
            for res in page.get("Reservations", []) or []:
                for ins in (res or {}).get("Instances", []) or []:
                    if isinstance(ins, Mapping):
                        yield ins

    # -------------------------
    # Signals
    # -------------------------

    def _emit_underutilized(
        self,
        ctx: RunContext,
        *,
        region: str,
        instances: Sequence[Mapping[str, Any]],
    ) -> List[FindingDraft]:
        if not instances:
            return []

        cfg = self._cfg
        ids = [str(i.get("InstanceId") or "") for i in instances]
        ids = [i for i in ids if i]
        metrics = _fetch_utilization_metrics(ctx, region=region, instance_ids=ids, lookback_days=cfg.underutilized_lookback_days)
        if not metrics:
            return []

        out: List[FindingDraft] = []
        for ins in instances:
            iid = str(ins.get("InstanceId") or "")
            if not iid:
                continue
            m = metrics.get(iid)
            if not m:
                continue
            cpu = float(m.get("cpu_avg", 0.0))
            net_kib_h = float(m.get("net_kib_per_hour", 0.0))
            if cpu > cfg.underutilized_cpu_avg_threshold:
                continue
            if net_kib_h > cfg.underutilized_net_avg_kib_per_hour_threshold:
                continue

            itype = str(ins.get("InstanceType") or "")
            cost, conf, note = _estimate_instance_monthly_cost_usd(ctx, region=region, instance_type=itype)
            rec_type = _recommended_smaller_instance_type(itype)
            rec_cost: Optional[float] = None
            rec_conf = conf
            rec_note = ""
            rightsizing_savings: Optional[float] = None

            if rec_type:
                rec_cost, rec_conf, rec_note = _estimate_instance_monthly_cost_usd(
                    ctx,
                    region=region,
                    instance_type=rec_type,
                )
                if rec_cost is not None and cost is not None and rec_cost < cost:
                    rightsizing_savings = money(cost - rec_cost)

            recommendation = "Consider rightsizing, scheduling, or stopping this instance."
            if rec_type:
                recommendation = (
                    f"Downsize from {itype} to {rec_type} after validating workload headroom; "
                    "alternatively schedule or stop this instance if it is not needed."
                )
                if rightsizing_savings is not None:
                    recommendation = (
                        f"Downsize from {itype} to {rec_type} after validating workload headroom "
                        f"(estimated savings ~${rightsizing_savings:.2f}/month); alternatively "
                        "schedule or stop this instance if it is not needed."
                    )

            estimate_notes_parts = [part for part in (note, rec_note) if part]
            estimate_notes = "; ".join(estimate_notes_parts)
            estimate_confidence = min(int(conf), int(rec_conf)) if rec_type else int(conf)
            estimated_savings = rightsizing_savings if rightsizing_savings is not None else cost

            scope = build_scope(
                ctx,
                account=self._account,
                region=region,
                service="ec2",
                resource_type="instance",
                resource_id=iid,
                resource_arn=str(ins.get("InstanceArn") or ""),
            )

            out.append(
                FindingDraft(
                    check_id="aws.ec2.instances.underutilized",
                    check_name="EC2 underutilized running instance",
                    category="cost",
                    status="fail",
                    severity=Severity(level="medium", score=550),
                    title=f"Underutilized EC2 instance {iid}",
                    scope=scope,
                    message=(
                        f"Average CPU {cpu:.1f}% and network {net_kib_h:.1f} KiB/h over the last "
                        f"{cfg.underutilized_lookback_days} days."  # deterministic
                    ),
                    recommendation=recommendation,
                    estimated_monthly_cost=cost,
                    estimated_monthly_savings=estimated_savings,
                    estimate_confidence=estimate_confidence,
                    estimate_notes=estimate_notes,
                    dimensions={
                        "instance_type": itype,
                        "recommended_instance_type": rec_type or "",
                        "recommended_monthly_cost_usd": (f"{rec_cost:.2f}" if rec_cost is not None else ""),
                        "rightsizing_monthly_savings_usd": (
                            f"{rightsizing_savings:.2f}" if rightsizing_savings is not None else ""
                        ),
                        "cpu_avg": f"{cpu:.2f}",
                        "net_kib_per_hour": f"{net_kib_h:.2f}",
                        "lookback_days": str(cfg.underutilized_lookback_days),
                    },
                    issue_key={"instance_id": iid, "signal": "underutilized"},
                )
            )

            if len(out) >= cfg.max_findings_per_type:
                break

        return out

    def _emit_stopped_long(
        self,
        ctx: RunContext,
        *,
        region: str,
        ec2: Any,
        instances: Sequence[Mapping[str, Any]],
    ) -> List[FindingDraft]:
        if not instances:
            return []

        cfg = self._cfg
        now = now_utc()

        # Best-effort attached EBS storage estimate.
        vol_ids: List[str] = []
        for ins in instances:
            for bdm in ins.get("BlockDeviceMappings", []) or []:
                ebs = (bdm or {}).get("Ebs") if isinstance(bdm, Mapping) else None
                vid = str((ebs or {}).get("VolumeId") or "")
                if vid:
                    vol_ids.append(vid)

        vol_map: Dict[str, Mapping[str, Any]] = {}
        for batch in _chunked(vol_ids, 200):
            try:
                resp = ec2.describe_volumes(VolumeIds=batch)
            except (BotoCoreError, ClientError):
                continue
            for v in resp.get("Volumes", []) or []:
                if isinstance(v, Mapping) and v.get("VolumeId"):
                    vol_map[str(v.get("VolumeId"))] = v

        out: List[FindingDraft] = []
        for ins in instances:
            iid = str(ins.get("InstanceId") or "")
            if not iid:
                continue
            stop_ts = _parse_stop_time(str(ins.get("StateTransitionReason") or ""))
            # Fallback: if we can't parse, use LaunchTime as a weak proxy.
            if stop_ts is None:
                stop_ts = utc(ins.get("LaunchTime"))
            if stop_ts is None:
                continue
            age_days = int((now - stop_ts).total_seconds() / 86400.0)
            if age_days < int(cfg.stopped_long_age_days):
                continue

            # Sum attached volume sizes if we can.
            size_gib = 0.0
            est_storage_cost = 0.0
            for bdm in ins.get("BlockDeviceMappings", []) or []:
                ebs = (bdm or {}).get("Ebs") if isinstance(bdm, Mapping) else None
                vid = str((ebs or {}).get("VolumeId") or "")
                if not vid:
                    continue
                v = vol_map.get(vid)
                if not v:
                    continue
                try:
                    sz = float(v.get("Size") or 0.0)
                except (TypeError, ValueError):
                    sz = 0.0
                size_gib += max(sz, 0.0)
                est_storage_cost += _estimate_ebs_monthly_cost_usd(sz, str(v.get("VolumeType") or "gp2"))

            scope = build_scope(
                ctx,
                account=self._account,
                region=region,
                service="ec2",
                resource_type="instance",
                resource_id=iid,
                resource_arn=str(ins.get("InstanceArn") or ""),
            )

            out.append(
                FindingDraft(
                    check_id="aws.ec2.instances.stopped.long",
                    check_name="EC2 stopped for a long time",
                    category="cost",
                    status="fail",
                    severity=Severity(level="low", score=350),
                    title=f"Stopped EC2 instance {iid} has been stopped for {age_days} days",
                    scope=scope,
                    message=(
                        f"Instance is stopped since {stop_ts.date().isoformat()} (~{age_days} days). "
                        f"Attached storage estimate: {size_gib:.0f} GiB."  # deterministic
                    ),
                    recommendation="Terminate if not needed to avoid ongoing EBS storage costs.",
                    estimated_monthly_cost=money(est_storage_cost) if est_storage_cost > 0.0 else None,
                    estimated_monthly_savings=money(est_storage_cost) if est_storage_cost > 0.0 else None,
                    estimate_confidence=70 if est_storage_cost > 0.0 else 40,
                    estimate_notes="attached EBS storage estimate (fallback pricing)",
                    dimensions={
                        "age_days": str(age_days),
                        "stop_date": stop_ts.date().isoformat(),
                        "attached_storage_gib": f"{size_gib:.0f}",
                    },
                    issue_key={"instance_id": iid, "signal": "stopped_long"},
                )
            )

            if len(out) >= cfg.max_findings_per_type:
                break

        return out

    def _emit_old_generation(
        self,
        ctx: RunContext,
        *,
        region: str,
        instances: Sequence[Mapping[str, Any]],
    ) -> List[FindingDraft]:
        if not instances:
            return []

        cfg = self._cfg
        out: List[FindingDraft] = []
        for ins in instances:
            iid = str(ins.get("InstanceId") or "")
            itype = str(ins.get("InstanceType") or "")
            fam = _instance_family(itype)
            if not iid or not fam or fam not in _OLD_FAMILIES:
                continue

            scope = build_scope(
                ctx,
                account=self._account,
                region=region,
                service="ec2",
                resource_type="instance",
                resource_id=iid,
                resource_arn=str(ins.get("InstanceArn") or ""),
            )

            out.append(
                FindingDraft(
                    check_id="aws.ec2.instances.old.generation",
                    check_name="EC2 old generation instance family",
                    category="cost",
                    status="info",
                    severity=Severity(level="low", score=250),
                    title=f"EC2 instance {iid} uses an old generation family ({fam})",
                    scope=scope,
                    message=f"Instance type '{itype}' is an older generation family.",
                    recommendation="Plan a migration to a current generation family (e.g., t3/t4g, m6/m7, c6/c7, r6/r7).",
                    dimensions={"instance_type": itype, "family": fam},
                    issue_key={"instance_id": iid, "signal": "old_generation"},
                )
            )

            if len(out) >= cfg.max_findings_per_type:
                break

        return out

    def _emit_imdsv1_allowed(
        self,
        ctx: RunContext,
        *,
        region: str,
        instances: Sequence[Mapping[str, Any]],
    ) -> List[FindingDraft]:
        cfg = self._cfg
        out: List[FindingDraft] = []

        for ins in instances:
            iid = str(ins.get("InstanceId") or "")
            if not iid:
                continue

            meta = ins.get("MetadataOptions") if isinstance(ins.get("MetadataOptions"), Mapping) else {}
            http_tokens = str((meta or {}).get("HttpTokens") or "").lower()
            # Missing field => treat as not required (older instances)
            if http_tokens == "required":
                continue

            scope = build_scope(
                ctx,
                account=self._account,
                region=region,
                service="ec2",
                resource_type="instance",
                resource_id=iid,
                resource_arn=str(ins.get("InstanceArn") or ""),
            )

            out.append(
                FindingDraft(
                    check_id="aws.ec2.instances.security.imdsv1.allowed",
                    check_name="EC2 IMDSv1 allowed (HttpTokens not required)",
                    category="governance",
                    status="fail",
                    severity=Severity(level="high", score=800),
                    title=f"EC2 instance {iid} allows IMDSv1",
                    scope=scope,
                    message=f"MetadataOptions.HttpTokens is '{http_tokens or 'missing'}' (should be 'required').",
                    recommendation="Require IMDSv2 by setting HttpTokens=required on the instance/launch template.",
                    dimensions={"http_tokens": http_tokens or "missing"},
                    issue_key={"instance_id": iid, "signal": "imdsv1_allowed"},
                )
            )

            if len(out) >= cfg.max_findings_per_type:
                break

        return out


    def _emit_unused_security_groups(
        self,
        ctx: RunContext,
        *,
        region: str,
        sgs: Sequence[Mapping[str, Any]],
        enis: Sequence[Mapping[str, Any]],
    ) -> List[FindingDraft]:
        cfg = self._cfg
        out: List[FindingDraft] = []

        attached_sg_ids: Set[str] = set()
        for eni in enis:
            for g in (eni.get("Groups") or []):
                gid = str((g or {}).get("GroupId") or "")
                if gid:
                    attached_sg_ids.add(gid)

        # any SG involved in SG-to-SG rules (either as referrer or referenced) is considered "used"
        sg_ids_in_sg_rules: Set[str] = set()
        for sg in sgs:
            sg_id = str(sg.get("GroupId") or "")
            if not sg_id:
                continue

            # scan both ingress & egress for UserIdGroupPairs
            for perm in (sg.get("IpPermissions") or []):
                for pair in (perm or {}).get("UserIdGroupPairs", []) or []:
                    sg_ids_in_sg_rules.add(sg_id)  # the referrer SG
                    ref = str((pair or {}).get("GroupId") or "")
                    if ref:
                        sg_ids_in_sg_rules.add(ref)  # the referenced SG

            for perm in (sg.get("IpPermissionsEgress") or []):
                for pair in (perm or {}).get("UserIdGroupPairs", []) or []:
                    sg_ids_in_sg_rules.add(sg_id)
                    ref = str((pair or {}).get("GroupId") or "")
                    if ref:
                        sg_ids_in_sg_rules.add(ref)

        for sg in sgs:
            gid = str(sg.get("GroupId") or "")
            gname = str(sg.get("GroupName") or "")
            if not gid:
                continue
            if gname == "default":
                continue
            if gid in attached_sg_ids:
                continue
            if gid in sg_ids_in_sg_rules:
                continue

            scope = build_scope(
                ctx,
                account=self._account,
                region=region,
                service="ec2",
                resource_type="security-group",
                resource_id=gid,
                resource_arn=str(sg.get("GroupArn") or ""),
            )

            out.append(
                FindingDraft(
                    check_id="aws.ec2.security.groups.unused",
                    check_name="Unused security group",
                    category="governance",
                    status="fail",
                    severity=Severity(level="low", score=250),
                    title=f"Unused security group {gid}",
                    scope=scope,
                    message="Security group is not attached to any network interface and is not referenced in any SG rules.",
                    recommendation="Delete the security group if it is no longer needed.",
                    dimensions={"group_id": gid, "group_name": gname},
                    issue_key={"group_id": gid, "signal": "unused_security_group"},
                )
            )

            if len(out) >= cfg.max_findings_per_type:
                break

        return out

    

    def _perm_exposes_port_to_world(self, perm: Mapping[str, Any], port: int) -> bool:
        proto_val = perm.get("IpProtocol")
        proto = str(proto_val) if proto_val is not None else ""

        # protocol -1 == all
        if proto == "-1":
            covers = True
        else:
            fp = _to_int(perm.get("FromPort"))
            tp = _to_int(perm.get("ToPort"))
            if fp is None or tp is None:
                return False
            covers = fp <= port <= tp

        if not covers:
            return False

        for r in (perm.get("IpRanges") or []):
            cidr = str((r or {}).get("CidrIp") or "")
            if cidr == "0.0.0.0/0":
                return True

        for r in (perm.get("Ipv6Ranges") or []):
            cidr6 = str((r or {}).get("CidrIpv6") or "")
            if cidr6 == "::/0":
                return True

        return False


    def _emit_t_family_credit_issues(
        self,
        ctx: RunContext,
        *,
        region: str,
        instances: Sequence[Mapping[str, Any]],
    ) -> List[FindingDraft]:
        cfg = self._cfg

        t_instances: List[Mapping[str, Any]] = []
        t_ids: List[str] = []
        for ins in instances:
            iid = str(ins.get("InstanceId") or "")
            itype = str(ins.get("InstanceType") or "").lower()
            if iid and itype.startswith("t"):
                t_instances.append(ins)
                t_ids.append(iid)

        if not t_ids:
            return []

        metrics = _fetch_t_credit_metrics(ctx, instance_ids=t_ids, lookback_days=cfg.t_credit_lookback_days)
        if not metrics:
            return []

        out: List[FindingDraft] = []
        for ins in t_instances:
            iid = str(ins.get("InstanceId") or "")
            itype = str(ins.get("InstanceType") or "")
            m = metrics.get(iid) or {}
            bal_min = float(m.get("credit_balance_min", 0.0))
            surplus = float(m.get("surplus_charged_sum", 0.0))

            if bal_min >= cfg.t_credit_balance_min_threshold and surplus <= 0.0:
                continue

            scope = build_scope(
                ctx,
                account=self._account,
                region=region,
                service="ec2",
                resource_type="instance",
                resource_id=iid,
                resource_arn=str(ins.get("InstanceArn") or ""),
            )

            out.append(
                FindingDraft(
                    check_id="aws.ec2.instances.t.credit.issues",
                    check_name="EC2 burstable CPU credit issues",
                    category="cost",
                    status="fail",
                    severity=Severity(level="medium", score=650),
                    title=f"EC2 burstable instance {iid} shows CPU credit issues",
                    scope=scope,
                    message=(
                        f"Over last {cfg.t_credit_lookback_days} days: "
                        f"CPUCreditBalance(min)={bal_min:.1f}, CPUSurplusCreditsCharged(sum)={surplus:.1f}."
                    ),
                    recommendation="Consider moving to a larger T size, enabling Unlimited appropriately, or migrating to a non-burstable family.",
                    dimensions={
                        "instance_type": itype,
                        "credit_balance_min": f"{bal_min:.2f}",
                        "surplus_credits_charged_sum": f"{surplus:.2f}",
                        "lookback_days": str(cfg.t_credit_lookback_days),
                    },
                    issue_key={"instance_id": iid, "signal": "t_credit_issues"},
                )
            )

            if len(out) >= cfg.max_findings_per_type:
                break

        return out
    

    def _emit_missing_tags(
        self,
        ctx: RunContext,
        *,
        region: str,
        instances: Sequence[Mapping[str, Any]],
    ) -> List[FindingDraft]:
        cfg = self._cfg
        required = tuple(str(k).strip().lower() for k in cfg.required_instance_tag_keys if str(k).strip())
        if not required:
            return []

        out: List[FindingDraft] = []
        for ins in instances:
            iid = str(ins.get("InstanceId") or "")
            if not iid:
                continue

            tags = normalize_tags(ins.get("Tags"))
            missing = [k for k in required if not tags.get(k)]
            if not missing:
                continue

            scope = build_scope(
                ctx,
                account=self._account,
                region=region,
                service="ec2",
                resource_type="instance",
                resource_id=iid,
                resource_arn=str(ins.get("InstanceArn") or ""),
            )

            miss = ",".join(missing)
            out.append(
                FindingDraft(
                    check_id="aws.ec2.instances.tags.missing",
                    check_name="EC2 instance missing required tags",
                    category="governance",
                    status="fail",
                    severity=Severity(level="low", score=300),
                    title=f"EC2 instance {iid} missing required tags",
                    scope=scope,
                    message=f"Missing required tag keys: {miss}.",
                    recommendation="Apply consistent tagging (owner/env/cost_center) to improve allocation, chargeback, and automation.",
                    dimensions={"missing_tag_keys": miss},
                    issue_key={"instance_id": iid, "signal": "missing_tags"},
                )
            )

            if len(out) >= cfg.max_findings_per_type:
                break

        return out



    def _emit_public_admin_ports(
        self,
        ctx: RunContext,
        *,
        region: str,
        instances: Sequence[Mapping[str, Any]],
        sg_by_id: Mapping[str, Mapping[str, Any]],
    ) -> List[FindingDraft]:
        cfg = self._cfg
        out: List[FindingDraft] = []
        target_ports = (22, 3389)

        for ins in instances:
            iid = str(ins.get("InstanceId") or "")
            if not iid:
                continue

            sg_ids: List[str] = []
            for g in ins.get("SecurityGroups", []) or []:
                gid = str((g or {}).get("GroupId") or "")
                if gid:
                    sg_ids.append(gid)

            open_ports: Set[int] = set()
            offending_sgs: Set[str] = set()

            for gid in sg_ids:
                sg = sg_by_id.get(gid)
                if not sg:
                    continue
                for perm in sg.get("IpPermissions", []) or []:
                    if not isinstance(perm, Mapping):
                        continue
                    for p in target_ports:
                        if self._perm_exposes_port_to_world(perm, p):
                            open_ports.add(p)
                            offending_sgs.add(gid)

            if not open_ports:
                continue

            scope = build_scope(
                ctx,
                account=self._account,
                region=region,
                service="ec2",
                resource_type="instance",
                resource_id=iid,
                resource_arn=str(ins.get("InstanceArn") or ""),
            )

            ports_str = ",".join(str(p) for p in sorted(open_ports))
            sg_str = ",".join(sorted(offending_sgs)) if offending_sgs else ""

            out.append(
                FindingDraft(
                    check_id="aws.ec2.instances.security.admin.ports.open.world",
                    check_name="EC2 SSH/RDP open to the world",
                    category="governance",
                    status="fail",
                    severity=Severity(level="high", score=850),
                    title=f"EC2 instance {iid} exposes admin ports to the Internet",
                    scope=scope,
                    message=f"Security groups allow 0.0.0.0/0 or ::/0 access to ports {ports_str}.",
                    recommendation="Restrict ingress to trusted IP ranges, use VPN/bastion, and enforce least privilege SG rules.",
                    dimensions={"open_ports": ports_str, "offending_sg_ids": sg_str},
                    issue_key={"instance_id": iid, "signal": "admin_ports_open_world"},
                )
            )

            if len(out) >= cfg.max_findings_per_type:
                break

        return out

    def _list_security_groups(self, ec2: Any) -> Iterator[Mapping[str, Any]]:
        paginator = ec2.get_paginator("describe_security_groups")
        for page in paginator.paginate():
            for sg in page.get("SecurityGroups", []) or []:
                if isinstance(sg, Mapping):
                    yield sg

    def _list_network_interfaces(self, ec2: Any) -> Iterator[Mapping[str, Any]]:
        paginator = ec2.get_paginator("describe_network_interfaces")
        for page in paginator.paginate():
            for eni in page.get("NetworkInterfaces", []) or []:
                if isinstance(eni, Mapping):
                    yield eni


@register_checker("checks.aws.ec2_instances:EC2InstancesChecker")
def _factory(ctx: RunContext, bootstrap: Bootstrap) -> EC2InstancesChecker:
    """Instantiate this checker from runtime bootstrap data."""

    account_id = str(bootstrap.get("aws_account_id") or "")
    if not account_id:
        raise RuntimeError("aws_account_id missing from bootstrap (required for EC2InstancesChecker)")

    billing_account_id = str(bootstrap.get("aws_billing_account_id") or account_id)
    return EC2InstancesChecker(
        account=AwsAccountContext(account_id=account_id, billing_account_id=billing_account_id),
    )
