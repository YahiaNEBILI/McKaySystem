"""
checks/aws/rds_instances_optimizations.py

RDS Instances Optimization Checker
=================================

Emits infra-native FinOps / governance signals for Amazon RDS DB instances:

1) Stopped instances with storage cost
2) Storage overprovisioned (CloudWatch FreeStorageSpace, p95)
3) Multi-AZ enabled on non-production (tag-based)
4) Old-generation instance family (e.g., db.m3, db.m4, db.t2)
5) Engine needs upgrade (policy):
   - MySQL: 5.6 or 5.7
   - Postgres: 9 / 10 / 11
6) Unused read replicas (batched CloudWatch GetMetricData):
   - sustained near-zero ReadIOPS (p95 under threshold)
   - optional suppression tags for DR/reporting/analytics/migration

Performance Notes
-----------------
Metric collection uses CloudWatch GetMetricData with batching (up to 500 metric queries per call)
and a coarse period (default 1 day) to keep the pipeline fast and scalable.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

from botocore.exceptions import ClientError

import checks.aws._common as common

from checks.aws._common import (
    build_scope,
    AwsAccountContext,
    normalize_tags,
    money,
    safe_region_from_client,
)

from checks.registry import register_checker
from contracts.finops_checker_pattern import FindingDraft, Severity

_NONPROD_VALUES = {
    "dev", "test", "nprd", "staging", "nonprod", "non-prod", "sandbox", "qa", "uat"
}
_ENV_TAG_KEYS = {"env", "environment"}

_OLD_FAMILIES = {"m1", "m2", "m3", "m4", "r3", "r4", "t1", "t2", "x1"}

# Suppression tags for replica checks (treat as intent flags; conservative to avoid false positives)
_REPLICA_PURPOSE_KEYS = {"purpose", "role", "usage", "workload", "service", "component"}
_REPLICA_PURPOSE_VALUES = {
    "failover",
    "disaster-recovery",
    "disasterrecovery",
    "migration",
}
_GENERIC_SUPPRESS_KEYS = {"retain", "do_not_delete", "donotdelete", "keep"}
_GENERIC_SUPPRESS_VALUES = {"1", "true", "yes", "y"}


def _arn_partition(arn: str) -> str:
    try:
        parts = arn.split(":")
        if len(parts) >= 2 and parts[0] == "arn":
            return parts[1] or ""
    except (AttributeError, TypeError, ValueError):  # pragma: no cover
        return ""
    return ""


def _bytes_to_gb(b: float) -> float:
    return float(b) / (1024.0 * 1024.0 * 1024.0)


def _hours_per_month() -> float:
    """Average hours per month (365 days / 12 * 24)."""
    return (365.0 / 12.0) * 24.0


def _resolve_rds_instance_hour_price(
    ctx: Any,
    *,
    region: str,
    db_instance_class: str,
    deployment_option: str,
    engine: str,
    license_model: str,
) -> Tuple[Optional[float], str, int]:
    """Best-effort pricing lookup for an RDS instance hourly on-demand price.

    Returns (hourly_price_usd, notes, confidence).

    - hourly_price_usd is None when unknown.
    - confidence is a rough indicator used in findings (0-100).
    """

    pricing = getattr(getattr(ctx, "services", None), "pricing", None)
    if pricing is None:
        return (None, "PricingService unavailable; leaving instance pricing unknown.", 20)

    try:
        quote = pricing.rds_instance_hour(
            region=region,
            db_instance_class=db_instance_class,
            deployment_option=deployment_option,
            database_engine=engine or None,
            license_model=license_model or None,
        )
    except (AttributeError, TypeError, ValueError):
        quote = None

    if quote is None:
        return (None, "Pricing lookup failed/unknown; leaving instance pricing unknown.", 20)

    conf = 70 if str(quote.source) == "pricing_api" else 60
    return (
        float(quote.unit_price_usd),
        f"PricingService {quote.source} as_of={quote.as_of.isoformat()} unit={quote.unit}",
        conf,
    )


def _percentile(values: Sequence[float], p: float) -> Optional[float]:
    if not values:
        return None
    vals = sorted(values)
    if p <= 0:
        return vals[0]
    if p >= 100:
        return vals[-1]
    k = (len(vals) - 1) * (p / 100.0)
    f = int(k)
    c = min(f + 1, len(vals) - 1)
    if f == c:
        return vals[f]
    return vals[f] * (c - k) + vals[c] * (k - f)


def _extract_tags(tag_list: Sequence[Dict[str, Any]]) -> Dict[str, str]:
    # Normalize into lower-cased keys/values for consistent suppression and environment checks.
    return normalize_tags(tag_list)


def _is_non_prod(tags: Dict[str, str]) -> bool:
    # tags are already normalized by normalize_tags (lower-cased keys and values)
    for k, v in tags.items():
        if k in _ENV_TAG_KEYS and v in {"prod", "production"}:
            return False
    for k, v in tags.items():
        if k in _ENV_TAG_KEYS and v in _NONPROD_VALUES:
            return True
    return False


def _family_from_instance_class(db_instance_class: str) -> str:
    # "db.m3.large" -> "m3"
    txt = str(db_instance_class or "")
    if not txt.startswith("db."):
        return ""
    parts = txt.split(".")
    return parts[1] if len(parts) >= 3 else ""


def _norm_engine(engine: str) -> str:
    return (engine or "").strip().lower()


def _parse_major_minor(version: str) -> Optional[Tuple[int, int]]:
    s = (version or "").strip()
    if not s:
        return None

    parts = s.split(".", 2)
    try:
        major_txt = parts[0]
        minor_txt = parts[1] if len(parts) > 1 else "0"

        # keep leading digits only (handles '13beta1', '8a', etc.)
        def _lead_int(x: str) -> int:
            x = x.strip()
            i = 0
            while i < len(x) and x[i].isdigit():
                i += 1
            if i == 0:
                raise ValueError("no digits")
            return int(x[:i])

        return (_lead_int(major_txt), _lead_int(minor_txt))
    except ValueError:
        return None


def _engine_needs_upgrade(
    *,
    engine: str,
    engine_version: str,
    mysql_blocked_prefixes: Sequence[str],
    postgres_min_version: Optional[Tuple[int, int]],
    mariadb_min_version: Optional[Tuple[int, int]],
) -> bool:
    """
    Return True when engine/version is flagged as outdated by local policy.

    Rules:
    - MySQL: needs upgrade if version starts with any blocked prefix (e.g. '5.6', '5.7')
    - Postgres / MariaDB: needs upgrade if parsed (major, minor) < configured minimum
    """
    eng = _norm_engine(engine)
    ver = (engine_version or "").strip()

    # --- MySQL (and Aurora MySQL variants if you want) ---
    if "mysql" in eng:
        # Keep it prefix-based: supports '5.7.44', '5.6.51', etc.
        if mysql_blocked_prefixes and ver:
            return any(ver.startswith(pfx) for pfx in mysql_blocked_prefixes)
        return False

    if "postgres" in eng and postgres_min_version is not None:
        parsed = _parse_major_minor(ver)
        if parsed is None:
            return False
        return parsed < postgres_min_version

    if "mariadb" in eng and mariadb_min_version is not None:
        parsed = _parse_major_minor(ver)
        if parsed is None:
            return False
        return parsed < mariadb_min_version

    return False


def _is_aurora_engine(engine: str) -> bool:
    return "aurora" in (engine or "").lower()


def _tag_suppresses_replica_check(tags: Dict[str, str]) -> bool:
    # Any explicit keep/retain flags
    for k, v in tags.items():
        kk = str(k or "").strip().lower()
        vv = str(v or "").strip().lower()
        if kk in _GENERIC_SUPPRESS_KEYS and vv in _GENERIC_SUPPRESS_VALUES:
            return True

    # Purpose/role tags indicating intended replica usage
    for k, v in tags.items():
        kk = str(k or "").strip().lower()
        vv = str(v or "").strip().lower()
        if kk in _REPLICA_PURPOSE_KEYS and vv.replace("_", "-") in _REPLICA_PURPOSE_VALUES:
            return True
        if kk in _REPLICA_PURPOSE_KEYS and vv in _REPLICA_PURPOSE_VALUES:
            return True
    return False


class _CloudWatchBatchMetrics:
    """
    Fetch per-instance time series metrics using CloudWatch GetMetricData in large batches.

    Returns raw values for each instance so caller can compute percentiles and apply rules.
    """

    def __init__(self, cw: Any) -> None:
        self._cw = cw
        # Cache within a run: (metric, stat, period, start_iso, end_iso, instance_id) -> values
        self._cache: Dict[Tuple[str, str, int, str, str, str], List[float]] = {}

    def fetch_values_by_instance(
        self,
        *,
        namespace: str,
        metric_name: str,
        stat: str,
        period: int,
        start: datetime,
        end: datetime,
        instance_ids: Sequence[str],
    ) -> Dict[str, List[float]]:
        start_key = start.isoformat()
        end_key = end.isoformat()

        results: Dict[str, List[float]] = {}
        to_query: List[str] = []

        for iid in instance_ids:
            key = (metric_name, stat, period, start_key, end_key, iid)
            cached = self._cache.get(key)
            if cached is not None:
                results[iid] = list(cached)
            else:
                to_query.append(iid)

        if not to_query:
            return results

        # Build metric queries, 1 query per instance (keep query count low).
        # Max 500 per call; we batch at 400 for safer payload sizing.
        batch_size = 400
        for i in range(0, len(to_query), batch_size):
            batch = to_query[i : i + batch_size]
            metric_data_queries: List[Dict[str, Any]] = []
            id_to_instance: Dict[str, str] = {}

            for idx, iid in enumerate(batch):
                qid = f"m{idx}"
                id_to_instance[qid] = iid
                metric_data_queries.append(
                    {
                        "Id": qid,
                        "MetricStat": {
                            "Metric": {
                                "Namespace": namespace,
                                "MetricName": metric_name,
                                "Dimensions": [{"Name": "DBInstanceIdentifier", "Value": iid}],
                            },
                            "Period": period,
                            "Stat": stat,
                        },
                        "ReturnData": True,
                    }
                )

            next_token: Optional[str] = None
            # Paginate GetMetricData if needed
            while True:
                kwargs: Dict[str, Any] = {
                    "MetricDataQueries": metric_data_queries,
                    "StartTime": start,
                    "EndTime": end,
                    "ScanBy": "TimestampAscending",
                }
                if next_token:
                    kwargs["NextToken"] = next_token

                resp = self._cw.get_metric_data(**kwargs)
                for r in resp.get("MetricDataResults", []) or []:
                    qid = str(r.get("Id") or "")
                    iid = id_to_instance.get(qid)
                    if not iid:
                        continue
                    vals = r.get("Values", []) or []
                    numbers: List[float] = []
                    for v in vals:
                        if isinstance(v, (int, float)):
                            numbers.append(float(v))
                    # Merge pages: append
                    results.setdefault(iid, []).extend(numbers)

                next_token = resp.get("NextToken")
                if not next_token:
                    break

        # Write to cache
        for iid, vals in results.items():
            key = (metric_name, stat, period, start_key, end_key, iid)
            self._cache[key] = list(vals)

        # Ensure all requested instance_ids appear in dict (maybe empty)
        for iid in instance_ids:
            results.setdefault(iid, [])

        return results


class RDSInstancesOptimizationsChecker:
    checker_id = "aws.rds.instances.optimizations"

    def __init__(
        self,
        *,
        account: AwsAccountContext,
        storage_gb_month_price_usd: float = 0.115,
        storage_window_days: int = 14,
        storage_period_seconds: int = 86400,
        overprov_used_ratio_threshold: float = 0.40,
        overprov_min_excess_gb: float = 20.0,
        replica_unused_window_days: int = 14,
        replica_period_seconds: int = 86400,
        replica_read_iops_p95_threshold: float = 0.1,
        replica_min_datapoints: int = 7,  # at least ~1 week with daily period
        storage_min_datapoints: Optional[int] = None,
        storage_min_coverage_ratio: float = 0.60,
        replica_min_coverage_ratio: float = 0.60,
        mysql_blocked_prefixes: Sequence[str] = ("5.6", "5.7"),
        postgres_min_version: Optional[tuple[int, int]] = (12, 0),
        mariadb_min_version: Optional[tuple[int, int]]= (10, 6),
    ) -> None:
        self._account = account
        self._storage_gb_month_price_usd = float(storage_gb_month_price_usd)
        self._storage_window_days = int(storage_window_days)
        self._storage_period_seconds = int(storage_period_seconds)
        self._overprov_used_ratio_threshold = float(overprov_used_ratio_threshold)
        self._overprov_min_excess_gb = float(overprov_min_excess_gb)

        self._replica_unused_window_days = int(replica_unused_window_days)
        self._replica_period_seconds = int(replica_period_seconds)
        self._replica_read_iops_p95_threshold = float(replica_read_iops_p95_threshold)
        self._replica_min_datapoints = int(replica_min_datapoints)
        self._storage_min_datapoints = int(storage_min_datapoints) if storage_min_datapoints is not None else None
        self._storage_min_coverage_ratio = float(storage_min_coverage_ratio)
        self._replica_min_coverage_ratio = float(replica_min_coverage_ratio)
        self._mysql_blocked_prefixes = tuple(str(x) for x in mysql_blocked_prefixes)
        self._postgres_min_version = (
            (int(postgres_min_version[0]), int(postgres_min_version[1]))
            if postgres_min_version is not None
            else None
        )

        self._mariadb_min_version = (
            (int(mariadb_min_version[0]), int(mariadb_min_version[1]))
            if mariadb_min_version is not None
            else None
        )

    def run(self, ctx) -> Iterable[FindingDraft]:
        if not getattr(ctx, "services", None) or not getattr(ctx.services, "rds", None):
            raise RuntimeError("RDSInstancesOptimizationsChecker requires ctx.services.rds")

        rds = ctx.services.rds
        cw = getattr(ctx.services, "cloudwatch", None)
        region = safe_region_from_client(rds)

        try:
            instances = list(self._list_db_instances(rds))
        except ClientError as exc:
            yield self._access_error(ctx, region, "describe_db_instances", exc)
            return

        # Pre-fetch metrics in batches for performance.
        metric_fetcher: Optional[_CloudWatchBatchMetrics] = _CloudWatchBatchMetrics(cw) if cw is not None else None

        # Build lists for metric queries.
        ids_for_storage: List[str] = []
        ids_for_replicas: List[str] = []
        inst_by_id: Dict[str, Dict[str, Any]] = {}

        # Cache tags by ARN (list_tags_for_resource can be throttled).
        tags_by_arn: Dict[str, Dict[str, str]] = {}

        def get_tags(arn: str) -> Dict[str, str]:
            if not arn:
                return {}
            if arn in tags_by_arn:
                return tags_by_arn[arn]
            try:
                resp = rds.list_tags_for_resource(ResourceName=arn)
                tags = _extract_tags(resp.get("TagList", []) or [])
            except ClientError:
                tags = {}
            tags_by_arn[arn] = tags
            return tags

        # First pass: collect instances and identify metric candidates.
        replica_candidates: List[str] = []
        now_ts = common.now_utc()

        for inst in instances:
            instance_id = str(inst.get("DBInstanceIdentifier") or "")
            if not instance_id:
                continue
            inst_by_id[instance_id] = inst

            allocated_gb = float(inst.get("AllocatedStorage") or 0.0)
            if metric_fetcher is not None and allocated_gb > 0:
                ids_for_storage.append(instance_id)

            if metric_fetcher is not None and self._is_read_replica(inst) and not _is_aurora_engine(str(inst.get("Engine") or "")):
                status = str(inst.get("DBInstanceStatus") or "").lower()
                if status != "available":
                    continue
                created = inst.get("InstanceCreateTime")
                if isinstance(created, datetime):
                    created_ts = created.replace(tzinfo=created.tzinfo or timezone.utc)
                    if created_ts > (now_ts - timedelta(days=7)):
                        continue
                replica_candidates.append(instance_id)

        # Resolve replica suppression tags *before* querying CloudWatch to reduce noise and cost.
        for instance_id in replica_candidates:
            inst = inst_by_id.get(instance_id, {})
            arn = str(inst.get("DBInstanceArn") or "")
            tags = get_tags(arn)
            if _tag_suppresses_replica_check(tags):
                continue
            ids_for_replicas.append(instance_id)

        # Tags are only needed for checks that use them (Multi-AZ non-prod, replica suppression),
        # so we avoid fetching tags for every instance.
        tags_by_id: Dict[str, Dict[str, str]] = {}

        storage_metrics: Dict[str, List[float]] = {}
        replica_read_iops: Dict[str, List[float]] = {}
        replica_connections: Dict[str, List[float]] = {}

        if metric_fetcher is not None and ids_for_storage:
            end = common.now_utc()
            start = end - timedelta(days=self._storage_window_days)
            try:
                storage_metrics = metric_fetcher.fetch_values_by_instance(
                    namespace="AWS/RDS",
                    metric_name="FreeStorageSpace",
                    stat="Average",
                    period=self._storage_period_seconds,
                    start=start,
                    end=end,
                    instance_ids=ids_for_storage,
                )
            except ClientError as exc:
                yield self._access_error(ctx, region, "cloudwatch:GetMetricData FreeStorageSpace", exc)
                storage_metrics = {iid: [] for iid in ids_for_storage}

        if metric_fetcher is not None and ids_for_replicas:
            end = common.now_utc()
            start = end - timedelta(days=self._replica_unused_window_days)
            try:
                replica_read_iops = metric_fetcher.fetch_values_by_instance(
                    namespace="AWS/RDS",
                    metric_name="ReadIOPS",
                    stat="Average",
                    period=self._replica_period_seconds,
                    start=start,
                    end=end,
                    instance_ids=ids_for_replicas,
                )
                # Connections is optional evidence; never required to trigger.
                replica_connections = metric_fetcher.fetch_values_by_instance(
                    namespace="AWS/RDS",
                    metric_name="DatabaseConnections",
                    stat="Average",
                    period=self._replica_period_seconds,
                    start=start,
                    end=end,
                    instance_ids=ids_for_replicas,
                )
            except ClientError as exc:
                yield self._access_error(ctx, region, "cloudwatch:GetMetricData replica metrics", exc)
                replica_read_iops = {iid: [] for iid in ids_for_replicas}
                replica_connections = {iid: [] for iid in ids_for_replicas}

        # Evaluate instance-level checks
        for instance_id, inst in inst_by_id.items():
            tags = tags_by_id.get(instance_id)
            if tags is None:
                arn = str(inst.get("DBInstanceArn") or "")
                needs_tags = bool(inst.get("MultiAZ", False)) or instance_id in ids_for_replicas
                tags = get_tags(arn) if needs_tags else {}
                tags_by_id[instance_id] = tags
            yield from self._evaluate_instance(
                ctx=ctx,
                inst=inst,
                tags=tags,
                region=region,
                free_storage_values=storage_metrics.get(instance_id, []),
                replica_read_iops_values=replica_read_iops.get(instance_id, []),
                replica_conn_values=replica_connections.get(instance_id, []),
            )

    def _list_db_instances(self, rds: Any) -> Iterator[Dict[str, Any]]:
        paginator = rds.get_paginator("describe_db_instances")
        for page in paginator.paginate():
            for inst in page.get("DBInstances", []) or []:
                if isinstance(inst, dict):
                    yield inst

    def _is_read_replica(self, inst: Dict[str, Any]) -> bool:
        # On replicas, this key is typically present.
        src = inst.get("ReadReplicaSourceDBInstanceIdentifier")
        if src:
            return True
        # Some cases have ReadReplicaDBInstanceIdentifiers on primary, not the replica.
        return False

    def _evaluate_instance(
        self,
        *,
        ctx: Any,
        inst: Dict[str, Any],
        tags: Dict[str, str],
        region: str,
        free_storage_values: Sequence[float],
        replica_read_iops_values: Sequence[float],
        replica_conn_values: Sequence[float],
    ) -> Iterable[FindingDraft]:
        instance_id = str(inst.get("DBInstanceIdentifier") or "")
        arn = str(inst.get("DBInstanceArn") or "")
        partition = _arn_partition(arn) or self._account.partition
        scope = build_scope(
            ctx,
            account=AwsAccountContext(
                account_id=self._account.account_id,
                billing_account_id=str(self._account.billing_account_id or self._account.account_id),
                partition=partition,
            ),
            region=region,
            service="rds",
            resource_type="db_instance",
            resource_id=instance_id,
            resource_arn=arn,
        )

        status = str(inst.get("DBInstanceStatus") or "").lower()
        allocated_gb = float(inst.get("AllocatedStorage") or 0.0)
        multi_az = bool(inst.get("MultiAZ", False))
        instance_class = str(inst.get("DBInstanceClass") or "")
        engine = str(inst.get("Engine") or "")
        engine_version = str(inst.get("EngineVersion") or "")
        license_model = str(inst.get("LicenseModel") or "")

        # 1) stopped_instances_with_storage
        if status == "stopped" and allocated_gb > 0:
            monthly_cost = allocated_gb * self._storage_gb_month_price_usd
            # Optional context: what it would cost if running (does not change savings for a stopped instance).
            dep = "Multi-AZ" if multi_az else "Single-AZ"
            hourly_run, hourly_notes, hourly_conf = _resolve_rds_instance_hour_price(
                ctx,
                region=region,
                db_instance_class=instance_class,
                deployment_option=dep,
                engine=engine,
                license_model=license_model,
            )
            running_monthly = (float(hourly_run) * _hours_per_month()) if hourly_run is not None else None
            yield FindingDraft(
                check_id="aws.rds.instances.stopped_storage",
                check_name="RDS stopped instances still incur storage cost",
                category="cost",
                sub_category="waste",
                status="fail",
                severity=Severity(level="medium", score=500),
                title=f"Stopped RDS instance still incurs storage cost: {instance_id}",
                scope=scope,
                message=(
                    f"DB instance '{instance_id}' is 'stopped' but still has {allocated_gb:.0f} GB allocated storage."
                ),
                recommendation=(
                    "If the instance is no longer needed, delete it (after snapshot/backup as required). "
                    "If it must remain stopped, review storage footprint and snapshot retention."
                ),
                estimated_monthly_cost=money(monthly_cost),
                estimated_monthly_savings=money(monthly_cost),
                estimate_confidence=60,
                estimate_notes="AllocatedStorage GB * default USD/GB-month. Excludes I/O and backup charges.",
                tags=tags,
                dimensions={
                    "allocated_gb": f"{allocated_gb:.0f}",
                    "status": status,
                    "deployment": ("multi_az" if multi_az else "single_az"),
                    "if_running_monthly_cost_usd": (f"{running_monthly:.2f}" if running_monthly is not None else ""),
                    "pricing_notes": (hourly_notes if hourly_run is not None else ""),
                    "pricing_confidence": (str(hourly_conf) if hourly_run is not None else ""),
                },
            ).with_issue(check="stopped_storage", account_id=self._account.account_id, region=region, resource_type="db_instance", resource_id=instance_id, db_instance=instance_id)

        # 2) storage_overprovisioned (uses pre-fetched FreeStorageSpace values)
        if allocated_gb > 0:
            overprov = self._storage_overprovisioned_from_values(
                allocated_gb=allocated_gb,
                free_storage_avg_bytes=free_storage_values,
            )
            if overprov is not None:
                used_gb, p95_free_gb, excess_gb, dp_count, p50_free_gb, min_free_gb = overprov
                monthly_savings = excess_gb * self._storage_gb_month_price_usd
                yield FindingDraft(
                    check_id="aws.rds.storage.overprovisioned",
                    check_name="RDS storage overprovisioned",
                    category="cost",
                    sub_category="rightsizing",
                    status="fail",
                    severity=Severity(level="low", score=350),
                    title=f"RDS allocated storage appears overprovisioned: {instance_id}",
                    scope=scope,
                    message=(
                        f"Allocated={allocated_gb:.0f} GB; estimated used ~{used_gb:.1f} GB "
                        f"(p95 free ~{p95_free_gb:.1f} GB over {self._storage_window_days}d)."
                    ),
                    recommendation=(
                        "RDS storage typically cannot be reduced in-place. Consider snapshot+restore to a smaller size, "
                        "or rebuild with lower allocation. If enabled, use storage autoscaling with sensible limits."
                    ),
                    estimated_monthly_savings=money(monthly_savings),
                    estimated_monthly_cost=0.0,
                    estimate_confidence=70,
                    estimate_notes=(
                        "Excess GB inferred from FreeStorageSpace p95 * default USD/GB-month; "
                        "savings depend on migration feasibility."
                    ),
                    tags=tags,
                    dimensions={
                        "allocated_gb": f"{allocated_gb:.0f}",
                        "estimated_used_gb": f"{used_gb:.1f}",
                        "p95_free_gb": f"{p95_free_gb:.1f}",
                        "p50_free_gb": f"{p50_free_gb:.1f}",
                        "min_free_gb": f"{min_free_gb:.1f}",
                        "window_days": str(self._storage_window_days),
                        "period_seconds": str(self._storage_period_seconds),
                        "datapoints": str(dp_count),
                    },
                ).with_issue(check="storage_overprovisioned", account_id=self._account.account_id, region=region, resource_type="db_instance", resource_id=instance_id, db_instance=instance_id)

        # 3) multi_az_non_prod
        if multi_az and _is_non_prod(tags):
            # Best-effort savings estimate: Multi-AZ vs Single-AZ hourly delta.
            hrs = _hours_per_month()
            hz_multi, notes_multi, conf_multi = _resolve_rds_instance_hour_price(
                ctx,
                region=region,
                db_instance_class=instance_class,
                deployment_option="Multi-AZ",
                engine=engine,
                license_model=license_model,
            )
            hz_single, notes_single, conf_single = _resolve_rds_instance_hour_price(
                ctx,
                region=region,
                db_instance_class=instance_class,
                deployment_option="Single-AZ",
                engine=engine,
                license_model=license_model,
            )

            monthly_savings = 0.0
            monthly_cost = 0.0
            confidence = 30
            estimate_notes = "Accurate savings requires instance pricing; this is a configuration signal without CUR."

            if hz_multi is not None and hz_single is not None:
                # Multi-AZ hourly is typically higher; we report the delta as a potential savings.
                delta = max(0.0, float(hz_multi) - float(hz_single))
                monthly_savings = delta * hrs
                monthly_cost = float(hz_multi) * hrs
                confidence = min(80, max(conf_multi, conf_single))
                estimate_notes = (
                    f"Estimated delta=(Multi-AZ - Single-AZ) * {hrs:.1f}h/mo. "
                    f"multi: {notes_multi}; single: {notes_single}"
                )

            yield FindingDraft(
                check_id="aws.rds.multi_az.non_prod",
                check_name="RDS Multi-AZ enabled on non-production",
                category="cost",
                sub_category="configuration",
                status="fail",
                severity=Severity(level="medium", score=520),
                title=f"Multi-AZ enabled on non-prod RDS instance: {instance_id}",
                scope=scope,
                message="Multi-AZ is enabled and the instance appears to be non-production based on env tags.",
                recommendation="If HA is not required in non-prod, consider Single-AZ after validating compliance/DR needs.",
                estimated_monthly_savings=money(monthly_savings),
                estimated_monthly_cost=money(monthly_cost),
                estimate_confidence=confidence,
                estimate_notes=estimate_notes,
                tags=tags,
            ).with_issue(check="multi_az_non_prod", account_id=self._account.account_id, region=region, resource_type="db_instance", resource_id=instance_id, db_instance=instance_id)

        # 4) instance_family_old_generation
        fam = _family_from_instance_class(instance_class)
        if fam in _OLD_FAMILIES:
            yield FindingDraft(
                check_id="aws.rds.instance_family.old_generation",
                check_name="RDS old-generation instance family",
                category="cost",
                sub_category="modernization",
                status="fail",
                severity=Severity(level="low", score=320),
                title=f"Old-generation RDS instance family detected: {instance_id}",
                scope=scope,
                message=f"Instance class is '{instance_class}' (family '{fam}'), which is considered old-generation.",
                recommendation=(
                    "Evaluate migrating to a newer generation (e.g., m6g/m7g, r6g/r7g, m6i/m7i) "
                    "for better price/perf. Validate compatibility and performance before changing."
                ),
                estimated_monthly_savings=0.0,
                estimated_monthly_cost=0.0,
                estimate_confidence=20,
                estimate_notes="Modernization opportunity; savings not estimated without pricing enrichment.",
                tags=tags,
                dimensions={"instance_class": instance_class, "family": fam},
            ).with_issue(check="old_generation_family", account_id=self._account.account_id, region=region, resource_type="db_instance", resource_id=instance_id, db_instance=instance_id, family=fam)

        # 5) needs_engine_upgrade (policy)
        if _engine_needs_upgrade(engine=engine, engine_version=engine_version, mysql_blocked_prefixes=self._mysql_blocked_prefixes, 
                                 postgres_min_version=self._postgres_min_version, mariadb_min_version=self._mariadb_min_version):
            yield FindingDraft(
                check_id="aws.rds.engine.needs_upgrade",
                check_name="RDS engine version needs upgrade",
                category="governance",
                sub_category="lifecycle",
                status="fail",
                severity=Severity(level="high", score=750),
                title=f"RDS engine version is outdated: {instance_id}",
                scope=scope,
                message=f"Engine '{engine}' version '{engine_version}' is flagged as needing upgrade by policy.",
                recommendation="Plan an upgrade to a supported major version; test in staging and validate app compatibility.",
                estimated_monthly_savings=0.0,
                estimated_monthly_cost=0.0,
                estimate_confidence=40,
                estimate_notes="Policy-based governance signal. Extended support cost not computed without a maintained dataset.",
                tags=tags,
                dimensions={"engine": engine, "engine_version": engine_version},
            ).with_issue(check="engine_upgrade", account_id=self._account.account_id, region=region, resource_type="db_instance", resource_id=instance_id, db_instance=instance_id, engine=engine, engine_version=engine_version)

        # 6) unused read replica (batched ReadIOPS values)
        if self._is_read_replica(inst) and not _is_aurora_engine(engine) and not _tag_suppresses_replica_check(tags):
            if status == "available":
                rr = self._unused_read_replica_from_values(
                    read_iops_values=replica_read_iops_values,
                    conn_values=replica_conn_values,
                )
                if rr is not None:
                    p95_read_iops, dp_count, p95_conns = rr
                    # Cost is meaningful with PricingService; if available we emit a best-effort savings estimate.
                    hrs = _hours_per_month()
                    dep = "Multi-AZ" if multi_az else "Single-AZ"
                    hourly, notes, conf = _resolve_rds_instance_hour_price(
                        ctx,
                        region=region,
                        db_instance_class=instance_class,
                        deployment_option=dep,
                        engine=engine,
                        license_model=license_model,
                    )
                    est_cost = 0.0
                    est_savings = 0.0
                    est_conf = 70
                    est_notes = (
                        "Signal based on CloudWatch ReadIOPS. Accurate savings requires instance pricing enrichment."
                    )
                    if hourly is not None:
                        est_cost = float(hourly) * hrs
                        est_savings = est_cost
                        est_conf = min(90, max(70, conf))
                        est_notes = f"Estimated on-demand instance cost * {hrs:.1f}h/mo. {notes}"

                    yield FindingDraft(
                        check_id="aws.rds.read_replica.unused",
                        check_name="RDS unused read replica",
                        category="cost",
                        sub_category="waste",
                        status="fail",
                        severity=Severity(level="medium", score=560),
                        title=f"Read replica appears unused (near-zero reads): {instance_id}",
                        scope=scope,
                        message=(
                            f"Replica shows near-zero read activity (p95 ReadIOPS={p95_read_iops:.3f}) "
                            f"over {self._replica_unused_window_days}d."
                        ),
                        recommendation=(
                            "Confirm the replica is not required for DR/reporting/migration. "
                            "If unused, consider deleting it, or keeping it only during reporting windows."
                        ),
                        estimated_monthly_savings=money(est_savings),
                        estimated_monthly_cost=money(est_cost),
                        estimate_confidence=est_conf,
                        estimate_notes=est_notes,
                        tags=tags,
                        dimensions={
                            "window_days": str(self._replica_unused_window_days),
                            "period_seconds": str(self._replica_period_seconds),
                            "datapoints": str(dp_count),
                            "p95_read_iops": f"{p95_read_iops:.6f}",
                            "p95_connections": (f"{p95_conns:.3f}" if p95_conns is not None else ""),
                            "replica_source": str(inst.get("ReadReplicaSourceDBInstanceIdentifier") or ""),
                        },
                    ).with_issue(check="unused_read_replica", account_id=self._account.account_id, region=region, resource_type="db_instance", resource_id=instance_id, db_instance=instance_id)

    def _expected_datapoints(self, *, window_days: int, period_seconds: int) -> int:
        if window_days <= 0 or period_seconds <= 0:
            return 0
        return int(round((float(window_days) * 86400.0) / float(period_seconds)))

    def _min_required_datapoints(self, *, expected: int, absolute_min: int, coverage_ratio: float) -> int:
        if expected <= 0:
            return absolute_min
        # Allow some gaps; require a fraction of expected points.
        return max(absolute_min, int(expected * float(coverage_ratio)))

    def _storage_overprovisioned_from_values(
        self,
        *,
        allocated_gb: float,
        free_storage_avg_bytes: Sequence[float],
    ) -> Optional[Tuple[float, float, float, int, float, float]]:
        values = [float(v) for v in free_storage_avg_bytes if isinstance(v, (int, float))]
        expected = self._expected_datapoints(window_days=self._storage_window_days, period_seconds=self._storage_period_seconds)
        req = self._storage_min_datapoints if self._storage_min_datapoints is not None else self._min_required_datapoints(
            expected=expected,
            absolute_min=7,
            coverage_ratio=self._storage_min_coverage_ratio,
        )
        if len(values) < req:
            return None

        p95_free_bytes = _percentile(values, 95.0)
        p50_free_bytes = _percentile(values, 50.0)
        min_free_bytes = min(values) if values else None
        if p95_free_bytes is None or p50_free_bytes is None or min_free_bytes is None:
            return None

        p95_free_gb = max(0.0, _bytes_to_gb(float(p95_free_bytes)))
        p50_free_gb = max(0.0, _bytes_to_gb(float(p50_free_bytes)))
        min_free_gb = max(0.0, _bytes_to_gb(float(min_free_bytes)))

        used_gb = max(0.0, float(allocated_gb) - p95_free_gb)
        used_ratio = used_gb / float(allocated_gb) if allocated_gb > 0 else 1.0
        if used_ratio >= self._overprov_used_ratio_threshold:
            return None

        target_floor = float(allocated_gb) * self._overprov_used_ratio_threshold
        excess_gb = max(0.0, float(allocated_gb) - max(used_gb, target_floor))
        if excess_gb < self._overprov_min_excess_gb:
            return None

        return (used_gb, p95_free_gb, excess_gb, len(values), p50_free_gb, min_free_gb)

    def _unused_read_replica_from_values(
        self,
        *,
        read_iops_values: Sequence[float],
        conn_values: Sequence[float],
    ) -> Optional[Tuple[float, int, Optional[float]]]:
        reads = [float(v) for v in read_iops_values if isinstance(v, (int, float))]
        expected = self._expected_datapoints(window_days=self._replica_unused_window_days, period_seconds=self._replica_period_seconds)
        req = self._min_required_datapoints(expected=expected, absolute_min=self._replica_min_datapoints, coverage_ratio=self._replica_min_coverage_ratio)
        if len(reads) < req:
            return None

        p95_read = _percentile(reads, 95.0)
        if p95_read is None:
            return None

        if float(p95_read) >= self._replica_read_iops_p95_threshold:
            return None

        conns = [float(v) for v in conn_values if isinstance(v, (int, float))]
        p95_conns = _percentile(conns, 95.0) if conns else None

        return (float(p95_read), len(reads), p95_conns)

    def _access_error(self, ctx: Any, region: str, action: str, exc: ClientError) -> FindingDraft:
        code = ""
        try:
            code = str(exc.response.get("Error", {}).get("Code", ""))
        except (AttributeError, TypeError, ValueError):  # pragma: no cover
            code = ""

        scope = build_scope(
            ctx,
            account=self._account,
            region=region,
            service="rds",
            resource_type="account",
            resource_id=self._account.account_id,
            resource_arn="",
        )
        
        return FindingDraft(
            check_id="aws.rds.instances.access_error",
            check_name="RDS access error",
            category="governance",
            status="info",
            severity=Severity(level="info", score=0),
            title="RDS permissions missing for instances optimization checks",
            scope=scope,
            message=f"Access denied calling {action} in region '{region}'. ErrorCode={code}",
            recommendation=(
                "Grant rds:DescribeDBInstances, rds:ListTagsForResource, cloudwatch:GetMetricData "
                "(and optionally cloudwatch:GetMetricStatistics)."
            ),
            estimated_monthly_cost=0.0,
            estimated_monthly_savings=0.0,
            estimate_confidence=0,
            estimate_notes="Informational finding emitted when permissions are missing.",
        ).with_issue(check="access_error", account_id=self._account.account_id, region=region, resource_type="account", resource_id=self._account.account_id, action=action)


SPEC = "checks.aws.rds_instances_optimizations:RDSInstancesOptimizationsChecker"


@register_checker(SPEC)
def _factory(ctx: Any, bootstrap: Dict[str, Any]) -> RDSInstancesOptimizationsChecker:
    account_id = str(bootstrap.get("aws_account_id") or "")
    billing_id = str(bootstrap.get("aws_billing_account_id") or account_id)
    if not account_id:
        raise ValueError("bootstrap missing aws_account_id")

    return RDSInstancesOptimizationsChecker(
        account=AwsAccountContext(account_id=account_id, billing_account_id=billing_id),
    )
