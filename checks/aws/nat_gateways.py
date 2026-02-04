"""
checks/aws/nat_gateways.py

NAT Gateway cost + hygiene checker.

Signals (cost / optimization):
1) Idle NAT Gateways (best-effort via CloudWatch)
   - Low or near-zero traffic over a lookback window (p95 daily bytes < threshold)
2) High data processing on NAT Gateways (heuristic)
   - Large monthly-equivalent traffic suggests adding VPC Endpoints
     (S3/DynamoDB gateway endpoints, interface endpoints for common AWS services)

Signals (hygiene / correctness):
3) Unreferenced NAT Gateways (orphaned)
   - NAT Gateway not referenced by any route table route (best-effort)
4) Cross-AZ NAT usage (cost + resilience smell)
   - A subnet route table in AZ-A points to a NAT Gateway in AZ-B (best-effort)

Notes
-----
- Uses EC2 APIs for inventory (DescribeNatGateways / DescribeRouteTables / DescribeSubnets).
- Uses CloudWatch metrics in namespace "AWS/NATGateway" to estimate utilization.
- Estimates are directional; CUR enrichment should refine costs downstream.
- This checker runs in the region configured by ``ctx.services.ec2``.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Dict, Iterable, Iterator, List, Mapping, Optional, Sequence, Set, Tuple, cast

from botocore.client import BaseClient
from botocore.exceptions import BotoCoreError, ClientError, OperationNotPageableError

from checks.aws._common import (
    AwsAccountContext,
    build_scope,
    gb_from_bytes,
    is_suppressed,
    money,
    normalize_tags,
    now_utc,
    safe_float,
    safe_region_from_client,
)

from checks.registry import Bootstrap, register_checker
from contracts.finops_checker_pattern import Checker, FindingDraft, RunContext, Severity


# -----------------------------
# Config
# -----------------------------


@dataclass(frozen=True)
class NatGatewaysConfig:
    """Configuration knobs for :class:`NatGatewaysChecker`."""

    lookback_days: int = 14
    # For idle detection: p95 daily bytes threshold (default ~1 MiB/day).
    idle_p95_daily_bytes_threshold: float = 1_048_576.0
    # Minimum number of datapoints (daily) to consider metrics meaningful.
    min_daily_datapoints: int = 7

    # High data processing: if monthly-equivalent traffic exceeds this threshold (GiB).
    high_data_processing_gib_month_threshold: float = 100.0

    # "Orphaned" detection: ignore NATs created very recently.
    orphan_min_age_days: int = 1

    # Tag-based suppression (lowercased by normalize_tags)
    suppress_tag_keys: Tuple[str, ...] = ("finops:ignore", "do-not-delete", "keep")

    # Safety valve for very large environments
    max_findings_per_type: int = 50_000


# -----------------------------
# Pricing (best-effort)
# -----------------------------


_FALLBACK_NAT_HOURLY_USD: float = 0.045
_FALLBACK_NAT_DATA_USD_PER_GB: float = 0.045


def _pricing_service(ctx: RunContext) -> Any:
    return getattr(getattr(ctx, "services", None), "pricing", None)


def _resolve_nat_pricing(ctx: RunContext, *, region: str) -> Tuple[float, float, str, int]:
    """
    Best-effort pricing for NAT Gateway.

    Returns: (usd_per_hour, usd_per_gb_processed, notes, confidence_0_100)
    """
    pricing = _pricing_service(ctx)
    if pricing is None:
        return _FALLBACK_NAT_HOURLY_USD, _FALLBACK_NAT_DATA_USD_PER_GB, "PricingService unavailable; using fallback pricing.", 30

    location = ""
    try:
        location = str(pricing.location_for_region(region) or "")
    except (AttributeError, TypeError, ValueError):
        location = ""
    if not location:
        return _FALLBACK_NAT_HOURLY_USD, _FALLBACK_NAT_DATA_USD_PER_GB, "Pricing region mapping missing; using fallback pricing.", 30

    # NAT pricing is published under AmazonEC2. Catalog attributes are not perfectly stable,
    # so we try a few filter sets and fall back if none match.
    hourly: Optional[float] = None
    per_gb: Optional[float] = None
    notes: List[str] = []

    # Hourly (Hrs)
    hourly_attempts: List[List[Dict[str, str]]] = [
        [
            {"Field": "location", "Value": location},
            {"Field": "productFamily", "Value": "NAT Gateway"},
        ],
        [
            {"Field": "location", "Value": location},
            {"Field": "usagetype", "Value": "NatGateway-Hours"},
        ],
        [
            {"Field": "location", "Value": location},
            {"Field": "group", "Value": "NAT Gateway"},
        ],
    ]

    for filters in hourly_attempts:
        try:
            quote = pricing.get_on_demand_unit_price(service_code="AmazonEC2", filters=filters, unit="Hrs")
        except (AttributeError, TypeError, ValueError, ClientError):
            quote = None
        if quote is None:
            continue
        try:
            hourly = float(getattr(quote, "unit_price", None) or getattr(quote, "price", None) or 0.0)
        except (TypeError, ValueError):
            hourly = None
        if hourly and hourly > 0.0:
            notes.append("on-demand hourly price resolved via PricingService")
            break
        hourly = None

    # Data processing (GB)
    data_attempts: List[List[Dict[str, str]]] = [
        [
            {"Field": "location", "Value": location},
            {"Field": "usagetype", "Value": "NatGateway-Bytes"},
        ],
        [
            {"Field": "location", "Value": location},
            {"Field": "group", "Value": "NAT Gateway"},
            {"Field": "operation", "Value": "DataProcessing"},
        ],
        [
            {"Field": "location", "Value": location},
            {"Field": "productFamily", "Value": "NAT Gateway"},
            {"Field": "operation", "Value": "DataProcessing"},
        ],
    ]
    for filters in data_attempts:
        try:
            quote = pricing.get_on_demand_unit_price(service_code="AmazonEC2", filters=filters, unit="GB")
        except (AttributeError, TypeError, ValueError, ClientError):
            quote = None
        if quote is None:
            continue
        try:
            per_gb = float(getattr(quote, "unit_price", None) or getattr(quote, "price", None) or 0.0)
        except (TypeError, ValueError):
            per_gb = None
        if per_gb and per_gb > 0.0:
            notes.append("on-demand data processing price resolved via PricingService")
            break
        per_gb = None

    final_hourly = float(hourly if hourly and hourly > 0.0 else _FALLBACK_NAT_HOURLY_USD)
    final_per_gb = float(per_gb if per_gb and per_gb > 0.0 else _FALLBACK_NAT_DATA_USD_PER_GB)
    confidence = 75 if hourly and per_gb else 55 if (hourly or per_gb) else 30
    if not notes:
        notes.append("using fallback pricing")
    return final_hourly, final_per_gb, "; ".join(notes), confidence


# -----------------------------
# Pagination helpers
# -----------------------------


def _paginate_items(
    client: BaseClient,
    operation: str,
    result_key: str,
    *,
    params: Optional[Dict[str, Any]] = None,
) -> Iterator[Dict[str, Any]]:
    params = dict(params or {})

    if hasattr(client, "get_paginator"):
        try:
            paginator = client.get_paginator(operation)
            for page in paginator.paginate(**params):
                for item in page.get(result_key, []) or []:
                    if isinstance(item, dict):
                        yield item
            return
        except OperationNotPageableError:
            # Fall back to token-based pagination.
            pass
        except (AttributeError, KeyError, TypeError, ValueError):
            # Best-effort: some fakes/mocks or unusual clients may not behave like boto3.
            pass

    next_token: Optional[str] = None
    while True:
        call = getattr(client, operation)
        req = dict(params)
        if next_token:
            req["NextToken"] = next_token
        resp = call(**req) if req else call()
        for item in resp.get(result_key, []) or []:
            if isinstance(item, dict):
                yield item
        next_token = cast(Optional[str], resp.get("NextToken"))
        if not next_token:
            break


# -----------------------------
# CloudWatch batching
# -----------------------------


class _NatCloudWatchMetrics:
    """Batch CloudWatch fetcher for NAT Gateway daily byte sums."""

    def __init__(self, cw: Any) -> None:
        self._cw = cw
        self._cache: Dict[Tuple[str, int, str, str, str], List[float]] = {}

    def daily_bytes(
        self,
        *,
        nat_gateway_ids: Sequence[str],
        start: datetime,
        end: datetime,
    ) -> Dict[str, List[float]]:
        """
        Return daily traffic byte series per NAT Gateway id.

        Series is: BytesOutToDestination + BytesInFromDestination (daily Sum).
        """
        metric_name_out = "BytesOutToDestination"
        metric_name_in = "BytesInFromDestination"
        namespace = "AWS/NATGateway"
        period = 86400
        stat = "Sum"

        start_key = start.date().isoformat()
        end_key = end.date().isoformat()

        out: Dict[str, List[float]] = {nid: [] for nid in nat_gateway_ids}
        missing_out: List[str] = []
        missing_in: List[str] = []

        for nid in nat_gateway_ids:
            key_out = (metric_name_out, period, start_key, end_key, nid)
            key_in = (metric_name_in, period, start_key, end_key, nid)
            if key_out not in self._cache:
                missing_out.append(nid)
            if key_in not in self._cache:
                missing_in.append(nid)

        if missing_out:
            self._fetch_and_cache(
                namespace=namespace,
                metric_name=metric_name_out,
                nat_gateway_ids=missing_out,
                start=start,
                end=end,
                period=period,
                stat=stat,
            )
        if missing_in:
            self._fetch_and_cache(
                namespace=namespace,
                metric_name=metric_name_in,
                nat_gateway_ids=missing_in,
                start=start,
                end=end,
                period=period,
                stat=stat,
            )

        for nid in nat_gateway_ids:
            series_out = self._cache.get((metric_name_out, period, start_key, end_key, nid), [])
            series_in = self._cache.get((metric_name_in, period, start_key, end_key, nid), [])
            merged: List[float] = []
            # Merge by index (timestamps are ascending); keep safe if lengths mismatch.
            max_len = max(len(series_out), len(series_in))
            for i in range(max_len):
                v = 0.0
                if i < len(series_out):
                    v += float(series_out[i])
                if i < len(series_in):
                    v += float(series_in[i])
                merged.append(float(v))
            out[nid] = merged

        return out

    def _fetch_and_cache(
        self,
        *,
        namespace: str,
        metric_name: str,
        nat_gateway_ids: Sequence[str],
        start: datetime,
        end: datetime,
        period: int,
        stat: str,
    ) -> None:
        if not nat_gateway_ids:
            return

        start_key = start.date().isoformat()
        end_key = end.date().isoformat()

        # CloudWatch GetMetricData allows up to 500 queries per call.
        # We use 100 to be conservative (two metrics are queried separately).
        batch_size = 100
        for i in range(0, len(nat_gateway_ids), batch_size):
            batch = list(nat_gateway_ids[i:i + batch_size])

            queries: List[Dict[str, Any]] = []
            id_to_nat: Dict[str, str] = {}
            for j, nid in enumerate(batch):
                qid = f"m{i+j}"
                id_to_nat[qid] = nid
                queries.append(
                    {
                        "Id": qid,
                        "MetricStat": {
                            "Metric": {
                                "Namespace": namespace,
                                "MetricName": metric_name,
                                "Dimensions": [{"Name": "NatGatewayId", "Value": nid}],
                            },
                            "Period": period,
                            "Stat": stat,
                        },
                        "ReturnData": True,
                    }
                )

            next_token: Optional[str] = None
            merged: Dict[str, List[float]] = {}
            while True:
                kwargs: Dict[str, Any] = {
                    "MetricDataQueries": queries,
                    "StartTime": start,
                    "EndTime": end,
                    "ScanBy": "TimestampAscending",
                }
                if next_token:
                    kwargs["NextToken"] = next_token
                resp = self._cw.get_metric_data(**kwargs)
                for r in resp.get("MetricDataResults", []) or []:
                    qid = str(r.get("Id") or "")
                    nid = id_to_nat.get(qid)
                    if not nid:
                        continue
                    vals = r.get("Values", []) or []
                    numbers: List[float] = []
                    for v in vals:
                        if isinstance(v, (int, float)):
                            numbers.append(float(v))
                    merged.setdefault(nid, []).extend(numbers)
                next_token = cast(Optional[str], resp.get("NextToken"))
                if not next_token:
                    break

            for nid, series in merged.items():
                self._cache[(metric_name, period, start_key, end_key, nid)] = list(series)


# -----------------------------
# Core checker
# -----------------------------


class NatGatewaysChecker:
    """Detect idle, orphaned, and costly NAT Gateways."""

    checker_id = "aws.ec2.nat_gateways"

    def __init__(
        self,
        *,
        account_id: str,
        billing_account_id: Optional[str] = None,
        partition: str = "aws",
        cfg: Optional[NatGatewaysConfig] = None,
    ) -> None:

        self._account = AwsAccountContext(
            account_id=str(account_id or ""),
            billing_account_id=str(billing_account_id) if billing_account_id else None,
            partition=str(partition or "aws"),
        )
        self._cfg = cfg or NatGatewaysConfig()

    def run(self, ctx: RunContext) -> Iterable[FindingDraft]:
        services = getattr(ctx, "services", None)
        if services is None:
            raise RuntimeError("RunContext.services is required")

        ec2 = services.ec2
        cw = getattr(ctx.services, "cloudwatch", None)
        region = safe_region_from_client(ec2) or str(getattr(ctx.services, "region", "") or "")

        # Inventory NAT gateways
        try:
            nat_gateways = list(_paginate_items(ec2, "describe_nat_gateways", "NatGateways"))
        except ClientError as exc:
            yield self._access_error(ctx, region, "describe_nat_gateways", exc)
            return

        if not nat_gateways:
            return

        # Normalize & filter to "available" NATs (best-effort)
        nats: List[Dict[str, Any]] = []
        for nat in nat_gateways:
            state = str(nat.get("State") or "").lower()
            if state and state not in {"available", "pending", "failed", "deleting", "deleted"}:
                # Unknown state: still include.
                pass
            # Keep all except deleted
            if state == "deleted":
                continue
            nats.append(nat)

        nat_ids = [str(n.get("NatGatewayId") or "") for n in nats if n.get("NatGatewayId")]
        nat_ids = [nid for nid in nat_ids if nid]
        if not nat_ids:
            return

        # Tags suppression map
        nat_tags: Dict[str, Dict[str, str]] = {}
        for nat in nats:
            nid = str(nat.get("NatGatewayId") or "")
            if not nid:
                continue
            nat_tags[nid] = normalize_tags(nat.get("Tags"))

        suppress_keys = frozenset([str(k).strip().lower() for k in self._cfg.suppress_tag_keys])

        # Route table references (best-effort; filter by nat ids when supported)
        referenced_by_routes: Set[str] = set()
        cross_az_pairs: Dict[str, Set[Tuple[str, str]]] = {nid: set() for nid in nat_ids}

        nat_subnet_ids: Set[str] = {str(n.get("SubnetId") or "") for n in nats if n.get("SubnetId")}
        nat_subnet_ids.discard("")

        route_tables: List[Mapping[str, Any]] = []
        assoc_subnet_ids: Set[str] = set()

        try:
            for rt in self._route_tables_by_nat(ec2, nat_ids):
                route_tables.append(rt)
                for a in rt.get("Associations", []) or []:
                    if not isinstance(a, Mapping):
                        continue
                    sid = str(a.get("SubnetId") or "")
                    if sid:
                        assoc_subnet_ids.add(sid)
        except ClientError as exc:
            # If we can't see route tables, skip orphan/cross-AZ signals (don't fail the whole checker).
            yield self._access_error(ctx, region, "describe_route_tables", exc)
            referenced_by_routes = set(nat_ids)  # avoid marking everything orphaned
            cross_az_pairs = {nid: set() for nid in nat_ids}
            route_tables = []
            assoc_subnet_ids = set()

        # subnet_id -> az (for NAT and associated subnets)
        subnet_az: Dict[str, str] = {}
        all_subnet_ids = set(nat_subnet_ids) | set(assoc_subnet_ids)
        try:
            subnet_az = self._describe_subnet_az(ec2, sorted(all_subnet_ids))
        except ClientError:
            subnet_az = {}

        nat_az: Dict[str, str] = {}
        nat_vpc: Dict[str, str] = {}
        for nat in nats:
            nid = str(nat.get("NatGatewayId") or "")
            sid = str(nat.get("SubnetId") or "")
            nat_az[nid] = subnet_az.get(sid, "")
            nat_vpc[nid] = str(nat.get("VpcId") or "")

        for rt in route_tables:
            self._process_route_table_page(rt, referenced_by_routes, nat_ids, cross_az_pairs, subnet_az, nat_az)

        # Metrics (best-effort)
        daily_bytes: Dict[str, List[float]] = {}
        emitted_perm: Set[str] = set()
        if cw is not None:
            lookback = int(self._cfg.lookback_days)
            end = now_utc()
            start = end - timedelta(days=lookback)
            try:
                fetcher = _NatCloudWatchMetrics(cw)
                daily_bytes = fetcher.daily_bytes(nat_gateway_ids=nat_ids, start=start, end=end)
            except ClientError as exc:
                if self._is_access_denied(exc) and "cloudwatch:GetMetricData" not in emitted_perm:
                    emitted_perm.add("cloudwatch:GetMetricData")
                    yield self._missing_permission(
                        ctx,
                        region,
                        operation="cloudwatch:GetMetricData",
                        service="cloudwatch",
                        message="CloudWatch GetMetricData is required to evaluate NAT Gateway traffic (idle/high data).",
                    )
                else:
                    yield self._cloudwatch_error(ctx, region, "get_metric_data", exc)
                daily_bytes = {}
            except BotoCoreError as exc:
                yield self._cloudwatch_error(ctx, region, "get_metric_data", exc)
                daily_bytes = {}

        # Pricing
        usd_per_hour, usd_per_gb, pricing_notes, pricing_conf = _resolve_nat_pricing(ctx, region=region)

        emitted: Dict[str, int] = {"orphaned": 0, "idle": 0, "high_data": 0, "cross_az": 0}

        for nat in nats:
            nid = str(nat.get("NatGatewayId") or "")
            if not nid:
                continue

            tags = nat_tags.get(nid, {})
            if is_suppressed(tags, suppress_keys=suppress_keys):
                continue

            state = str(nat.get("State") or "").lower()
            vpc_id = str(nat.get("VpcId") or "")
            subnet_id = str(nat.get("SubnetId") or "")
            az = nat_az.get(nid, "")

            created = nat.get("CreateTime")
            created_dt: Optional[datetime]
            if isinstance(created, datetime):
                created_dt = created
            else:
                created_dt = None

            # Estimated baseline monthly cost (hourly only)
            monthly_hourly_cost = money(float(usd_per_hour) * 730.0)

            # Orphaned: not referenced by any route table
            if nid not in referenced_by_routes and state != "deleting":
                if self._old_enough(created_dt, min_age_days=self._cfg.orphan_min_age_days):
                    if emitted["orphaned"] < self._cfg.max_findings_per_type:
                        emitted["orphaned"] += 1
                        yield self._finding_orphaned(
                            ctx,
                            region,
                            nat_id=nid,
                            vpc_id=vpc_id,
                            subnet_id=subnet_id,
                            az=az,
                            tags=tags,
                            monthly_cost=monthly_hourly_cost,
                            pricing_conf=pricing_conf,
                            pricing_notes=pricing_notes,
                        )
                continue  # orphan usually implies no need for other signals

            # Cross-AZ route usage (best-effort)
            pairs = cross_az_pairs.get(nid) or set()
            if pairs and emitted["cross_az"] < self._cfg.max_findings_per_type:
                emitted["cross_az"] += 1
                yield self._finding_cross_az(
                    ctx,
                    region,
                    nat_id=nid,
                    vpc_id=vpc_id,
                    nat_az=az,
                    tags=tags,
                    pairs=pairs,
                )

            # Idle detection
            series = daily_bytes.get(nid, [])
            if series and len(series) >= int(self._cfg.min_daily_datapoints):
                p95 = _p95(series)
                if p95 < float(self._cfg.idle_p95_daily_bytes_threshold):
                    if emitted["idle"] < self._cfg.max_findings_per_type:
                        emitted["idle"] += 1
                        yield self._finding_idle(
                            ctx,
                            region,
                            nat_id=nid,
                            vpc_id=vpc_id,
                            subnet_id=subnet_id,
                            az=az,
                            tags=tags,
                            monthly_cost=monthly_hourly_cost,
                            pricing_conf=pricing_conf,
                            pricing_notes=pricing_notes,
                            p95_daily_bytes=p95,
                            lookback_days=self._cfg.lookback_days,
                        )

                # High data processing
                # Compute a rough monthly traffic from the mean daily bytes.
                avg_daily = float(sum(series) / max(1, len(series)))
                monthly_gib = gb_from_bytes(avg_daily * 30.0)
                if monthly_gib >= float(self._cfg.high_data_processing_gib_month_threshold):
                    if emitted["high_data"] < self._cfg.max_findings_per_type:
                        emitted["high_data"] += 1
                        data_cost = money(float(monthly_gib) * float(usd_per_gb))
                        yield self._finding_high_data_processing(
                            ctx,
                            region,
                            nat_id=nid,
                            vpc_id=vpc_id,
                            az=az,
                            tags=tags,
                            monthly_gib=monthly_gib,
                            est_monthly_data_cost=data_cost,
                            est_monthly_total_cost=money(monthly_hourly_cost + data_cost),
                            pricing_conf=pricing_conf,
                            pricing_notes=pricing_notes,
                        )

        return

    # -----------------------------
    # AWS helpers
    # -----------------------------

    def _describe_subnet_az(self, ec2: Any, subnet_ids: Sequence[str]) -> Dict[str, str]:
        if not subnet_ids:
            return {}
        out: Dict[str, str] = {}
        # describe_subnets allows up to 200 IDs per call
        chunk = 200
        for i in range(0, len(subnet_ids), chunk):
            batch = [sid for sid in subnet_ids[i:i + chunk] if sid]
            if not batch:
                continue
            resp = ec2.describe_subnets(SubnetIds=batch)
            for s in resp.get("Subnets", []) or []:
                sid = str(s.get("SubnetId") or "")
                az = str(s.get("AvailabilityZone") or "")
                if sid:
                    out[sid] = az
        return out

    def _route_tables_by_nat(self, ec2: Any, nat_ids: Sequence[str]) -> Iterator[Mapping[str, Any]]:
        # Prefer server-side filtering if supported: route.nat-gateway-id
        batch = 50
        for i in range(0, len(nat_ids), batch):
            chunk_ids = [nid for nid in nat_ids[i:i + batch] if nid]
            if not chunk_ids:
                continue
            params = {"Filters": [{"Name": "route.nat-gateway-id", "Values": chunk_ids}]}
            yielded = False
            try:
                for item in _paginate_items(ec2, "describe_route_tables", "RouteTables", params=params):
                    yielded = True
                    yield item
            except ClientError:
                if yielded:
                    raise
                # Fallback: list all route tables once
                for item in _paginate_items(ec2, "describe_route_tables", "RouteTables"):
                    yield item
                return

    def _process_route_table_page(
        self,
        route_table: Mapping[str, Any],
        referenced_by_routes: Set[str],
        nat_ids: Sequence[str],
        cross_az_pairs: Dict[str, Set[Tuple[str, str]]],
        subnet_az: Mapping[str, str],
        nat_az: Mapping[str, str],
    ) -> None:
        nat_set = set(nat_ids)

        # Determine which subnets this route table is associated to (subnet_id -> az)
        assoc_subnets: List[Tuple[str, str]] = []
        for a in route_table.get("Associations", []) or []:
            if not isinstance(a, Mapping):
                continue
            subnet_id = str(a.get("SubnetId") or "")
            if not subnet_id:
                continue
            assoc_subnets.append((subnet_id, str(subnet_az.get(subnet_id, "") or "")))

        for r in route_table.get("Routes", []) or []:
            if not isinstance(r, Mapping):
                continue
            nid = str(r.get("NatGatewayId") or "")
            if not nid or nid not in nat_set:
                continue
            referenced_by_routes.add(nid)

            # Cross-AZ: any associated subnet AZ differs from NAT AZ
            nat_zone = str(nat_az.get(nid, "") or "")
            if not nat_zone:
                continue
            for subnet_id, subnet_zone in assoc_subnets:
                if subnet_zone and subnet_zone != nat_zone:
                    cross_az_pairs.setdefault(nid, set()).add((subnet_id, subnet_zone))

    # -----------------------------
    # Findings
    # -----------------------------

    def _access_error(self, ctx: RunContext, region: str, operation: str, exc: ClientError) -> FindingDraft:
        return FindingDraft(
            check_id="aws.ec2.nat_gateways.access_error",
            check_name="EC2 NAT Gateways access error",
            category="governance",
            status="unknown",
            severity=Severity(level="info", score=100),
            title=f"Unable to evaluate NAT Gateways ({operation})",
            message=str(exc),
            scope=build_scope(
                ctx,
                account=self._account,
                region=region,
                service="ec2",
                resource_type="nat-gateway",
            ),
            recommendation="Ensure the scanning role has required EC2 permissions (DescribeNatGateways, DescribeRouteTables, DescribeSubnets) and CloudWatch GetMetricData.",
        ).with_issue(operation=operation)

    def _cloudwatch_error(self, ctx: RunContext, region: str, operation: str, exc: Exception) -> FindingDraft:
        return FindingDraft(
            check_id="aws.ec2.nat_gateways.cloudwatch_error",
            check_name="NAT Gateways CloudWatch error",
            category="governance",
            status="unknown",
            severity=Severity(level="info", score=120),
            title=f"Unable to evaluate NAT Gateway metrics ({operation})",
            message=str(exc),
            scope=build_scope(
                ctx,
                account=self._account,
                region=region,
                service="cloudwatch",
                resource_type="metric",
            ),
            recommendation="Ensure the scanning role has cloudwatch:GetMetricData (and related permissions) and retry.",
        ).with_issue(operation=operation)

    def _missing_permission(
        self,
        ctx: RunContext,
        region: str,
        *,
        operation: str,
        service: str,
        message: str,
    ) -> FindingDraft:
        return FindingDraft(
            check_id="aws.ec2.nat_gateways.missing_permission",
            check_name="NAT Gateways missing permission",
            category="governance",
            status="info",
            severity=Severity(level="info", score=110),
            title=f"Missing permission to evaluate NAT Gateways ({operation})",
            message=message,
            scope=build_scope(
                ctx,
                account=self._account,
                region=region,
                service=service,
                resource_type="permission",
            ),
            recommendation="Grant the scanning role the missing permission(s) and re-run the scan.",
        ).with_issue(operation=operation)

    def _is_access_denied(self, exc: ClientError) -> bool:
        try:
            code = str(exc.response.get("Error", {}).get("Code") or "")
        except (AttributeError, TypeError, ValueError):
            return False
        return code in {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation"}

    def _finding_orphaned(
        self,
        ctx: RunContext,
        region: str,
        *,
        nat_id: str,
        vpc_id: str,
        subnet_id: str,
        az: str,
        tags: Dict[str, str],
        monthly_cost: float,
        pricing_conf: int,
        pricing_notes: str,
    ) -> FindingDraft:
        return FindingDraft(
            check_id="aws.ec2.nat_gateways.orphaned",
            check_name="Orphaned NAT Gateway",
            category="cost",
            status="fail",
            severity=Severity(level="medium", score=500),
            title=f"NAT Gateway {nat_id} is not referenced by any route table",
            message=(
                "This NAT Gateway does not appear in any VPC route table routes (best-effort). "
                "If it is truly unused, you can delete it to avoid ongoing hourly charges."
            ),
            recommendation="Verify no subnets rely on this NAT Gateway, then delete it. Consider using VPC endpoints for AWS service traffic.",
            remediation="Delete the NAT Gateway if confirmed unused.",
            scope=build_scope(
                ctx,
                account=self._account,
                region=region,
                availability_zone=az,
                service="ec2",
                resource_type="nat-gateway",
                resource_id=nat_id,
            ),
            tags=tags,
            dimensions={"vpc_id": vpc_id, "subnet_id": subnet_id},
            estimated_monthly_cost=monthly_cost,
            estimated_monthly_savings=monthly_cost,
            estimate_confidence=pricing_conf,
            estimate_notes=pricing_notes,
        ).with_issue(nat_gateway_id=nat_id)

    def _finding_idle(
        self,
        ctx: RunContext,
        region: str,
        *,
        nat_id: str,
        vpc_id: str,
        subnet_id: str,
        az: str,
        tags: Dict[str, str],
        monthly_cost: float,
        pricing_conf: int,
        pricing_notes: str,
        p95_daily_bytes: float,
        lookback_days: int,
    ) -> FindingDraft:
        daily_gib = gb_from_bytes(p95_daily_bytes)
        return FindingDraft(
            check_id="aws.ec2.nat_gateways.idle",
            check_name="Idle NAT Gateway",
            category="cost",
            status="fail",
            severity=Severity(level="low", score=350),
            title=f"NAT Gateway {nat_id} shows very low traffic (p95 ~{daily_gib:.4f} GiB/day)",
            message=(
                f"Over the last {int(lookback_days)} days, this NAT Gateway's p95 daily traffic is near zero "
                "(best-effort from CloudWatch). If workloads no longer need egress, deleting it avoids hourly charges."
            ),
            recommendation="Confirm this NAT Gateway is not needed and delete it. If only AWS service traffic is required, add VPC endpoints to keep traffic private and reduce NAT usage.",
            remediation="Delete the NAT Gateway if confirmed unused.",
            scope=build_scope(
                ctx,
                account=self._account,
                region=region,
                availability_zone=az,
                service="ec2",
                resource_type="nat-gateway",
                resource_id=nat_id,
            ),
            tags=tags,
            dimensions={"vpc_id": vpc_id, "subnet_id": subnet_id},
            estimated_monthly_cost=monthly_cost,
            estimated_monthly_savings=monthly_cost,
            estimate_confidence=pricing_conf,
            estimate_notes=pricing_notes,
        ).with_issue(nat_gateway_id=nat_id)

    def _finding_high_data_processing(
        self,
        ctx: RunContext,
        region: str,
        *,
        nat_id: str,
        vpc_id: str,
        az: str,
        tags: Dict[str, str],
        monthly_gib: float,
        est_monthly_data_cost: float,
        est_monthly_total_cost: float,
        pricing_conf: int,
        pricing_notes: str,
    ) -> FindingDraft:
        return FindingDraft(
            check_id="aws.ec2.nat_gateways.high_data_processing",
            check_name="High NAT Gateway data processing",
            category="cost",
            status="fail",
            severity=Severity(level="medium", score=600),
            title=f"NAT Gateway {nat_id} processes high traffic (~{monthly_gib:.1f} GiB/month)",
            message=(
                "NAT Gateway data processing can be a significant cost driver. If most traffic is to AWS services, "
                "consider VPC endpoints (S3/DynamoDB gateway endpoints; interface endpoints for ECR, STS, SSM, Logs, etc.) "
                "to keep traffic private and reduce NAT data processing charges."
            ),
            recommendation="Review NAT traffic destinations; add relevant VPC endpoints; reduce chatty workloads; consider consolidating NAT usage.",
            remediation="Add VPC endpoints for high-volume AWS service traffic and re-route private subnets accordingly.",
            scope=build_scope(
                ctx,
                account=self._account,
                region=region,
                availability_zone=az,
                service="ec2",
                resource_type="nat-gateway",
                resource_id=nat_id,
            ),
            tags=tags,
            dimensions={"vpc_id": vpc_id, "estimated_monthly_gib": f"{monthly_gib:.2f}"},
            estimated_monthly_cost=est_monthly_total_cost,
            estimated_monthly_savings=est_monthly_data_cost,
            estimate_confidence=pricing_conf,
            estimate_notes=pricing_notes,
        ).with_issue(nat_gateway_id=nat_id)

    def _finding_cross_az(
        self,
        ctx: RunContext,
        region: str,
        *,
        nat_id: str,
        vpc_id: str,
        nat_az: str,
        tags: Dict[str, str],
        pairs: Set[Tuple[str, str]],
    ) -> FindingDraft:
        sample = ", ".join([f"{sid}({az})" for sid, az in sorted(list(pairs))[:5]])
        return FindingDraft(
            check_id="aws.ec2.nat_gateways.cross_az",
            check_name="Cross-AZ NAT Gateway routing",
            category="cost",
            status="fail",
            severity=Severity(level="medium", score=550),
            title=f"Cross-AZ NAT usage detected for {nat_id}",
            message=(
                "Some subnets appear to route through a NAT Gateway in a different Availability Zone "
                "(best-effort from route table associations). This can increase cross-AZ data charges and "
                "reduce resilience during AZ impairments."
            ),
            recommendation="Ensure each private subnet routes to a NAT Gateway in the same AZ (one NAT per AZ for HA).",
            remediation="Create a NAT Gateway per AZ and update route tables to use the same-AZ NAT.",
            scope=build_scope(
                ctx,
                account=self._account,
                region=region,
                availability_zone=nat_az,
                service="ec2",
                resource_type="nat-gateway",
                resource_id=nat_id,
            ),
            tags=tags,
            dimensions={"vpc_id": vpc_id, "nat_az": nat_az, "sample_subnets": sample},
        ).with_issue(nat_gateway_id=nat_id)

    # -----------------------------
    # Utilities
    # -----------------------------

    def _old_enough(self, created: Optional[datetime], *, min_age_days: int) -> bool:
        if created is None:
            return True
        try:
            age = now_utc() - created
            return age >= timedelta(days=int(min_age_days))
        except (TypeError, ValueError, OverflowError):
            return True


def _p95(values: Sequence[float]) -> float:
    vals = [safe_float(v, default=0.0) for v in values if safe_float(v, default=0.0) >= 0.0]
    if not vals:
        return 0.0
    vals_sorted = sorted(vals)
    # p95 index
    idx = int(round(0.95 * (len(vals_sorted) - 1)))
    idx = max(0, min(idx, len(vals_sorted) - 1))
    return float(vals_sorted[idx])


@register_checker("checks.aws.nat_gateways:NatGatewaysChecker")
def _factory(ctx: RunContext, bootstrap: Bootstrap) -> Checker:
    account_id = str(bootstrap.get("account_id") or "")
    billing_id = str(bootstrap.get("billing_account_id") or "") or None
    cfg = NatGatewaysConfig()
    return NatGatewaysChecker(account_id=account_id, billing_account_id=billing_id, cfg=cfg)
