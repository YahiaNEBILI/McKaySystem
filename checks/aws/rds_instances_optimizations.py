"""
checks/aws/rds_instances_optimizations.py

RDS Instances Optimization Checker
=================================

This checker emits multiple infra-native FinOps signals for Amazon RDS DB instances:

1) Stopped instances with storage cost
2) Storage overprovisioned (CloudWatch FreeStorageSpace)
3) Multi-AZ enabled on non-production (tag-based)
4) Old-generation instance family (e.g., db.m3, db.m4, db.t2)
5) Engine needs upgrade:
   - MySQL: 5.6 or 5.7
   - Postgres: 9 / 10 / 11
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

from botocore.exceptions import ClientError

from checks.registry import register_checker
from contracts.finops_checker_pattern import FindingDraft, Scope, Severity

_NONPROD_VALUES = {
    "dev", "test", "nprd", "staging", "nonprod", "non-prod", "sandbox", "qa", "uat"
}
_ENV_TAG_KEYS = {"env", "environment", "Environment"}

_OLD_FAMILIES = {"m1", "m2", "m3", "m4", "r3", "r4", "t1", "t2", "x1"}


@dataclass(frozen=True)
class AwsAccountContext:
    account_id: str
    billing_account_id: Optional[str] = None
    partition: str = "aws"


def _safe_region_from_client(client: Any) -> str:
    try:
        return str(getattr(getattr(client, "meta", None), "region_name", "") or "")
    except Exception:  # pragma: no cover
        return ""


def _arn_partition(arn: str) -> str:
    try:
        parts = arn.split(":")
        if len(parts) >= 2 and parts[0] == "arn":
            return parts[1] or ""
    except Exception:  # pragma: no cover
        return ""
    return ""


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _fmt_money_usd(amount: float) -> str:
    return f"{amount:.2f}"


def _bytes_to_gb(b: float) -> float:
    return float(b) / (1024.0 * 1024.0 * 1024.0)


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
    out: Dict[str, str] = {}
    for t in tag_list or []:
        k = str(t.get("Key") or "").strip()
        v = str(t.get("Value") or "").strip()
        if k:
            out[k] = v
    return out


def _is_non_prod(tags: Dict[str, str]) -> bool:
    # explicit prod wins
    for k, v in tags.items():
        if str(k).strip().lower() in _ENV_TAG_KEYS and str(v).strip().lower() in {"prod", "production"}:
            return False
    for k, v in tags.items():
        if str(k).strip().lower() in _ENV_TAG_KEYS and str(v).strip().lower() in _NONPROD_VALUES:
            return True
    return False


def _family_from_instance_class(db_instance_class: str) -> str:
    # "db.m3.large" -> "m3"
    txt = str(db_instance_class or "")
    if not txt.startswith("db."):
        return ""
    parts = txt.split(".")
    return parts[1] if len(parts) >= 3 else ""


def _mysql_needs_upgrade(engine: str, engine_version: str) -> bool:
    if "mysql" not in (engine or "").lower():
        return False
    v = str(engine_version or "").strip()
    return v.startswith("5.6") or v.startswith("5.7")


def _postgres_needs_upgrade(engine: str, engine_version: str) -> bool:
    if "postgres" not in (engine or "").lower():
        return False
    v = str(engine_version or "").strip()
    major_txt = v.split(".", 1)[0] if v else ""
    try:
        major = int(major_txt)
    except ValueError:
        return False
    return major in {9, 10, 11}


class RDSInstancesOptimizationsChecker:
    checker_id = "aws.rds.instances.optimizations"

    def __init__(
        self,
        *,
        account: AwsAccountContext,
        storage_gb_month_price_usd: float = 0.115,
        storage_window_days: int = 14,
        overprov_used_ratio_threshold: float = 0.40,
        overprov_min_excess_gb: float = 20.0,
    ) -> None:
        self._account = account
        self._storage_gb_month_price_usd = float(storage_gb_month_price_usd)
        self._storage_window_days = int(storage_window_days)
        self._overprov_used_ratio_threshold = float(overprov_used_ratio_threshold)
        self._overprov_min_excess_gb = float(overprov_min_excess_gb)

    def run(self, ctx) -> Iterable[FindingDraft]:
        if not getattr(ctx, "services", None) or not getattr(ctx.services, "rds", None):
            raise RuntimeError("RDSInstancesOptimizationsChecker requires ctx.services.rds")

        rds = ctx.services.rds
        cw = getattr(ctx.services, "cloudwatch", None)
        region = _safe_region_from_client(rds)

        try:
            instances = list(self._list_db_instances(rds))
        except ClientError as exc:
            yield self._access_error(region, "describe_db_instances", exc)
            return

        for inst in instances:
            yield from self._evaluate_instance(ctx, rds, cw, inst, region)

    def _list_db_instances(self, rds: Any) -> Iterator[Dict[str, Any]]:
        paginator = rds.get_paginator("describe_db_instances")
        for page in paginator.paginate():
            for inst in page.get("DBInstances", []) or []:
                if isinstance(inst, dict):
                    yield inst

    def _list_tags(self, rds: Any, arn: str) -> Dict[str, str]:
        if not arn:
            return {}
        resp = rds.list_tags_for_resource(ResourceName=arn)
        return _extract_tags(resp.get("TagList", []) or [])

    def _evaluate_instance(
        self,
        ctx,
        rds: Any,
        cw: Any,
        inst: Dict[str, Any],
        region: str,
    ) -> Iterable[FindingDraft]:
        instance_id = str(inst.get("DBInstanceIdentifier") or "")
        arn = str(inst.get("DBInstanceArn") or "")
        partition = _arn_partition(arn) or self._account.partition

        try:
            tags = self._list_tags(rds, arn)
        except ClientError:
            tags = {}

        scope = Scope(
            cloud="aws",
            provider_partition=partition,
            account_id=self._account.account_id,
            billing_account_id=str(self._account.billing_account_id or self._account.account_id),
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

        # 1) stopped_instances_with_storage
        if status == "stopped" and allocated_gb > 0:
            monthly_cost = allocated_gb * self._storage_gb_month_price_usd
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
                estimated_monthly_cost=_fmt_money_usd(monthly_cost),
                estimated_monthly_savings=_fmt_money_usd(monthly_cost),
                estimate_confidence=60,
                estimate_notes="AllocatedStorage GB * default USD/GB-month. Excludes I/O and backup charges.",
                tags=tags,
            ).with_issue(check="stopped_storage", db_instance=instance_id)

        # 2) storage_overprovisioned (CloudWatch)
        if cw is not None and allocated_gb > 0:
            overprov = self._storage_overprovisioned(
                cw=cw,
                db_instance_id=instance_id,
                allocated_gb=allocated_gb,
            )
            if overprov is not None:
                used_gb, p95_free_gb, excess_gb = overprov
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
                    estimated_monthly_savings=_fmt_money_usd(monthly_savings),
                    estimated_monthly_cost="0",
                    estimate_confidence=70,
                    estimate_notes="Excess GB inferred from FreeStorageSpace p95 * default USD/GB-month; savings depend on migration feasibility.",
                    tags=tags,
                    dimensions={
                        "allocated_gb": f"{allocated_gb:.0f}",
                        "estimated_used_gb": f"{used_gb:.1f}",
                        "p95_free_gb": f"{p95_free_gb:.1f}",
                        "window_days": str(self._storage_window_days),
                    },
                ).with_issue(check="storage_overprovisioned", db_instance=instance_id)

        # 3) multi_az_non_prod
        if multi_az and _is_non_prod(tags):
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
                estimated_monthly_savings="0",
                estimated_monthly_cost="0",
                estimate_confidence=30,
                estimate_notes="Accurate savings requires instance pricing; this is a configuration signal without CUR.",
                tags=tags,
            ).with_issue(check="multi_az_non_prod", db_instance=instance_id)

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
                estimated_monthly_savings="0",
                estimated_monthly_cost="0",
                estimate_confidence=20,
                estimate_notes="Modernization opportunity; savings not estimated without pricing enrichment.",
                tags=tags,
                dimensions={"instance_class": instance_class, "family": fam},
            ).with_issue(check="old_generation_family", db_instance=instance_id, family=fam)

        # 5) needs_engine_upgrade
        if _mysql_needs_upgrade(engine, engine_version) or _postgres_needs_upgrade(engine, engine_version):
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
                estimated_monthly_savings="0",
                estimated_monthly_cost="0",
                estimate_confidence=40,
                estimate_notes="Policy-based governance signal. Extended support cost not computed without a maintained dataset.",
                tags=tags,
                dimensions={"engine": engine, "engine_version": engine_version},
            ).with_issue(check="engine_upgrade", db_instance=instance_id, engine=engine, engine_version=engine_version)

    def _storage_overprovisioned(
        self,
        *,
        cw: Any,
        db_instance_id: str,
        allocated_gb: float,
    ) -> Optional[Tuple[float, float, float]]:
        end = _now_utc()
        start = end - timedelta(days=self._storage_window_days)

        try:
            resp = cw.get_metric_statistics(
                Namespace="AWS/RDS",
                MetricName="FreeStorageSpace",
                Dimensions=[{"Name": "DBInstanceIdentifier", "Value": db_instance_id}],
                StartTime=start,
                EndTime=end,
                Period=3600,
                Statistics=["Average"],
            )
        except ClientError:
            return None

        values: List[float] = []
        for dp in (resp.get("Datapoints", []) or []):
            v = dp.get("Average")
            if isinstance(v, (int, float)):
                values.append(float(v))

        if len(values) < 12:
            return None

        p95_free_bytes = _percentile(values, 95.0)
        if p95_free_bytes is None:
            return None

        p95_free_gb = max(0.0, _bytes_to_gb(float(p95_free_bytes)))
        used_gb = max(0.0, float(allocated_gb) - p95_free_gb)

        used_ratio = used_gb / float(allocated_gb) if allocated_gb > 0 else 1.0
        if used_ratio >= self._overprov_used_ratio_threshold:
            return None

        target_floor = float(allocated_gb) * self._overprov_used_ratio_threshold
        excess_gb = max(0.0, float(allocated_gb) - max(used_gb, target_floor))
        if excess_gb < self._overprov_min_excess_gb:
            return None

        return (used_gb, p95_free_gb, excess_gb)

    def _access_error(self, region: str, action: str, exc: ClientError) -> FindingDraft:
        code = ""
        try:
            code = str(exc.response.get("Error", {}).get("Code", ""))
        except Exception:  # pragma: no cover
            code = ""

        scope = Scope(
            cloud="aws",
            provider_partition=self._account.partition,
            account_id=self._account.account_id,
            billing_account_id=str(self._account.billing_account_id or self._account.account_id),
            region=region,
            service="rds",
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
            recommendation="Grant rds:DescribeDBInstances, rds:ListTagsForResource, cloudwatch:GetMetricStatistics.",
            estimated_monthly_cost="0",
            estimated_monthly_savings="0",
            estimate_confidence=0,
            estimate_notes="Informational finding emitted when permissions are missing.",
        ).with_issue(check="access_error", action=action, region=region)


SPEC = "checks.aws.rds_instances_optimizations:RDSInstancesOptimizationsChecker"


@register_checker(SPEC)
def _factory(ctx, bootstrap: Dict[str, Any]) -> RDSInstancesOptimizationsChecker:
    account_id = str(bootstrap.get("aws_account_id") or "")
    billing_id = str(bootstrap.get("aws_billing_account_id") or account_id)
    if not account_id:
        raise ValueError("bootstrap missing aws_account_id")

    return RDSInstancesOptimizationsChecker(
        account=AwsAccountContext(account_id=account_id, billing_account_id=billing_id),
    )
