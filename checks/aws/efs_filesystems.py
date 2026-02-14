"""checks/aws/efs_filesystems.py

Amazon EFS optimization + governance checker.

Signals (cost / optimization)
---------------------------
1) Possibly unused file systems (best-effort)
   - Low/no observed IO (DataReadIOBytes + DataWriteIOBytes) over N days
   - AND no client connections (ClientConnections) over N days

2) Provisioned throughput underutilized (best-effort)
   - If ThroughputMode == 'provisioned'
   - And p95 PercentIOLimit is consistently below a threshold

Signals (governance)
--------------------
3) Lifecycle policy missing (IA/Archive transitions)
4) Backups disabled
5) Unencrypted file system (rare; but enforceable)

Notes
-----
EFS is billed primarily by stored data; "over-provisioned storage" is not a
useful signal like block storage. Instead, this checker focuses on hygiene and
configuration choices that typically lead to wasted spend or higher operational
risk.

CloudWatch metrics are queried in batches (GetMetricData) to keep the checker
fast. All signals are best-effort and will degrade gracefully when permissions
are missing.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from botocore.exceptions import BotoCoreError, ClientError

from checks.aws._common import (
    AwsAccountContext,
    build_scope,
    is_suppressed,
    normalize_tags,
    now_utc,
    safe_region_from_client,
)
from checks.aws.defaults import (
    EFS_LOOKBACK_DAYS,
    EFS_MAX_FINDINGS_PER_TYPE,
    EFS_MIN_DAILY_DATAPOINTS,
    EFS_PERCENT_IO_LIMIT_PERIOD_SECONDS,
    EFS_SUPPRESS_TAG_KEYS,
    EFS_UNDERUTILIZED_P95_PERCENT_IO_LIMIT_THRESHOLD,
    EFS_UNUSED_MAX_CLIENT_CONNECTIONS_THRESHOLD,
    EFS_UNUSED_P95_DAILY_IO_BYTES_THRESHOLD,
)
from checks.registry import Bootstrap, register_checker
from contracts.finops_checker_pattern import Checker, FindingDraft, RunContext, Severity


@dataclass(frozen=True)
class EFSFileSystemsConfig:
    """Configuration knobs for :class:`EFSFileSystemsChecker`."""

    lookback_days: int = EFS_LOOKBACK_DAYS
    min_daily_datapoints: int = EFS_MIN_DAILY_DATAPOINTS

    # "Unused" heuristics
    # Daily p95 of (read+write) bytes must be below this threshold (bytes/day)
    unused_p95_daily_io_bytes_threshold: float = EFS_UNUSED_P95_DAILY_IO_BYTES_THRESHOLD
    # Max client connections over window must be <= this threshold
    unused_max_client_connections_threshold: float = EFS_UNUSED_MAX_CLIENT_CONNECTIONS_THRESHOLD

    # Provisioned throughput underutilization
    underutilized_p95_percent_io_limit_threshold: float = EFS_UNDERUTILIZED_P95_PERCENT_IO_LIMIT_THRESHOLD
    percent_io_limit_period_seconds: int = EFS_PERCENT_IO_LIMIT_PERIOD_SECONDS

    # Suppression tags (lowercased by normalize_tags)
    suppress_tag_keys: Tuple[str, ...] = EFS_SUPPRESS_TAG_KEYS

    # Safety valve
    max_findings_per_type: int = EFS_MAX_FINDINGS_PER_TYPE


def _safe_str(value: Any) -> str:
    return str(value or "")


def _safe_bool(value: Any) -> Optional[bool]:
    if isinstance(value, bool):
        return value
    return None


def _chunk(items: Sequence[Any], size: int) -> Iterable[Sequence[Any]]:
    if size <= 0:
        yield items
        return
    for i in range(0, len(items), size):
        yield items[i : i + size]


def _p95(values: Sequence[float]) -> float:
    """Compute p95 for a small sequence (no numpy dependency)."""
    if not values:
        return 0.0
    vals = sorted(float(v) for v in values)
    # nearest-rank p95
    k = int(round(0.95 * (len(vals) - 1)))
    k = max(0, min(len(vals) - 1, k))
    return float(vals[k])


def _extract_client_error_code(err: Exception) -> str:
    if isinstance(err, ClientError):
        try:
            return str(err.response.get("Error", {}).get("Code", ""))
        except (AttributeError, TypeError, ValueError):  # pragma: no cover
            return ""
    return ""


class EFSFileSystemsChecker(Checker):
    """EFS optimization + governance checker."""

    checker_id = "aws.efs.filesystems"

    # Shared metadata for all findings emitted by this checker.
    _CHECK_NAME = "EFS file systems"
    _CATEGORY_COST = "cost"
    _CATEGORY_GOV = "governance"

    def __init__(self, *, account_id: str, cfg: Optional[EFSFileSystemsConfig] = None) -> None:
        if not str(account_id or "").strip():
            raise ValueError("account_id is required")
        self._account = AwsAccountContext(account_id=str(account_id))
        self._cfg = cfg or EFSFileSystemsConfig()

    # -----------------------------
    # AWS list helpers
    # -----------------------------

    @staticmethod
    def _paginate(client: Any, op_name: str, *, result_key: str, **kwargs: Any) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        paginator = client.get_paginator(op_name)
        for page in paginator.paginate(**kwargs):
            items = page.get(result_key, [])
            if isinstance(items, list):
                for it in items:
                    if isinstance(it, Mapping):
                        out.append(dict(it))
        return out

    def _list_file_systems(self, efs: Any) -> List[Dict[str, Any]]:
        return self._paginate(efs, "describe_file_systems", result_key="FileSystems")

    # -----------------------------
    # CloudWatch metrics
    # -----------------------------

    @staticmethod
    def _metric_query(
        *,
        qid: str,
        metric_name: str,
        fs_id: str,
        stat: str,
        period: int,
        namespace: str = "AWS/EFS",
        unit: Optional[str] = None,
        extended_stat: Optional[str] = None,
    ) -> Dict[str, Any]:
        metric_stat: Dict[str, Any] = {
            "Metric": {"Namespace": namespace, "MetricName": metric_name, "Dimensions": [{"Name": "FileSystemId", "Value": fs_id}]},
            "Period": int(period),
        }
        if extended_stat:
            metric_stat["Stat"] = str(extended_stat)
        else:
            metric_stat["Stat"] = str(stat)
        if unit:
            metric_stat["Unit"] = unit
        return {"Id": qid, "MetricStat": metric_stat, "ReturnData": True}

    def _fetch_metrics(
        self,
        cw: Any,
        *,
        fs_ids: Sequence[str],
        start: datetime,
        end: datetime,
        daily_period: int,
        p95_period: int,
    ) -> Dict[str, Dict[str, List[float]]]:
        """Return metrics by fs_id and metric key."""
        # CloudWatch GetMetricData supports up to 500 queries per call.
        # We need:
        #  - daily read bytes sum
        #  - daily write bytes sum
        #  - daily max client connections
        #  - hourly p95 PercentIOLimit (for provisioned throughput)
        per_fs_queries = 4
        max_fs_per_call = max(1, 500 // per_fs_queries)

        out: Dict[str, Dict[str, List[float]]] = {fs_id: {"read": [], "write": [], "conn": [], "p95": []} for fs_id in fs_ids}

        for batch in _chunk(list(fs_ids), max_fs_per_call):
            queries: List[Dict[str, Any]] = []
            qmap: Dict[str, Tuple[str, str]] = {}
            for i, fs_id in enumerate(batch):
                base = f"m{i}"  # stable within the batch
                q_read = f"{base}r"
                q_write = f"{base}w"
                q_conn = f"{base}c"
                q_p95 = f"{base}p"

                queries.append(self._metric_query(qid=q_read, metric_name="DataReadIOBytes", fs_id=fs_id, stat="Sum", period=daily_period, unit="Bytes"))
                queries.append(self._metric_query(qid=q_write, metric_name="DataWriteIOBytes", fs_id=fs_id, stat="Sum", period=daily_period, unit="Bytes"))
                queries.append(self._metric_query(qid=q_conn, metric_name="ClientConnections", fs_id=fs_id, stat="Maximum", period=daily_period, unit="Count"))
                # PercentIOLimit is a percentage; use extended statistic p95.
                queries.append(self._metric_query(qid=q_p95, metric_name="PercentIOLimit", fs_id=fs_id, stat="Average", period=p95_period, unit="Percent", extended_stat="p95"))

                qmap[q_read] = (fs_id, "read")
                qmap[q_write] = (fs_id, "write")
                qmap[q_conn] = (fs_id, "conn")
                qmap[q_p95] = (fs_id, "p95")

            resp = cw.get_metric_data(
                MetricDataQueries=queries,
                StartTime=start,
                EndTime=end,
                ScanBy="TimestampAscending",
            )
            for r in resp.get("MetricDataResults", []) or []:
                qid = str(r.get("Id") or "")
                if qid not in qmap:
                    continue
                fs_id, key = qmap[qid]
                vals = r.get("Values", [])
                if isinstance(vals, list):
                    out[fs_id][key].extend(float(v) for v in vals if v is not None)

        return out

    # -----------------------------
    # Core run
    # -----------------------------

    def run(self, ctx: RunContext) -> Iterable[FindingDraft]:
        cfg = self._cfg
        services = getattr(ctx, "services", None)
        if services is None:
            raise RuntimeError("RunContext.services is required")

        efs = getattr(services, "efs", None)
        if efs is None:
            raise RuntimeError("EFSFileSystemsChecker requires ctx.services.efs")

        cw = getattr(services, "cloudwatch", None)
        region = safe_region_from_client(efs) or safe_region_from_client(getattr(services, "ec2", None))
        region = str(region or "")

        try:
            file_systems = self._list_file_systems(efs)
        except (ClientError, BotoCoreError, AttributeError, TypeError, ValueError) as exc:
            code = _extract_client_error_code(exc)
            yield FindingDraft(
                check_id="aws.efs.filesystems.access.error",
                check_name=self._CHECK_NAME,
                category=self._CATEGORY_GOV,
                status="unknown",
                severity=Severity(level="medium", score=650),
                title="Unable to list EFS file systems",
                scope=build_scope(ctx, account=self._account, region=region, service="efs"),
                message=f"Unable to list EFS file systems ({code or type(exc).__name__}).",
                issue_key={"check_id": "aws.efs.filesystems.access.error", "region": region},
            )
            return

        # Extract ids + tags
        fs_by_id: Dict[str, Dict[str, Any]] = {}
        tags_by_id: Dict[str, Dict[str, str]] = {}
        for fs in file_systems:
            fs_id = _safe_str(fs.get("FileSystemId"))
            if not fs_id:
                continue
            fs_by_id[fs_id] = fs
            tags = normalize_tags(fs.get("Tags") or fs.get("TagList") or [])
            tags_by_id[fs_id] = tags

        fs_ids = list(fs_by_id.keys())

        # CloudWatch metrics (best-effort)
        metrics: Dict[str, Dict[str, List[float]]] = {fs_id: {"read": [], "write": [], "conn": [], "p95": []} for fs_id in fs_ids}
        if cw is not None and fs_ids:
            end = now_utc()
            start = end - timedelta(days=int(cfg.lookback_days))
            try:
                metrics = self._fetch_metrics(
                    cw,
                    fs_ids=fs_ids,
                    start=start,
                    end=end,
                    daily_period=86400,
                    p95_period=int(cfg.percent_io_limit_period_seconds),
                )
            except (ClientError, BotoCoreError, AttributeError, TypeError, ValueError):
                # Best-effort: metrics unavailable -> skip cost signals that depend on them
                metrics = {fs_id: {"read": [], "write": [], "conn": [], "p95": []} for fs_id in fs_ids}

        suppress_keys = {k.lower() for k in cfg.suppress_tag_keys}

        # Emit findings
        emitted: Dict[str, int] = {}

        def _cap(check_id: str) -> bool:
            c = emitted.get(check_id, 0)
            if c >= cfg.max_findings_per_type:
                return True
            emitted[check_id] = c + 1
            return False

        for fs_id in fs_ids:
            fs = fs_by_id[fs_id]
            tags = tags_by_id.get(fs_id, {})
            if is_suppressed(tags, suppress_keys=suppress_keys):
                continue

            arn = _safe_str(fs.get("FileSystemArn"))
            scope = build_scope(
                ctx,
                account=self._account,
                region=region,
                service="efs",
                resource_type="filesystem",
                resource_id=fs_id,
                resource_arn=arn,
            )

            # 1) Possibly unused
            m = metrics.get(fs_id, {"read": [], "write": [], "conn": [], "p95": []})
            daily_io = [float(r) + float(w) for r, w in zip(m.get("read", []), m.get("write", []))] if m.get("read") and m.get("write") else []
            io_p95 = _p95(daily_io) if daily_io else 0.0
            conn_max = max(m.get("conn", []) or [0.0])
            if (
                len(daily_io) >= int(cfg.min_daily_datapoints)
                and io_p95 <= float(cfg.unused_p95_daily_io_bytes_threshold)
                and conn_max <= float(cfg.unused_max_client_connections_threshold)
            ):
                check_id = "aws.efs.filesystems.unused"
                if not _cap(check_id):
                    yield FindingDraft(
                        check_id=check_id,
                        check_name=self._CHECK_NAME,
                        category=self._CATEGORY_COST,
                        status="fail",
                        severity=Severity(level="medium", score=700),
                        title="Possible unused EFS file system",
                        scope=scope,
                        message=(
                            "Possible unused EFS file system: low IO and no client connections over lookback window. "
                            "Verify before deletion."
                        ),
                        recommendation="Confirm the file system is unused, then delete it to stop incurring storage costs.",
                        tags=tags,
                        dimensions={
                            "lookback_days": str(cfg.lookback_days),
                            "p95_daily_io_bytes": f"{io_p95:.0f}",
                            "max_client_connections": f"{conn_max:.0f}",
                        },
                        issue_key={"check_id": check_id, "file_system_id": fs_id},
                    )

            # 2) Provisioned throughput underutilized (PercentIOLimit)
            throughput_mode = _safe_str(fs.get("ThroughputMode")).lower()
            if throughput_mode == "provisioned":
                p95_vals = m.get("p95", []) or []
                # We requested p95 over hourly periods; take max as a conservative "worst" p95 signal
                p95_pct = max(p95_vals) if p95_vals else 0.0
                if p95_vals and p95_pct <= float(cfg.underutilized_p95_percent_io_limit_threshold):
                    check_id = "aws.efs.filesystems.provisioned.throughput.underutilized"
                    if not _cap(check_id):
                        yield FindingDraft(
                            check_id=check_id,
                            check_name=self._CHECK_NAME,
                            category=self._CATEGORY_COST,
                            status="fail",
                            severity=Severity(level="medium", score=650),
                            title="Provisioned throughput appears underutilized",
                            scope=scope,
                            message=(
                                "Provisioned throughput appears underutilized based on PercentIOLimit. "
                                "Consider switching to bursting or reducing provisioned throughput."
                            ),
                            recommendation="If performance allows, switch to bursting or reduce provisioned throughput to lower cost.",
                            tags=tags,
                            dimensions={
                                "lookback_days": str(cfg.lookback_days),
                                "p95_percent_io_limit_max": f"{p95_pct:.2f}",
                                "throughput_mode": throughput_mode,
                                "provisioned_throughput_mibps": _safe_str(fs.get("ProvisionedThroughputInMibps")),
                            },
                            issue_key={"check_id": check_id, "file_system_id": fs_id},
                        )

            # 3) Lifecycle missing
            check_id = "aws.efs.filesystems.lifecycle.missing"
            try:
                lc = efs.describe_lifecycle_configuration(FileSystemId=fs_id)
                policies = lc.get("LifecyclePolicies", []) if isinstance(lc, Mapping) else []
                has_ia = any(str(p.get("TransitionToIA") or "").strip() for p in (policies or []) if isinstance(p, Mapping))
                has_archive = any(str(p.get("TransitionToArchive") or "").strip() for p in (policies or []) if isinstance(p, Mapping))
                if not has_ia and not has_archive:
                    if not _cap(check_id):
                        yield FindingDraft(
                            check_id=check_id,
                            check_name=self._CHECK_NAME,
                            category=self._CATEGORY_COST,
                            status="fail",
                            severity=Severity(level="low", score=400),
                            title="EFS lifecycle policy is missing",
                            scope=scope,
                            message="EFS lifecycle policy is missing; consider enabling IA/Archive transitions to reduce storage cost.",
                            recommendation="Enable EFS lifecycle transitions (IA/Archive) where appropriate to reduce storage cost.",
                            tags=tags,
                            dimensions={"transition_to_ia": "false", "transition_to_archive": "false"},
                            issue_key={"check_id": check_id, "file_system_id": fs_id},
                        )
            except ClientError as exc:
                code = _extract_client_error_code(exc)
                # PolicyNotFound => no lifecycle config set
                if code in ("PolicyNotFound", "LifecyclePolicyNotFound", "NoSuchLifecycleConfiguration"):
                    if not _cap(check_id):
                        yield FindingDraft(
                            check_id=check_id,
                            check_name=self._CHECK_NAME,
                            category=self._CATEGORY_COST,
                            status="fail",
                            severity=Severity(level="low", score=400),
                            title="EFS lifecycle policy is missing",
                            scope=scope,
                            message="EFS lifecycle policy is missing; consider enabling IA/Archive transitions to reduce storage cost.",
                            recommendation="Enable EFS lifecycle transitions (IA/Archive) where appropriate to reduce storage cost.",
                            tags=tags,
                            dimensions={"transition_to_ia": "false", "transition_to_archive": "false"},
                            issue_key={"check_id": check_id, "file_system_id": fs_id},
                        )
                # Access denied: skip

            # 4) Backup policy
            try:
                bp = efs.describe_backup_policy(FileSystemId=fs_id)
                status = _safe_str((bp.get("BackupPolicy", {}) or {}).get("Status"))
                if status and status.upper() == "DISABLED":
                    bid = "aws.efs.filesystems.backup.disabled"
                    if not _cap(bid):
                        yield FindingDraft(
                            check_id=bid,
                            check_name=self._CHECK_NAME,
                            category=self._CATEGORY_GOV,
                            status="fail",
                            severity=Severity(level="medium", score=700),
                            title="EFS automatic backups are disabled",
                            scope=scope,
                            message="EFS automatic backups are disabled; consider enabling backups or ensuring alternate backup coverage.",
                            recommendation="Enable EFS automatic backups or ensure the file system is covered by an alternate backup solution.",
                            tags=tags,
                            dimensions={"backup_policy": "disabled"},
                            issue_key={"check_id": bid, "file_system_id": fs_id},
                        )
            except ClientError:
                pass

            # 5) Encryption
            enc = _safe_bool(fs.get("Encrypted"))
            if enc is False:
                eid = "aws.efs.filesystems.unencrypted"
                if not _cap(eid):
                    yield FindingDraft(
                        check_id=eid,
                        check_name=self._CHECK_NAME,
                        category=self._CATEGORY_GOV,
                        status="fail",
                        severity=Severity(level="high", score=900),
                        title="EFS file system is unencrypted",
                        scope=scope,
                        message="EFS file system is unencrypted at rest. Enable encryption to meet security requirements.",
                        recommendation="Create a new encrypted EFS file system and migrate data (encryption cannot be enabled in-place).",
                        tags=tags,
                        dimensions={"encrypted": "false"},
                        issue_key={"check_id": eid, "file_system_id": fs_id},
                    )


@register_checker("checks.aws.efs_filesystems:EFSFileSystemsChecker")
def _factory(ctx: RunContext, bootstrap: Bootstrap) -> Checker:
    account_id = str(bootstrap.get("aws_account_id") or "")
    if not account_id:
        raise ValueError("bootstrap['aws_account_id'] is required for EFSFileSystemsChecker")
    return EFSFileSystemsChecker(account_id=account_id)
