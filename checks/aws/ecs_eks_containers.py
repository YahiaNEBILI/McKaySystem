"""ECS/EKS containers optimization and governance checker.

Signals (ECS):
1) Possibly unused ECS cluster (no active services or running tasks)
2) ECS service desired count > 0 but running count == 0
3) Non-production ECS Fargate services without spot capacity strategy

Signals (EKS):
4) EKS cluster endpoint is public-only
5) EKS control-plane logging disabled
6) EKS cluster Kubernetes version below configured minimum
7) Non-production EKS managed nodegroups using on-demand capacity
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, Iterator, List, Mapping, Optional, Sequence, Tuple

from botocore.exceptions import BotoCoreError, ClientError, OperationNotPageableError

from checks.aws._common import (
    AwsAccountContext,
    build_scope,
    get_logger,
    normalize_tags,
    safe_region_from_client,
)
from checks.aws.defaults import (
    CONTAINERS_MAX_FINDINGS_PER_TYPE,
    CONTAINERS_NONPROD_TAG_KEYS,
    CONTAINERS_NONPROD_TAG_VALUES,
    EKS_MIN_SUPPORTED_VERSION,
)
from checks.registry import Bootstrap, register_checker
from contracts.finops_checker_pattern import Checker, FindingDraft, RunContext, Severity

_LOGGER = get_logger("ecs_eks_containers")


@dataclass(frozen=True)
class EcsEksContainersConfig:
    """Configuration knobs for :class:`EcsEksContainersChecker`."""

    max_findings_per_type: int = CONTAINERS_MAX_FINDINGS_PER_TYPE
    nonprod_tag_keys: Tuple[str, ...] = CONTAINERS_NONPROD_TAG_KEYS
    nonprod_tag_values: Tuple[str, ...] = CONTAINERS_NONPROD_TAG_VALUES
    eks_min_supported_version: Tuple[int, int] = EKS_MIN_SUPPORTED_VERSION


def _to_int(value: Any, default: int = 0) -> int:
    try:
        if value is None:
            return int(default)
        return int(value)
    except (TypeError, ValueError):
        return int(default)


def _is_access_denied(exc: ClientError) -> bool:
    try:
        code = str(exc.response.get("Error", {}).get("Code") or "")
    except (TypeError, ValueError, AttributeError):
        return False
    return code in {
        "AccessDenied",
        "AccessDeniedException",
        "UnauthorizedOperation",
        "UnrecognizedClientException",
    }


def _normalize_tags_any(raw_tags: Any) -> dict[str, str]:
    """Normalize tags from common AWS shapes, including ECS lower-case tags."""
    normalized = normalize_tags(raw_tags)
    if normalized:
        return normalized

    if isinstance(raw_tags, list):
        out: dict[str, str] = {}
        for item in raw_tags:
            if not isinstance(item, Mapping):
                continue
            key = str(item.get("Key") or item.get("key") or "").strip().lower()
            if not key:
                continue
            val = str(item.get("Value") or item.get("value") or "").strip().lower()
            out[key] = val
        return out
    return {}


def _paginate_strings(
    client: Any,
    operation: str,
    result_key: str,
    *,
    params: Optional[Dict[str, Any]] = None,
    request_token_key: str = "nextToken",
    response_token_keys: Sequence[str] = ("nextToken", "NextToken"),
) -> Iterator[str]:
    """Yield string items from paginator when available, else token-loop fallback."""
    call_params = dict(params or {})

    if hasattr(client, "get_paginator"):
        try:
            paginator = client.get_paginator(operation)
            for page in paginator.paginate(**call_params):
                for item in page.get(result_key, []) or []:
                    text = str(item or "").strip()
                    if text:
                        yield text
            return
        except (OperationNotPageableError, AttributeError, KeyError, TypeError, ValueError):
            pass

    call = getattr(client, operation, None)
    if not callable(call):
        raise AttributeError(f"client has no operation {operation}")

    next_token: Optional[str] = None
    while True:
        req = dict(call_params)
        if next_token:
            req[request_token_key] = next_token
        resp = call(**req) if req else call()
        for item in resp.get(result_key, []) or []:
            text = str(item or "").strip()
            if text:
                yield text

        next_token = None
        for key in response_token_keys:
            token = resp.get(key)
            if token:
                next_token = str(token)
                break
        if not next_token:
            break


def _parse_k8s_version(version: str) -> Optional[Tuple[int, int]]:
    """Parse Kubernetes version like '1.27' or '1.27.6' into (major, minor)."""
    text = str(version or "").strip()
    if not text:
        return None
    parts = text.split(".")
    if len(parts) < 2:
        return None
    try:
        major = int(parts[0])
        minor_text = parts[1]
        digits = ""
        for ch in minor_text:
            if ch.isdigit():
                digits += ch
            else:
                break
        if not digits:
            return None
        minor = int(digits)
    except (TypeError, ValueError):
        return None
    return major, minor


def _cluster_name_from_arn(cluster_arn: str) -> str:
    marker = "cluster/"
    text = str(cluster_arn or "")
    if marker in text:
        return text.split(marker, 1)[1]
    return text


def _service_name_from_arn(service_arn: str) -> str:
    marker = "service/"
    text = str(service_arn or "")
    if marker in text:
        return text.split(marker, 1)[1]
    return text


class EcsEksContainersChecker(Checker):
    """ECS/EKS containers checker."""

    checker_id = "aws.containers.ecs_eks.audit"

    def __init__(
        self,
        *,
        account: AwsAccountContext,
        cfg: Optional[EcsEksContainersConfig] = None,
    ) -> None:
        self._account = account
        self._cfg = cfg or EcsEksContainersConfig()

    def run(self, ctx: RunContext) -> Iterable[FindingDraft]:
        _LOGGER.info("Starting ECS/EKS containers check")
        services = getattr(ctx, "services", None)
        if services is None:
            return []

        ecs = getattr(services, "ecs", None)
        eks = getattr(services, "eks", None)
        if ecs is None and eks is None:
            return []

        region = (
            safe_region_from_client(ecs)
            or safe_region_from_client(eks)
            or str(getattr(services, "region", "") or "")
        )
        emitted: Dict[str, int] = {}

        if ecs is not None:
            for finding in self._run_ecs(ctx, ecs=ecs, region=region, emitted=emitted):
                yield finding

        if eks is not None:
            for finding in self._run_eks(ctx, eks=eks, region=region, emitted=emitted):
                yield finding

    def _run_ecs(
        self,
        ctx: RunContext,
        *,
        ecs: Any,
        region: str,
        emitted: Dict[str, int],
    ) -> Iterable[FindingDraft]:
        try:
            cluster_arns = list(_paginate_strings(ecs, "list_clusters", "clusterArns"))
        except ClientError as exc:
            if _is_access_denied(exc):
                yield self._access_error(ctx, region=region, service="ecs", action="ecs:ListClusters", exc=exc)
                return
            raise

        if not cluster_arns:
            return

        clusters = self._describe_ecs_clusters(ecs, cluster_arns)
        for cluster in clusters:
            cluster_arn = str(cluster.get("clusterArn") or "")
            cluster_name = str(cluster.get("clusterName") or _cluster_name_from_arn(cluster_arn))
            cluster_tags = _normalize_tags_any(cluster.get("tags"))

            active_services = _to_int(cluster.get("activeServicesCount"))
            running_tasks = _to_int(cluster.get("runningTasksCount"))
            pending_tasks = _to_int(cluster.get("pendingTasksCount"))
            registered_instances = _to_int(cluster.get("registeredContainerInstancesCount"))

            if (
                active_services == 0
                and running_tasks == 0
                and pending_tasks == 0
                and registered_instances == 0
            ):
                check_id = "aws.ecs.cluster.possibly.unused"
                if self._should_emit(check_id, emitted):
                    yield FindingDraft(
                        check_id=check_id,
                        check_name="ECS cluster possibly unused",
                        category="cost",
                        status="info",
                        severity=Severity(level="low", score=240),
                        title=f"ECS cluster appears idle: {cluster_name}",
                        scope=build_scope(
                            ctx,
                            account=self._account,
                            region=region,
                            service="ecs",
                            resource_type="cluster",
                            resource_id=cluster_name,
                            resource_arn=cluster_arn,
                        ),
                        message=(
                            "Cluster has no active services, running tasks, pending tasks, or "
                            "registered container instances."
                        ),
                        recommendation=(
                            "If this cluster is no longer required, delete it and clean up related "
                            "service/task definitions to reduce operational sprawl."
                        ),
                        tags=cluster_tags,
                        issue_key={
                            "signal": "cluster_idle",
                            "cluster_arn": cluster_arn,
                        },
                    )

            try:
                service_arns = list(
                    _paginate_strings(
                        ecs,
                        "list_services",
                        "serviceArns",
                        params={"cluster": cluster_arn},
                    )
                )
            except ClientError as exc:
                if _is_access_denied(exc):
                    check_id = "aws.containers.access.error"
                    if self._should_emit(check_id, emitted):
                        yield self._access_error(
                            ctx,
                            region=region,
                            service="ecs",
                            action="ecs:ListServices",
                            exc=exc,
                        )
                    continue
                raise

            for svc in self._describe_ecs_services(ecs, cluster_arn=cluster_arn, service_arns=service_arns):
                service_arn = str(svc.get("serviceArn") or "")
                service_name = str(svc.get("serviceName") or _service_name_from_arn(service_arn))
                service_tags = _normalize_tags_any(svc.get("tags"))
                tags = dict(cluster_tags)
                tags.update(service_tags)

                status = str(svc.get("status") or "").upper()
                desired_count = _to_int(svc.get("desiredCount"))
                running_count = _to_int(svc.get("runningCount"))

                if status == "ACTIVE" and desired_count > 0 and running_count == 0:
                    check_id = "aws.ecs.service.zero.running"
                    if self._should_emit(check_id, emitted):
                        yield FindingDraft(
                            check_id=check_id,
                            check_name="ECS service desired tasks not running",
                            category="governance",
                            status="fail",
                            severity=Severity(level="medium", score=620),
                            title=f"ECS service has zero running tasks: {service_name}",
                            scope=build_scope(
                                ctx,
                                account=self._account,
                                region=region,
                                service="ecs",
                                resource_type="service",
                                resource_id=service_name,
                                resource_arn=service_arn,
                            ),
                            message=(
                                f"Service is ACTIVE with desiredCount={desired_count} "
                                f"but runningCount={running_count}."
                            ),
                            recommendation=(
                                "Investigate deployment, capacity, and task definition failures. "
                                "Restore healthy running tasks or scale down if the service is intentionally inactive."
                            ),
                            tags=tags,
                            dimensions={
                                "cluster_name": cluster_name,
                                "desired_count": str(desired_count),
                                "running_count": str(running_count),
                            },
                            issue_key={
                                "signal": "zero_running_tasks",
                                "service_arn": service_arn,
                                "cluster_arn": cluster_arn,
                            },
                        )

                if not (status == "ACTIVE" and desired_count > 0 and self._is_non_prod(tags)):
                    continue

                cp_strategy = svc.get("capacityProviderStrategy") or []
                providers: List[str] = []
                if isinstance(cp_strategy, list):
                    for item in cp_strategy:
                        if not isinstance(item, Mapping):
                            continue
                        cp_name = str(item.get("capacityProvider") or "").strip().upper()
                        if cp_name:
                            providers.append(cp_name)
                launch_type = str(svc.get("launchType") or "").strip().upper()
                uses_fargate = launch_type == "FARGATE" or "FARGATE" in providers
                uses_spot = any(name.endswith("SPOT") for name in providers)

                if uses_fargate and not uses_spot:
                    check_id = "aws.ecs.service.nonprod.on_demand"
                    if self._should_emit(check_id, emitted):
                        yield FindingDraft(
                            check_id=check_id,
                            check_name="Non-production ECS service on on-demand Fargate",
                            category="cost",
                            status="info",
                            severity=Severity(level="low", score=260),
                            title=f"ECS non-prod service may use higher-cost capacity: {service_name}",
                            scope=build_scope(
                                ctx,
                                account=self._account,
                                region=region,
                                service="ecs",
                                resource_type="service",
                                resource_id=service_name,
                                resource_arn=service_arn,
                            ),
                            message=(
                                "Non-production service appears to run on Fargate without spot capacity providers."
                            ),
                            recommendation=(
                                "Evaluate adding FARGATE_SPOT to the service capacity provider strategy "
                                "for lower-cost non-production workloads."
                            ),
                            tags=tags,
                            dimensions={
                                "cluster_name": cluster_name,
                                "launch_type": launch_type,
                                "capacity_providers": ",".join(sorted(set(providers))),
                            },
                            issue_key={
                                "signal": "nonprod_fargate_no_spot",
                                "service_arn": service_arn,
                                "cluster_arn": cluster_arn,
                            },
                        )

    def _describe_ecs_clusters(self, ecs: Any, cluster_arns: Sequence[str]) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for i in range(0, len(cluster_arns), 100):
            batch = list(cluster_arns[i : i + 100])
            if not batch:
                continue
            try:
                resp = ecs.describe_clusters(
                    clusters=batch,
                    include=["STATISTICS", "TAGS", "SETTINGS", "CONFIGURATIONS"],
                )
            except (ClientError, BotoCoreError):
                continue
            for cluster in (resp or {}).get("clusters", []) or []:
                if isinstance(cluster, Mapping):
                    out.append(dict(cluster))
        return out

    def _describe_ecs_services(
        self,
        ecs: Any,
        *,
        cluster_arn: str,
        service_arns: Sequence[str],
    ) -> Iterator[Dict[str, Any]]:
        for i in range(0, len(service_arns), 10):
            batch = list(service_arns[i : i + 10])
            if not batch:
                continue
            try:
                resp = ecs.describe_services(cluster=cluster_arn, services=batch, include=["TAGS"])
            except (ClientError, BotoCoreError):
                continue
            for service in (resp or {}).get("services", []) or []:
                if isinstance(service, Mapping):
                    yield dict(service)

    def _run_eks(
        self,
        ctx: RunContext,
        *,
        eks: Any,
        region: str,
        emitted: Dict[str, int],
    ) -> Iterable[FindingDraft]:
        try:
            cluster_names = list(_paginate_strings(eks, "list_clusters", "clusters"))
        except ClientError as exc:
            if _is_access_denied(exc):
                yield self._access_error(ctx, region=region, service="eks", action="eks:ListClusters", exc=exc)
                return
            raise

        for cluster_name in cluster_names:
            try:
                cluster_resp = eks.describe_cluster(name=cluster_name)
            except ClientError as exc:
                if _is_access_denied(exc):
                    check_id = "aws.containers.access.error"
                    if self._should_emit(check_id, emitted):
                        yield self._access_error(
                            ctx,
                            region=region,
                            service="eks",
                            action="eks:DescribeCluster",
                            exc=exc,
                        )
                    continue
                raise

            cluster = (cluster_resp or {}).get("cluster") or {}
            if not isinstance(cluster, Mapping):
                continue

            cluster_arn = str(cluster.get("arn") or "")
            cluster_tags = _normalize_tags_any(cluster.get("tags"))
            vpc_cfg = cluster.get("resourcesVpcConfig") or {}
            endpoint_public = bool(vpc_cfg.get("endpointPublicAccess"))
            endpoint_private = bool(vpc_cfg.get("endpointPrivateAccess"))
            if endpoint_public and not endpoint_private:
                check_id = "aws.eks.cluster.endpoint.public.only"
                if self._should_emit(check_id, emitted):
                    yield FindingDraft(
                        check_id=check_id,
                        check_name="EKS cluster endpoint is public-only",
                        category="governance",
                        status="fail",
                        severity=Severity(level="high", score=820),
                        title=f"EKS cluster endpoint is exposed publicly: {cluster_name}",
                        scope=build_scope(
                            ctx,
                            account=self._account,
                            region=region,
                            service="eks",
                            resource_type="cluster",
                            resource_id=cluster_name,
                            resource_arn=cluster_arn,
                        ),
                        message="Cluster API endpoint allows public access while private endpoint access is disabled.",
                        recommendation=(
                            "Enable private endpoint access and restrict public CIDRs to minimize control-plane exposure."
                        ),
                        tags=cluster_tags,
                        issue_key={"signal": "public_only_endpoint", "cluster_name": cluster_name},
                    )

            cluster_logging = (cluster.get("logging") or {}).get("clusterLogging") or []
            any_logging_enabled = False
            if isinstance(cluster_logging, list):
                any_logging_enabled = any(
                    bool(item.get("enabled")) for item in cluster_logging if isinstance(item, Mapping)
                )
            if not any_logging_enabled:
                check_id = "aws.eks.cluster.controlplane.logging.disabled"
                if self._should_emit(check_id, emitted):
                    yield FindingDraft(
                        check_id=check_id,
                        check_name="EKS control plane logging disabled",
                        category="governance",
                        status="info",
                        severity=Severity(level="medium", score=520),
                        title=f"EKS control plane logging is disabled: {cluster_name}",
                        scope=build_scope(
                            ctx,
                            account=self._account,
                            region=region,
                            service="eks",
                            resource_type="cluster",
                            resource_id=cluster_name,
                            resource_arn=cluster_arn,
                        ),
                        message="Cluster control-plane logs are disabled for all log types.",
                        recommendation="Enable required EKS control-plane logs to improve incident response and auditability.",
                        tags=cluster_tags,
                        issue_key={"signal": "controlplane_logging_disabled", "cluster_name": cluster_name},
                    )

            version = str(cluster.get("version") or "")
            parsed = _parse_k8s_version(version)
            if parsed is not None and parsed < self._cfg.eks_min_supported_version:
                target = f"{self._cfg.eks_min_supported_version[0]}.{self._cfg.eks_min_supported_version[1]}"
                check_id = "aws.eks.cluster.version.outdated"
                if self._should_emit(check_id, emitted):
                    yield FindingDraft(
                        check_id=check_id,
                        check_name="EKS cluster Kubernetes version outdated",
                        category="governance",
                        status="fail",
                        severity=Severity(level="medium", score=610),
                        title=f"EKS cluster Kubernetes version is outdated: {cluster_name}",
                        scope=build_scope(
                            ctx,
                            account=self._account,
                            region=region,
                            service="eks",
                            resource_type="cluster",
                            resource_id=cluster_name,
                            resource_arn=cluster_arn,
                        ),
                        message=f"Cluster version is {version}; minimum recommended baseline is {target}.",
                        recommendation="Plan an EKS version upgrade to a currently supported baseline version.",
                        tags=cluster_tags,
                        dimensions={"cluster_version": version, "recommended_min_version": target},
                        issue_key={"signal": "cluster_version_outdated", "cluster_name": cluster_name},
                    )

            try:
                nodegroups = list(
                    _paginate_strings(
                        eks,
                        "list_nodegroups",
                        "nodegroups",
                        params={"clusterName": cluster_name},
                    )
                )
            except ClientError as exc:
                if _is_access_denied(exc):
                    check_id = "aws.containers.access.error"
                    if self._should_emit(check_id, emitted):
                        yield self._access_error(
                            ctx,
                            region=region,
                            service="eks",
                            action="eks:ListNodegroups",
                            exc=exc,
                        )
                    continue
                raise

            for ng_name in nodegroups:
                try:
                    ng_resp = eks.describe_nodegroup(clusterName=cluster_name, nodegroupName=ng_name)
                except ClientError as exc:
                    if _is_access_denied(exc):
                        check_id = "aws.containers.access.error"
                        if self._should_emit(check_id, emitted):
                            yield self._access_error(
                                ctx,
                                region=region,
                                service="eks",
                                action="eks:DescribeNodegroup",
                                exc=exc,
                            )
                        continue
                    raise
                nodegroup = (ng_resp or {}).get("nodegroup") or {}
                if not isinstance(nodegroup, Mapping):
                    continue

                nodegroup_arn = str(nodegroup.get("nodegroupArn") or "")
                nodegroup_tags = _normalize_tags_any(nodegroup.get("tags"))
                merged_tags = dict(cluster_tags)
                merged_tags.update(nodegroup_tags)
                desired_size = _to_int((nodegroup.get("scalingConfig") or {}).get("desiredSize"))
                capacity_type = str(nodegroup.get("capacityType") or "ON_DEMAND").upper()

                if desired_size > 0 and capacity_type == "ON_DEMAND" and self._is_non_prod(merged_tags):
                    check_id = "aws.eks.nodegroup.nonprod.on_demand"
                    if self._should_emit(check_id, emitted):
                        yield FindingDraft(
                            check_id=check_id,
                            check_name="Non-production EKS nodegroup on on-demand capacity",
                            category="cost",
                            status="info",
                            severity=Severity(level="low", score=270),
                            title=f"EKS non-prod nodegroup may use higher-cost capacity: {ng_name}",
                            scope=build_scope(
                                ctx,
                                account=self._account,
                                region=region,
                                service="eks",
                                resource_type="nodegroup",
                                resource_id=ng_name,
                                resource_arn=nodegroup_arn,
                            ),
                            message=(
                                "Non-production nodegroup is using ON_DEMAND capacity with desired nodes > 0."
                            ),
                            recommendation=(
                                "Evaluate SPOT capacity for non-production nodegroups to reduce compute costs."
                            ),
                            tags=merged_tags,
                            dimensions={
                                "cluster_name": cluster_name,
                                "desired_size": str(desired_size),
                                "capacity_type": capacity_type,
                            },
                            issue_key={
                                "signal": "nonprod_nodegroup_ondemand",
                                "cluster_name": cluster_name,
                                "nodegroup_name": ng_name,
                            },
                        )

    def _access_error(
        self,
        ctx: RunContext,
        *,
        region: str,
        service: str,
        action: str,
        exc: ClientError,
    ) -> FindingDraft:
        code = ""
        try:
            code = str(exc.response.get("Error", {}).get("Code") or "")
        except (TypeError, ValueError, AttributeError):
            code = ""
        return FindingDraft(
            check_id="aws.containers.access.error",
            check_name="Containers API access error",
            category="governance",
            status="info",
            severity=Severity(level="info", score=0),
            title="Unable to collect full ECS/EKS inventory due to IAM restrictions",
            scope=build_scope(
                ctx,
                account=self._account,
                region=region,
                service=service,
                resource_type="account",
                resource_id=self._account.account_id,
            ),
            message=f"Access denied calling {action} in region '{region}'. ErrorCode={code}",
            recommendation=(
                "Grant least-privilege read permissions for ECS/EKS inventory APIs to enable full containers checks."
            ),
            issue_key={"signal": "access_error", "service": service, "action": action, "region": region},
        )

    def _is_non_prod(self, tags: Mapping[str, str]) -> bool:
        keys = {str(k).strip().lower() for k in self._cfg.nonprod_tag_keys}
        values = {str(v).strip().lower() for v in self._cfg.nonprod_tag_values}
        for key, value in tags.items():
            k = str(key or "").strip().lower()
            v = str(value or "").strip().lower()
            if k in keys and v in values:
                return True
        return False

    def _should_emit(self, check_id: str, emitted: Dict[str, int]) -> bool:
        count = int(emitted.get(check_id, 0))
        if count >= self._cfg.max_findings_per_type:
            return False
        emitted[check_id] = count + 1
        return True


@register_checker("checks.aws.ecs_eks_containers:EcsEksContainersChecker")
def _factory(ctx: RunContext, bootstrap: Bootstrap) -> EcsEksContainersChecker:
    account_id = str(bootstrap.get("aws_account_id") or "")
    if not account_id:
        raise RuntimeError("aws_account_id missing from bootstrap (required for EcsEksContainersChecker)")
    billing_account_id = str(bootstrap.get("aws_billing_account_id") or account_id)
    return EcsEksContainersChecker(
        account=AwsAccountContext(account_id=account_id, billing_account_id=billing_account_id),
    )

