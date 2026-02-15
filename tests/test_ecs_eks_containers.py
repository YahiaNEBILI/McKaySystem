"""Unit tests for ECS/EKS containers checker."""

from __future__ import annotations

from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any, Dict, Iterable, List, Mapping, Optional, cast

import pytest
from botocore.exceptions import ClientError

from checks.aws.ecs_eks_containers import EcsEksContainersChecker
from contracts.finops_checker_pattern import RunContext


class FakePaginator:
    def __init__(
        self,
        pages: Optional[List[Mapping[str, Any]]] = None,
        paginate_fn: Optional[Any] = None,
    ) -> None:
        self._pages = pages
        self._paginate_fn = paginate_fn

    def paginate(self, **_kwargs: Any) -> Iterable[Mapping[str, Any]]:
        if callable(self._paginate_fn):
            yield from self._paginate_fn(**_kwargs)
            return
        yield from (self._pages or [])


class FakeECS:
    """Minimal ECS fake for checker tests."""

    def __init__(
        self,
        *,
        region: str,
        cluster_arns: List[str],
        clusters_by_arn: Dict[str, Mapping[str, Any]],
        service_arns_by_cluster: Dict[str, List[str]],
        services_by_arn: Dict[str, Mapping[str, Any]],
        raise_on: Optional[str] = None,
    ) -> None:
        self.meta = SimpleNamespace(region_name=region)
        self._cluster_arns = cluster_arns
        self._clusters_by_arn = clusters_by_arn
        self._service_arns_by_cluster = service_arns_by_cluster
        self._services_by_arn = services_by_arn
        self._raise_on = raise_on

    def get_paginator(self, op_name: str) -> FakePaginator:
        if self._raise_on == op_name:
            raise ClientError(
                {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
                op_name,
            )

        if op_name == "list_clusters":
            return FakePaginator([{"clusterArns": list(self._cluster_arns)}])

        if op_name == "list_services":
            def _pages(**kwargs: Any) -> Iterable[Mapping[str, Any]]:
                cluster = str(kwargs.get("cluster") or "")
                yield {"serviceArns": list(self._service_arns_by_cluster.get(cluster, []))}

            return FakePaginator(paginate_fn=_pages)

        raise KeyError(op_name)

    def list_services(self, *, cluster: str, **_kwargs: Any) -> Mapping[str, Any]:
        if self._raise_on == "list_services":
            raise ClientError(
                {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
                "list_services",
            )
        return {"serviceArns": list(self._service_arns_by_cluster.get(cluster, []))}

    def describe_clusters(self, *, clusters: List[str], **_kwargs: Any) -> Mapping[str, Any]:
        items = [dict(self._clusters_by_arn[c]) for c in clusters if c in self._clusters_by_arn]
        return {"clusters": items}

    def describe_services(self, *, cluster: str, services: List[str], **_kwargs: Any) -> Mapping[str, Any]:
        _ = cluster
        items = [dict(self._services_by_arn[s]) for s in services if s in self._services_by_arn]
        return {"services": items}


class FakeEKS:
    """Minimal EKS fake for checker tests."""

    def __init__(
        self,
        *,
        region: str,
        clusters: List[str],
        clusters_by_name: Dict[str, Mapping[str, Any]],
        nodegroups_by_cluster: Dict[str, List[str]],
        nodegroups_by_name: Dict[tuple[str, str], Mapping[str, Any]],
        raise_on: Optional[str] = None,
    ) -> None:
        self.meta = SimpleNamespace(region_name=region)
        self._clusters = clusters
        self._clusters_by_name = clusters_by_name
        self._nodegroups_by_cluster = nodegroups_by_cluster
        self._nodegroups_by_name = nodegroups_by_name
        self._raise_on = raise_on

    def get_paginator(self, op_name: str) -> FakePaginator:
        if self._raise_on == op_name:
            raise ClientError(
                {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
                op_name,
            )

        if op_name == "list_clusters":
            return FakePaginator([{"clusters": list(self._clusters)}])

        if op_name == "list_nodegroups":
            def _pages(**kwargs: Any) -> Iterable[Mapping[str, Any]]:
                cluster = str(kwargs.get("clusterName") or "")
                yield {"nodegroups": list(self._nodegroups_by_cluster.get(cluster, []))}

            return FakePaginator(paginate_fn=_pages)

        raise KeyError(op_name)

    def list_nodegroups(self, *, clusterName: str, **_kwargs: Any) -> Mapping[str, Any]:
        if self._raise_on == "list_nodegroups":
            raise ClientError(
                {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
                "list_nodegroups",
            )
        return {"nodegroups": list(self._nodegroups_by_cluster.get(clusterName, []))}

    def describe_cluster(self, *, name: str) -> Mapping[str, Any]:
        if self._raise_on == "describe_cluster":
            raise ClientError(
                {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
                "describe_cluster",
            )
        return {"cluster": dict(self._clusters_by_name.get(name, {}))}

    def describe_nodegroup(self, *, clusterName: str, nodegroupName: str) -> Mapping[str, Any]:
        if self._raise_on == "describe_nodegroup":
            raise ClientError(
                {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
                "describe_nodegroup",
            )
        return {"nodegroup": dict(self._nodegroups_by_name.get((clusterName, nodegroupName), {}))}


@dataclass
class _Services:
    ecs: Any = None
    eks: Any = None
    region: str = ""


def _mk_ctx(*, ecs: Any = None, eks: Any = None, region: str = "eu-west-1") -> RunContext:
    return cast(
        RunContext,
        SimpleNamespace(
            cloud="aws",
            services=_Services(ecs=ecs, eks=eks, region=region),
        ),
    )


def _checker() -> EcsEksContainersChecker:
    import checks.aws.ecs_eks_containers as mod

    return EcsEksContainersChecker(
        account=mod.AwsAccountContext(account_id="111111111111", billing_account_id="111111111111")
    )


def test_ecs_unused_cluster_and_zero_running_service_emit() -> None:
    cluster_arn = "arn:aws:ecs:eu-west-1:111111111111:cluster/prod-cluster"
    service_arn = "arn:aws:ecs:eu-west-1:111111111111:service/prod-cluster/api"

    ecs = FakeECS(
        region="eu-west-1",
        cluster_arns=[cluster_arn],
        clusters_by_arn={
            cluster_arn: {
                "clusterArn": cluster_arn,
                "clusterName": "prod-cluster",
                "activeServicesCount": 0,
                "runningTasksCount": 0,
                "pendingTasksCount": 0,
                "registeredContainerInstancesCount": 0,
                "tags": [{"key": "env", "value": "prod"}],
            }
        },
        service_arns_by_cluster={cluster_arn: [service_arn]},
        services_by_arn={
            service_arn: {
                "serviceArn": service_arn,
                "serviceName": "api",
                "status": "ACTIVE",
                "desiredCount": 2,
                "runningCount": 0,
                "launchType": "FARGATE",
                "tags": [{"key": "env", "value": "prod"}],
            }
        },
    )

    findings = list(_checker().run(_mk_ctx(ecs=ecs)))
    check_ids = {f.check_id for f in findings}
    assert "aws.ecs.cluster.possibly.unused" in check_ids
    assert "aws.ecs.service.zero.running" in check_ids


def test_ecs_nonprod_fargate_without_spot_emits() -> None:
    cluster_arn = "arn:aws:ecs:eu-west-1:111111111111:cluster/dev-cluster"
    service_arn = "arn:aws:ecs:eu-west-1:111111111111:service/dev-cluster/worker"

    ecs = FakeECS(
        region="eu-west-1",
        cluster_arns=[cluster_arn],
        clusters_by_arn={
            cluster_arn: {
                "clusterArn": cluster_arn,
                "clusterName": "dev-cluster",
                "activeServicesCount": 1,
                "runningTasksCount": 2,
                "pendingTasksCount": 0,
                "registeredContainerInstancesCount": 0,
                "tags": [{"key": "env", "value": "dev"}],
            }
        },
        service_arns_by_cluster={cluster_arn: [service_arn]},
        services_by_arn={
            service_arn: {
                "serviceArn": service_arn,
                "serviceName": "worker",
                "status": "ACTIVE",
                "desiredCount": 2,
                "runningCount": 2,
                "launchType": "FARGATE",
                "capacityProviderStrategy": [{"capacityProvider": "FARGATE"}],
                "tags": [{"key": "env", "value": "dev"}],
            }
        },
    )

    findings = list(_checker().run(_mk_ctx(ecs=ecs)))
    assert any(f.check_id == "aws.ecs.service.nonprod.on_demand" for f in findings)


def test_eks_cluster_and_nodegroup_signals_emit() -> None:
    cluster_name = "dev-eks"
    cluster_arn = "arn:aws:eks:eu-west-1:111111111111:cluster/dev-eks"
    ng_name = "ng-app"
    ng_arn = "arn:aws:eks:eu-west-1:111111111111:nodegroup/dev-eks/ng-app/id"

    eks = FakeEKS(
        region="eu-west-1",
        clusters=[cluster_name],
        clusters_by_name={
            cluster_name: {
                "name": cluster_name,
                "arn": cluster_arn,
                "version": "1.26",
                "resourcesVpcConfig": {
                    "endpointPublicAccess": True,
                    "endpointPrivateAccess": False,
                },
                "logging": {"clusterLogging": [{"types": ["api"], "enabled": False}]},
                "tags": {"env": "dev"},
            }
        },
        nodegroups_by_cluster={cluster_name: [ng_name]},
        nodegroups_by_name={
            (cluster_name, ng_name): {
                "nodegroupName": ng_name,
                "nodegroupArn": ng_arn,
                "capacityType": "ON_DEMAND",
                "scalingConfig": {"desiredSize": 3},
                "tags": {"team": "platform"},
            }
        },
    )

    findings = list(_checker().run(_mk_ctx(eks=eks)))
    check_ids = {f.check_id for f in findings}
    assert "aws.eks.cluster.endpoint.public.only" in check_ids
    assert "aws.eks.cluster.controlplane.logging.disabled" in check_ids
    assert "aws.eks.cluster.version.outdated" in check_ids
    assert "aws.eks.nodegroup.nonprod.on_demand" in check_ids


def test_access_denied_emits_access_error() -> None:
    eks = FakeEKS(
        region="eu-west-1",
        clusters=[],
        clusters_by_name={},
        nodegroups_by_cluster={},
        nodegroups_by_name={},
        raise_on="list_clusters",
    )
    findings = list(_checker().run(_mk_ctx(eks=eks)))
    assert len(findings) == 1
    assert findings[0].check_id == "aws.containers.access.error"
    assert findings[0].status == "info"
