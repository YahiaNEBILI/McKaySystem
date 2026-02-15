# AWS ECS/EKS Containers checker

Status: Canonical  
Last reviewed: 2026-02-15

**Source code:** `checks/aws/ecs_eks_containers.py`

## Purpose

Detect ECS and EKS container-platform optimization and governance issues.

## Checker identity

- `checker_id`: `aws.containers.ecs_eks.audit`
- `spec`: `checks.aws.ecs_eks_containers:EcsEksContainersChecker`

## Check IDs emitted

- `aws.ecs.cluster.possibly.unused`
- `aws.ecs.service.zero.running`
- `aws.ecs.service.nonprod.on_demand`
- `aws.eks.cluster.endpoint.public.only`
- `aws.eks.cluster.controlplane.logging.disabled`
- `aws.eks.cluster.version.outdated`
- `aws.eks.nodegroup.nonprod.on_demand`
- `aws.containers.access.error`

## Key signals

ECS:
- Possibly unused clusters.
- Services with desired tasks but zero running tasks.
- Non-production services not using spot-oriented capacity strategy.

EKS:
- Public-only cluster endpoint posture.
- Control-plane logging disabled.
- Kubernetes version below configured minimum.
- Non-production managed node groups using on-demand capacity.

## Configuration and defaults

Configured via `EcsEksContainersConfig`.
Defaults are sourced from `checks/aws/defaults.py`, including:
- `CONTAINERS_MAX_FINDINGS_PER_TYPE`
- `CONTAINERS_NONPROD_TAG_KEYS`
- `CONTAINERS_NONPROD_TAG_VALUES`
- `EKS_MIN_SUPPORTED_VERSION`

## IAM permissions

Typical read-only permissions:
- `ecs:ListClusters`
- `ecs:DescribeClusters`
- `ecs:ListServices`
- `ecs:DescribeServices`
- `ecs:ListTasks`
- `eks:ListClusters`
- `eks:DescribeCluster`
- `eks:ListNodegroups`
- `eks:DescribeNodegroup`

## Determinism and limitations

- Findings are deterministic for equivalent inventory/tag input.
- Signals rely on control-plane inventory and do not attempt workload-level billing attribution.
- Access-denied scenarios are emitted as informational findings.

## Related tests

- `tests/test_ecs_eks_containers.py`
