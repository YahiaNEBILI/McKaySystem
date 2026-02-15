# AWS RDS Instances checker

Status: Canonical  
Last reviewed: 2026-02-15

**Source code:** `checks/aws/rds_instances_optimizations.py`

## Purpose

Detect RDS instance optimization and governance opportunities using inventory and CloudWatch signals.

## Checker identity

- `checker_id`: `aws.rds.instances.optimizations`
- `spec`: `checks.aws.rds_instances_optimizations:RDSInstancesOptimizationsChecker`

## Check IDs emitted

- `aws.rds.instances.stopped.storage`
- `aws.rds.storage.overprovisioned`
- `aws.rds.multi.az.non.prod`
- `aws.rds.instance.family.old.generation`
- `aws.rds.engine.needs.upgrade`
- `aws.rds.read.replica.unused`
- `aws.rds.instances.access.error`

## Key signals

- Stopped instances still incurring storage cost.
- Overprovisioned storage via FreeStorageSpace usage patterns.
- Non-production Multi-AZ posture opportunities.
- Legacy instance family and engine-version policy drift.
- Unused read replicas by sustained low read IOPS.

## Configuration and defaults

Defaults are sourced from `checks/aws/defaults.py`, including:
- storage analysis windows/coverage thresholds
- overprovisioning thresholds
- replica lookback and p95 read-IOPS thresholds
- blocked/allowed engine-version policy bounds

## IAM permissions

Typical read-only permissions:
- `rds:DescribeDBInstances`
- `rds:ListTagsForResource`
- `cloudwatch:GetMetricData`

Optional for improved cost-confidence:
- `pricing:GetProducts` (via pricing service)

## Determinism and limitations

- CloudWatch-dependent findings require metric coverage thresholds.
- Cost estimates are best-effort and should be refined by CUR enrichment.
- Access gaps surface as informational findings instead of hard failures.

## Related tests

- `tests/test_rds_instances_optimizations.py`
