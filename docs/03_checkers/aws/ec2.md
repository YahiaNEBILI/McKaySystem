# AWS EC2 checker

Status: Canonical  
Last reviewed: 2026-02-15

**Source code:** `checks/aws/ec2_instances.py`

## Purpose

Detect EC2 utilization, lifecycle, security, and tagging inefficiencies.

## Checker identity

- `checker_id`: `aws.ec2.instances`
- `spec`: `checks.aws.ec2_instances:EC2InstancesChecker`

## Check IDs emitted

- `aws.ec2.instances.underutilized`
- `aws.ec2.instances.stopped.long`
- `aws.ec2.instances.old.generation`
- `aws.ec2.instances.security.imdsv1.allowed`
- `aws.ec2.instances.security.admin.ports.open.world`
- `aws.ec2.instances.t.credit.issues`
- `aws.ec2.instances.tags.missing`
- `aws.ec2.security.groups.unused`

## Key signals

- Low-utilization running instances.
- Long-stopped instances with ongoing storage cost.
- Legacy instance families and burst-credit pressure.
- IMDSv1 allowed and publicly exposed SSH/RDP.
- Missing required tags and unused security groups.

## Configuration and defaults

Configured via `EC2InstancesConfig`.
Defaults are sourced from `checks/aws/defaults.py`, including:
- lookback windows and utilization thresholds
- stopped-age threshold
- burst-credit thresholds
- required tag keys

## IAM permissions

Typical read-only permissions:
- `ec2:DescribeInstances`
- `ec2:DescribeVolumes`
- `ec2:DescribeSecurityGroups`
- `ec2:DescribeNetworkInterfaces`
- `cloudwatch:GetMetricData`

Optional for improved cost-confidence:
- `pricing:GetProducts` (via pricing service)

## Determinism and limitations

- Metric-dependent findings require CloudWatch coverage.
- Estimates are directional and intended for optimization triage.
- Empty or malformed inputs are handled without terminating the run.

## Related tests

- `tests/test_ec2_instances.py`
