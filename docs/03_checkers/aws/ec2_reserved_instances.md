# AWS EC2 Reserved Instances checker

Status: Canonical  
Last reviewed: 2026-02-15

**Source code:** `checks/aws/ec2_reserved_instances.py`

## Purpose

Detect EC2 Reserved Instance commitment inefficiencies:
- Coverage gaps (on-demand usage not covered by active RIs)
- Low utilization (active RI commitments with unused capacity)

## Checker identity

- `checker_id`: `aws.ec2.reserved.instances`
- `spec`: `checks.aws.ec2_reserved_instances:EC2ReservedInstancesChecker`

## Check IDs emitted

- `aws.ec2.ri.coverage.gap`
- `aws.ec2.ri.utilization.low`

## Key signals

- Match running EC2 inventory and active RI inventory by:
  - instance type
  - platform
  - tenancy
- Apply AZ-scoped reservations first, then regional reservations.

## Estimation model

- Uses on-demand EC2 monthly baseline from PricingService when available.
- Coverage-gap potential savings use a configurable discount factor.
- Unused RI commitment cost uses a configurable effective-cost factor.

## IAM permissions

Typical read-only permissions:
- `ec2:DescribeInstances`
- `ec2:DescribeReservedInstances`
- `pricing:GetProducts` (optional, for better estimate confidence)

## Determinism and limitations

- Output is deterministic and sorted by key.
- Matching is best-effort and does not model every RI/SP discount nuance.
- Empty and malformed payloads are tolerated without crashing.

## Related tests

- `tests/test_ec2_reserved_instances.py`
