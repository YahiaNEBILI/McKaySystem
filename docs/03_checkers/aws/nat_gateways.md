# AWS NAT Gateways checker

Status: Canonical  
Last reviewed: 2026-02-15

**Source code:** `checks/aws/nat_gateways.py`

## Purpose

Detect NAT Gateway waste, routing hygiene issues, and data-processing cost signals.

## Checker identity

- `checker_id`: `aws.ec2.nat.gateways`
- `spec`: `checks.aws.nat_gateways:NatGatewaysChecker`

## Check IDs emitted

- `aws.ec2.nat.gateways.orphaned`
- `aws.ec2.nat.gateways.idle`
- `aws.ec2.nat.gateways.high.data.processing`
- `aws.ec2.nat.gateways.cross.az`
- `aws.ec2.nat.gateways.missing.permission`
- `aws.ec2.nat.gateways.cloudwatch.error`
- `aws.ec2.nat.gateways.access.error`

## Key signals

- Orphaned NAT gateways not referenced by route tables.
- Idle NAT gateways by p95 daily traffic.
- High monthly-equivalent data processing (VPC endpoint candidate signal).
- Cross-AZ NAT routing patterns that can increase cost and risk.

## Configuration and defaults

Configured via `NatGatewaysConfig`.
Defaults are sourced from `checks/aws/defaults.py`, including:
- lookback/datapoint thresholds
- idle and high-data thresholds
- orphan age threshold
- fallback hourly/data pricing
- suppression tag keys

## IAM permissions

Typical read-only permissions:
- `ec2:DescribeNatGateways`
- `ec2:DescribeRouteTables`
- `ec2:DescribeSubnets`
- `cloudwatch:GetMetricData`

Optional for improved cost-confidence:
- `pricing:GetProducts` (via pricing service)

## Determinism and limitations

- Cross-AZ inference is best-effort and intentionally avoids noisy public route-table cases.
- Cost estimates are directional and prioritize optimization discovery.
- Permission denials are explicitly emitted as informational findings.

## Related tests

- `tests/test_nat_gateways.py`
- `tests/test_nat_gateways_stress.py`
