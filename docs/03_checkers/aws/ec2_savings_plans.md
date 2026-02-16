# AWS EC2 Savings Plans checker

Status: Canonical  
Last reviewed: 2026-02-15

**Source code:** `checks/aws/ec2_savings_plans.py`

## Purpose

Detect EC2 Savings Plan commitment opportunities:
- Coverage gaps where estimated EC2 demand exceeds active commitment
- Low utilization where active commitment appears underused

## Checker identity

- `checker_id`: `aws.ec2.savings.plans`
- `spec`: `checks.aws.ec2_savings_plans:EC2SavingsPlansChecker`

## Check IDs emitted

- `aws.ec2.savings.plans.coverage.gap`
- `aws.ec2.savings.plans.utilization.low`

## Key signals

- Uses running EC2 inventory and best-effort on-demand pricing to estimate hourly demand.
- Compares estimated demand to active Savings Plan commitment (`Compute` + `EC2Instance` plans).

## Estimation model

- Coverage gap monthly cost: `uncovered_hourly * 730`.
- Coverage gap potential savings: configurable discount factor on uncovered monthly cost.
- Low-utilization monthly commitment waste: `unused_hourly * 730 * factor`.

## IAM permissions

Typical read-only permissions:
- `ec2:DescribeInstances`
- `savingsplans:DescribeSavingsPlans`
- `pricing:GetProducts` (optional, for better confidence)

## Determinism and limitations

- Deterministic output with stable ordering.
- Uses estimated EC2 demand baseline; does not replace billing-grade Cost Explorer analytics.
- Malformed commitment values are tolerated and ignored.

## Related tests

- `tests/test_ec2_savings_plans.py`
