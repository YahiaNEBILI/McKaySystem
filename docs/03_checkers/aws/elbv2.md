# AWS ELBv2 checker

Status: Canonical  
Last reviewed: 2026-02-15

**Source code:** `checks/aws/elbv2_load_balancers.py`

## Purpose

Detect load balancer hygiene and cost waste signals for ALB/NLB resources.

## Checker identity

- `checker_id`: `aws.elbv2.load.balancers`
- `spec`: `checks.aws.elbv2_load_balancers:ElbV2LoadBalancersChecker`

## Check IDs emitted

- `aws.elbv2.load.balancers.idle`
- `aws.elbv2.load.balancers.no.listeners`
- `aws.elbv2.load.balancers.no.registered.targets`
- `aws.elbv2.load.balancers.no.healthy.targets`
- `aws.elbv2.load.balancers.access.error`
- `aws.elbv2.load.balancers.missing.permission`

## Key signals

- Idle ALB/NLB traffic pattern over lookback window.
- Load balancers without listeners.
- Target groups without registered or healthy targets.
- Informational findings for permission gaps on inventory/health/metrics.

## Configuration and defaults

Configured via `ElbV2LoadBalancersConfig`.
Defaults are sourced from `checks/aws/defaults.py`, including:
- lookback/datapoint thresholds
- idle request/flow thresholds
- minimum age filter
- fallback hourly pricing

## IAM permissions

Typical read-only permissions:
- `elasticloadbalancing:DescribeLoadBalancers`
- `elasticloadbalancing:DescribeListeners`
- `elasticloadbalancing:DescribeTargetGroups`
- `elasticloadbalancing:DescribeTargetHealth`
- `cloudwatch:GetMetricData`

Optional for improved cost-confidence:
- `pricing:GetProducts` (via pricing service)

## Determinism and limitations

- Metrics and target health are best-effort and can be partially visible due to IAM.
- Cost estimates are directional and not a billing replacement.
- Permission denials are emitted as informational findings.

## Related tests

- `tests/test_elbv2_load_balancers.py`
