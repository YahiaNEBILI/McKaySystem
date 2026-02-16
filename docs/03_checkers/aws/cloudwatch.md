# AWS CloudWatch checker

Status: Canonical  
Last reviewed: 2026-02-15

**Source code:** `checks/aws/cloudwatch_metrics_logs_cost.py`

## Purpose

Emit CloudWatch logs/metrics/alarms cost and hygiene signals used directly and by correlation rules.

## Checker identity

- `checker_id`: `aws.cloudwatch.metrics.logs.cost`
- `spec`: `checks.aws.cloudwatch_metrics_logs_cost:CloudWatchMetricsLogsCostChecker`

## Check IDs emitted

- `aws.logs.log.groups.retention.missing`
- `aws.cloudwatch.custom.metrics.from.log.filters`
- `aws.cloudwatch.alarms.high.count`
- `aws.cloudwatch.access.error`

## Key signals

- Log groups with no retention policy.
- Custom metrics created from log metric filters.
- High alarm-count account/region signal.
- Informational access-error findings when required APIs are denied.

## Configuration and defaults

Configured via `CloudWatchMetricsLogsCostConfig`.
Defaults are sourced from `checks/aws/defaults.py`, including:
- retention policy requirement and suppression tags
- custom metric and alarm thresholds
- fallback unit pricing for custom metrics and alarms

## IAM permissions

Minimum read-only permissions:
- `logs:DescribeLogGroups`
- `logs:ListTagsLogGroup`
- `logs:DescribeMetricFilters`
- `cloudwatch:DescribeAlarms`

Optional for improved cost-confidence:
- `pricing:GetProducts` (via pricing service)

## Determinism and limitations

- Inventory-based signals are deterministic for identical API responses.
- Costs are best-effort and directional unless later enriched by CUR.
- Access-denied conditions are surfaced as informational findings.

## Related tests

- `tests/test_cloudwatch_metrics_logs_cost.py`
