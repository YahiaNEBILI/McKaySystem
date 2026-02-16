# AWS CloudFront checker

Status: Canonical  
Last reviewed: 2026-02-15

**Source code:** `checks/aws/cloudfront_distributions.py`

## Purpose

Detect CloudFront distributions that appear unused and configurations that disable default caching.

## Checker identity

- `checker_id`: `aws.cloudfront.distributions.audit`
- `spec`: `checks.aws.cloudfront_distributions:CloudFrontDistributionsChecker`
- `is_regional`: `false` (global service)

## Check IDs emitted

- `aws.cloudfront.distributions.unused`
- `aws.cloudfront.distributions.caching.disabled`
- `aws.cloudfront.distributions.missing.permission`
- `aws.cloudfront.distributions.access.error`

## Key signals

- Low request volume by p95 daily `AWS/CloudFront::Requests` over lookback window.
- Default cache behavior uses managed policy `CachingDisabled`.
- Legacy default cache behavior has `MinTTL`, `DefaultTTL`, and `MaxTTL` set to zero.

## Configuration and defaults

Configured via `CloudFrontDistributionsConfig`.
Defaults are sourced from `checks/aws/defaults.py`, including:
- lookback window and datapoint guardrails
- idle request threshold
- minimum resource age
- max findings per check type

## IAM permissions

Typical read-only permissions:
- `cloudfront:ListDistributions`
- `cloudwatch:GetMetricData`

## Determinism and limitations

- Request-based unused detection is best-effort and requires CloudWatch datapoints.
- Caching signal evaluates default behavior only (it does not score path-level cache hit ratios).
- Access-denied conditions are emitted as informational findings.

## Related tests

- `tests/test_cloudfront_distributions.py`
