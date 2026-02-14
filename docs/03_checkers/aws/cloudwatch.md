# AWS Cloudwatch Checker

Status: Derived  
Last reviewed: 2026-02-03

**Source code:** `checks/aws/cloudwatch_metrics_logs_cost.py`

## Purpose

AWS Cloudwatch Checker

## Signals

This page is generated from module docstrings and static analysis of `check_id` constants.
Use it as an index; detailed semantics are in code and in the checker contract.

## Check IDs emitted

- `aws.cloudwatch.access.error`
- `aws.logs.log.groups.retention.missing`
- `aws.cloudwatch.custom.metrics.from.log.filters`

## Notes / limitations

- API access can be partial; AccessDenied should downgrade to informational findings where applicable.
- Cost estimates are best-effort unless explicitly enriched from CUR.
