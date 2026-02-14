# AWS BACKUP_PLANS checker

Status: Derived  
Last reviewed: 2026-02-01

**Source code:** `checks/aws/backup_plans_audit.py`

## Purpose

AWS Backup Plans & Recovery Points Checker

## Signals

This page is generated from module docstrings and static analysis of `check_id` constants.
Use it as an index; detailed semantics are in code and in the checker contract.

## Check IDs emitted

- `aws.backup.access.error`
- `aws.backup.governance.plans.audit`
- `aws.backup.plans.no.selections`
- `aws.backup.recovery.points.stale`
- `aws.backup.rules.no.lifecycle`

## Notes / limitations

- API access can be partial; AccessDenied should downgrade to informational findings where applicable.
- Cost estimates are best-effort unless explicitly enriched from CUR.
