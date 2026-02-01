# AWS RDS_SNAPSHOTS checker

Status: Derived  
Last reviewed: 2026-02-01

**Source code:** `checks/aws/rds_snapshots_cleanup.py`

## Purpose

RDS Snapshots Cleanup Checker

## Signals

This page is generated from module docstrings and static analysis of `check_id` constants.
Use it as an index; detailed semantics are in code and in the checker contract.

## Check IDs emitted

- `aws.rds.snapshots.access_error`
- `aws.rds.snapshots.cleanup`
- `aws.rds.snapshots.manual_old`
- `aws.rds.snapshots.orphaned`

## Notes / limitations

- API access can be partial; AccessDenied should downgrade to informational findings where applicable.
- Cost estimates are best-effort unless explicitly enriched from CUR.
