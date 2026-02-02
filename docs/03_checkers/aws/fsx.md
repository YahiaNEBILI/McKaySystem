# AWS FSX checker

Status: Derived  
Last reviewed: 2026-02-01

**Source code:** `checks/aws/fsx_filesystems.py`

## Purpose

checks/aws/fsx_filesystems.py

## Signals

This page is generated from module docstrings and static analysis of `check_id` constants.
Use it as an index; detailed semantics are in code and in the checker contract.

## Check IDs emitted

- `aws.fsx.filesystems.large_and_inactive`
- `aws.fsx.filesystems.missing_required_tags`
- `aws.fsx.filesystems.multi_az_in_nonprod`
- `aws.fsx.filesystems.possible_unused`
- `aws.fsx.filesystems.underutilized_throughput`
- `aws.fsx.windows.backup_retention_low`
- `aws.fsx.windows.backups_disabled`
- `aws.fsx.windows.copy_tags_to_backups_disabled`
- `aws.fsx.windows.maintenance_window_business_hours`
- `aws.fsx.windows.maintenance_window_missing`
- `aws.fsx.windows.storage_type_mismatch`

## Notes / limitations

- API access can be partial; AccessDenied should downgrade to informational findings where applicable.
- Cost estimates are best-effort unless explicitly enriched from CUR.
