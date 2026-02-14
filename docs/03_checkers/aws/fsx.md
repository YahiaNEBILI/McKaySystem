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

- `aws.fsx.filesystems.large.and.inactive`
- `aws.fsx.filesystems.missing.required.tags`
- `aws.fsx.filesystems.multi.az.in.nonprod`
- `aws.fsx.filesystems.possible.unused`
- `aws.fsx.filesystems.underutilized.throughput`
- `aws.fsx.windows.backup.retention.low`
- `aws.fsx.windows.backups.disabled`
- `aws.fsx.windows.copy.tags.to.backups.disabled`
- `aws.fsx.windows.maintenance.window.business.hours`
- `aws.fsx.windows.maintenance.window.missing`
- `aws.fsx.windows.storage.type.mismatch`

## Notes / limitations

- API access can be partial; AccessDenied should downgrade to informational findings where applicable.
- Cost estimates are best-effort unless explicitly enriched from CUR.
