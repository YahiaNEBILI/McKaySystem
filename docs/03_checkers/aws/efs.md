# AWS EFS checker

Status: Derived  
Last reviewed: 2026-02-01

**Source code:** `checks/aws/efs_filesystems.py`

## Purpose

checks/aws/efs_filesystems.py

## Signals

This page is generated from module docstrings and static analysis of `check_id` constants.
Use it as an index; detailed semantics are in code and in the checker contract.

## Check IDs emitted

- `aws.efs.filesystems`
- `aws.efs.filesystems.access.error`
- `aws.efs.filesystems.backup.disabled`
- `aws.efs.filesystems.lifecycle.missing`
- `aws.efs.filesystems.provisioned.throughput.underutilized`
- `aws.efs.filesystems.unencrypted`
- `aws.efs.filesystems.unused`

## Notes / limitations

- API access can be partial; AccessDenied should downgrade to informational findings where applicable.
- Cost estimates are best-effort unless explicitly enriched from CUR.
