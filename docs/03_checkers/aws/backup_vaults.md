# AWS BACKUP_VAULTS checker

Status: Derived  
Last reviewed: 2026-02-01

**Source code:** `checks/aws/backup_vaults_audit.py`

## Purpose

AWS Backup Vaults Audit Checker

## Signals

This page is generated from module docstrings and static analysis of `check_id` constants.
Use it as an index; detailed semantics are in code and in the checker contract.

## Check IDs emitted

- `aws.backup.access.error`
- `aws.backup.vaults.access.policy.misconfig`
- `aws.backup.vaults.audit`
- `aws.backup.vaults.no.lifecycle`

## Notes / limitations

- API access can be partial; AccessDenied should downgrade to informational findings where applicable.
- Cost estimates are best-effort unless explicitly enriched from CUR.
