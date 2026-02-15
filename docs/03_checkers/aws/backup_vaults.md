# AWS Backup Vaults checker

Status: Canonical  
Last reviewed: 2026-02-15

**Source code:** `checks/aws/backup_vaults_audit.py`

## Purpose

Audit backup vault retention guardrails (Vault Lock) and access policy risk.

## Checker identity

- `checker_id`: `aws.backup.vaults.audit`
- `spec`: `checks.aws.backup_vaults_audit:AwsBackupVaultsAuditChecker`

## Check IDs emitted

- `aws.backup.vaults.no.lifecycle`
- `aws.backup.vaults.access.policy.misconfig`
- `aws.backup.access.error`

## Key signals

- Vaults missing retention guardrails (Vault Lock not configured) or allowing effectively indefinite retention.
- Vault access policies with wildcard principals, unallowlisted cross-account principals, or broad sensitive actions.
- Informational access findings when required Backup APIs are denied.

## Configuration and defaults

- Configured by checker constructor and bootstrap allowlist inputs.
- Defaults include fallback storage pricing in `checks/aws/defaults.py`:
  - `BACKUP_VAULTS_WARM_FALLBACK_USD`
  - `BACKUP_VAULTS_COLD_FALLBACK_USD`

## IAM permissions

Minimum read-only permissions:
- `backup:ListBackupVaults`
- `backup:DescribeBackupVault`
- `backup:GetBackupVaultAccessPolicy`

Optional for improved cost-confidence:
- `pricing:GetProducts` (via pricing service)

## Determinism and limitations

- Policy evaluation is intentionally conservative and best-effort for complex IAM policy semantics.
- Cost estimates are directional and reflect current stored data signals, not full lifecycle simulation.
- Missing permissions degrade to informational findings.

## Related tests

- `tests/test_backup_vaults_audit.py`
