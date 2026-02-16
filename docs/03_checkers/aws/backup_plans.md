# AWS Backup Plans checker

Status: Canonical  
Last reviewed: 2026-02-15

**Source code:** `checks/aws/backup_plans_audit.py`

## Purpose

Detect AWS Backup plan governance gaps and stale recovery-point retention risk.

## Checker identity

- `checker_id`: `aws.backup.governance.plans.audit`
- `spec`: `checks.aws.backup_plans_audit:AwsBackupPlansAuditChecker`

## Check IDs emitted

- `aws.backup.plans.no.selections`
- `aws.backup.rules.no.lifecycle`
- `aws.backup.recovery.points.stale`
- `aws.backup.access.error`

## Key signals

- Backup plans with no selections (effective no-op plans).
- Backup rules without lifecycle controls (no transition/delete policy).
- Recovery points older than policy threshold and not near planned deletion.
- Informational access error when required Backup inventory APIs are denied.

## Configuration and defaults

- Configured via checker constructor arguments.
- Defaults are sourced from `checks/aws/defaults.py`:
  - `BACKUP_PLANS_STALE_DAYS`
  - `BACKUP_PLANS_WARM_GB_MONTH_PRICE_USD`
  - `BACKUP_PLANS_COLD_GB_MONTH_PRICE_USD`
  - `BACKUP_PLANS_SKIP_IF_DELETING_WITHIN_DAYS`

## IAM permissions

Minimum read-only permissions:
- `backup:ListBackupPlans`
- `backup:ListBackupSelections`
- `backup:GetBackupPlan`
- `backup:ListBackupVaults`
- `backup:ListRecoveryPointsByBackupVault`

Optional for improved cost-confidence:
- `pricing:GetProducts` (via pricing service)

## Determinism and limitations

- Findings are emitted with stable issue discriminators and deterministic scope.
- Cost figures are best-effort directional estimates for storage only.
- Access-denied scenarios degrade to informational findings instead of crashing.

## Related tests

- `tests/test_backup_plans_audit.py`
