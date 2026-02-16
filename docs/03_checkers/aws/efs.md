# AWS EFS checker

Status: Canonical  
Last reviewed: 2026-02-15

**Source code:** `checks/aws/efs_filesystems.py`

## Purpose

Detect EFS lifecycle, security, backup, and utilization inefficiencies.

## Checker identity

- `checker_id`: `aws.efs.filesystems`
- `spec`: `checks.aws.efs_filesystems:EFSFileSystemsChecker`

## Check IDs emitted

- `aws.efs.filesystems.unused`
- `aws.efs.filesystems.provisioned.throughput.underutilized`
- `aws.efs.filesystems.lifecycle.missing`
- `aws.efs.filesystems.unencrypted`
- `aws.efs.filesystems.backup.disabled`
- `aws.efs.filesystems.access.error`

## Key signals

- Low/no activity filesystems (usage-based idle signal).
- Provisioned throughput significantly above observed demand.
- Missing lifecycle policy, missing encryption, disabled backups.
- Informational access-error findings on permission gaps.

## Configuration and defaults

Configured via `EFSFileSystemsConfig`.
Defaults are sourced from `checks/aws/defaults.py`, including:
- lookback and datapoint requirements
- idle/underutilization thresholds
- suppression tags
- max findings cap

## IAM permissions

Typical read-only permissions:
- `elasticfilesystem:DescribeFileSystems`
- `elasticfilesystem:DescribeLifecycleConfiguration`
- `elasticfilesystem:DescribeBackupPolicy`
- `elasticfilesystem:DescribeFileSystemPolicy` (where applicable)
- `cloudwatch:GetMetricData`

Optional for improved cost-confidence:
- `pricing:GetProducts` (via pricing service)

## Determinism and limitations

- Utilization findings depend on CloudWatch metric availability.
- Cost/savings are best-effort and not CUR-accurate by themselves.
- Access-denied scenarios are represented as informational findings.

## Related tests

- `tests/test_efs_filesystems.py`
