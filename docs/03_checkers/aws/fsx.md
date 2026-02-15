# AWS FSx checker

Status: Canonical  
Last reviewed: 2026-02-15

**Source code:** `checks/aws/fsx_filesystems.py`

## Purpose

Detect FSx cost and governance opportunities across Windows and non-Windows file systems.

## Checker identity

- `checker_id`: `aws.fsx.filesystems`
- `spec`: `checks.aws.fsx_filesystems:FSxFileSystemsChecker`

## Check IDs emitted

- `aws.fsx.filesystems.possible.unused`
- `aws.fsx.filesystems.underutilized.throughput`
- `aws.fsx.filesystems.large.and.inactive`
- `aws.fsx.filesystems.multi.az.in.nonprod`
- `aws.fsx.filesystems.missing.required.tags`
- `aws.fsx.windows.backups.disabled`
- `aws.fsx.windows.copy.tags.to.backups.disabled`
- `aws.fsx.windows.backup.retention.low`
- `aws.fsx.windows.maintenance.window.missing`
- `aws.fsx.windows.maintenance.window.business.hours`
- `aws.fsx.windows.storage.type.mismatch`

## Key signals

- Potentially unused or oversized FSx deployments.
- Throughput underutilization and large inactive footprints.
- Governance checks for required tags and non-prod HA posture.
- Windows-focused backup/maintenance/storage configuration controls.

## Configuration and defaults

Configured via `FSxFileSystemsConfig`.
Defaults are sourced from `checks/aws/defaults.py`, including:
- lookback periods and utilization thresholds
- large-storage thresholds
- backup-retention minimums
- required tag keys

## IAM permissions

Typical read-only permissions:
- `fsx:DescribeFileSystems`
- `fsx:DescribeBackups`
- `cloudwatch:GetMetricData`

Optional for improved cost-confidence:
- `pricing:GetProducts` (via pricing service)

## Determinism and limitations

- Signals rely on available CloudWatch/FSx metadata and can degrade under restricted IAM.
- Savings are approximate and intended for prioritization.
- Findings are deterministic for equivalent inventory/metric input.

## Related tests

- `tests/test_fsx_filesystems.py`
