# AWS RDS Snapshots checker

Status: Canonical  
Last reviewed: 2026-02-15

**Source code:** `checks/aws/rds_snapshots_cleanup.py`

## Purpose

Detect orphaned and stale manual RDS snapshots with suppression and cross-region safety guards.

## Checker identity

- `checker_id`: `aws.rds.snapshots.cleanup`
- `spec`: `checks.aws.rds_snapshots_cleanup:RDSSnapshotsCleanupChecker`

## Check IDs emitted

- `aws.rds.snapshots.orphaned`
- `aws.rds.snapshots.manual.old`
- `aws.rds.snapshots.access.error`

## Key signals

- Snapshots whose source DB/cluster no longer exists in-region.
- Manual snapshots older than configured retention threshold.
- Access error informational findings when inventory APIs are denied.

## Configuration and defaults

Defaults are sourced from `checks/aws/defaults.py`:
- `RDS_SNAPSHOTS_STALE_DAYS`
- `RDS_SNAPSHOTS_GB_MONTH_PRICE_USD`

The checker also applies retention suppression tags and cross-region copy guards.

## IAM permissions

Typical read-only permissions:
- `rds:DescribeDBInstances`
- `rds:DescribeDBClusters`
- `rds:DescribeDBSnapshots`
- `rds:DescribeDBClusterSnapshots`

Optional for improved cost-confidence:
- `pricing:GetProducts` (via pricing service)

## Determinism and limitations

- Suppression tags intentionally exclude intentionally retained snapshots.
- Aurora snapshot size is not always directly measurable, so some cost fields may remain unknown.
- Findings are deterministic for equivalent inventory input.

## Related tests

- `tests/test_rds_snapshots_cleanup.py`
