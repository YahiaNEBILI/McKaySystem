# AWS EBS checker

Status: Canonical  
Last reviewed: 2026-02-15

**Source code:** `checks/aws/ebs_storage.py`

## Purpose

Detect EBS cost and governance inefficiencies across volumes and snapshots.

## Checker identity

- `checker_id`: `aws.ec2.ebs.storage`
- `spec`: `checks.aws.ebs_storage:EBSStorageChecker`

## Check IDs emitted

- `aws.ec2.ebs.unattached.volume`
- `aws.ec2.ebs.gp2.to.gp3`
- `aws.ec2.ebs.old.snapshot`
- `aws.ec2.ebs.volume.unencrypted`
- `aws.ec2.ebs.snapshot.unencrypted`
- `aws.ec2.ebs.access.error`

## Key signals

- Unattached volumes older than threshold.
- gp2 volumes eligible for gp3 migration savings.
- Old snapshots not referenced by AMIs.
- Unencrypted volumes/snapshots.
- Informational access-error handling for missing read permissions.

## Configuration and defaults

Configured via `EBSStorageConfig`.
Defaults are sourced from `checks/aws/defaults.py`, including:
- unattached/old snapshot age thresholds
- suppression tag keys/values/prefixes
- max findings safety cap

## IAM permissions

Typical read-only permissions:
- `ec2:DescribeVolumes`
- `ec2:DescribeSnapshots`
- `ec2:DescribeImages`
- `ec2:DescribeInstances`

Optional for improved savings-confidence:
- `pricing:GetProducts` (via pricing service)

## Determinism and limitations

- Suppression tags intentionally reduce false positives for retained backups.
- Savings/cost values are best-effort and storage-price dependent.
- Access-denied scenarios are surfaced as informational findings.

## Related tests

- `tests/test_ebs_storage.py`
