# AWS EBS checker

Status: Derived  
Last reviewed: 2026-02-01

**Source code:** `checks/aws/ebs_storage.py`

## Purpose

checks/aws/ebs_storage.py

## Signals

This page is generated from module docstrings and static analysis of `check_id` constants.
Use it as an index; detailed semantics are in code and in the checker contract.

## Check IDs emitted

- `aws.ec2.ebs.gp2.to.gp3`
- `aws.ec2.ebs.old.snapshot`
- `aws.ec2.ebs.snapshot.unencrypted`
- `aws.ec2.ebs.unattached.volume`
- `aws.ec2.ebs.volume.unencrypted`

## Notes / limitations

- API access can be partial; AccessDenied should downgrade to informational findings where applicable.
- Cost estimates are best-effort unless explicitly enriched from CUR.
