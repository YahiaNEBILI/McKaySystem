# AWS RDS_INSTANCES checker

Status: Derived  
Last reviewed: 2026-02-01

**Source code:** `checks/aws/rds_instances_optimizations.py`

## Purpose

checks/aws/rds_instances_optimizations.py

## Signals

This page is generated from module docstrings and static analysis of `check_id` constants.
Use it as an index; detailed semantics are in code and in the checker contract.

## Check IDs emitted

- `aws.rds.engine.needs_upgrade`
- `aws.rds.instance_family.old_generation`
- `aws.rds.instances.access_error`
- `aws.rds.instances.optimizations`
- `aws.rds.instances.stopped_storage`
- `aws.rds.multi_az.non_prod`
- `aws.rds.read_replica.unused`
- `aws.rds.storage.overprovisioned`

## Notes / limitations

- API access can be partial; AccessDenied should downgrade to informational findings where applicable.
- Cost estimates are best-effort unless explicitly enriched from CUR.
