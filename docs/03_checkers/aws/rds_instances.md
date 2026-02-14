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

- `aws.rds.engine.needs.upgrade`
- `aws.rds.instance.family.old.generation`
- `aws.rds.instances.access.error`
- `aws.rds.instances.optimizations`
- `aws.rds.instances.stopped.storage`
- `aws.rds.multi.az.non.prod`
- `aws.rds.read.replica.unused`
- `aws.rds.storage.overprovisioned`

## Notes / limitations

- API access can be partial; AccessDenied should downgrade to informational findings where applicable.
- Cost estimates are best-effort unless explicitly enriched from CUR.
