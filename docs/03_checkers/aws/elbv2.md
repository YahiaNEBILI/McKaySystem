# AWS ELBV2 checker

Status: Derived  
Last reviewed: 2026-02-01

**Source code:** `checks/aws/elbv2_load_balancers.py`

## Purpose

checks/aws/elbv2_load_balancers.py

## Signals

This page is generated from module docstrings and static analysis of `check_id` constants.
Use it as an index; detailed semantics are in code and in the checker contract.

## Check IDs emitted

- `aws.elbv2.load.balancers`
- `aws.elbv2.load_balancers.access_error`
- `aws.elbv2.load_balancers.idle`
- `aws.elbv2.load_balancers.no_healthy_targets`
- `aws.elbv2.load_balancers.no_listeners`
- `aws.elbv2.load_balancers.no_registered_targets`

## Notes / limitations

- API access can be partial; AccessDenied should downgrade to informational findings where applicable.
- Cost estimates are best-effort unless explicitly enriched from CUR.
