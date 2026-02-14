# AWS NAT_GATEWAYS checker

Status: Derived  
Last reviewed: 2026-02-01

**Source code:** `checks/aws/nat_gateways.py`

## Purpose

checks/aws/nat_gateways.py

## Signals

This page is generated from module docstrings and static analysis of `check_id` constants.
Use it as an index; detailed semantics are in code and in the checker contract.

## Check IDs emitted

- `aws.ec2.nat.gateways`
- `aws.ec2.nat_gateways.access_error`
- `aws.ec2.nat_gateways.cross_az`
- `aws.ec2.nat_gateways.high_data_processing`
- `aws.ec2.nat_gateways.idle`
- `aws.ec2.nat_gateways.orphaned`

## Notes / limitations

- API access can be partial; AccessDenied should downgrade to informational findings where applicable.
- Cost estimates are best-effort unless explicitly enriched from CUR.
