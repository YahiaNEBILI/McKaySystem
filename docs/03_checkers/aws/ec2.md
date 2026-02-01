# AWS EC2 checker

Status: Derived  
Last reviewed: 2026-02-01

**Source code:** `checks/aws/ec2_instances.py`

## Purpose

checks/aws/ec2_instances.py

## Signals

This page is generated from module docstrings and static analysis of `check_id` constants.
Use it as an index; detailed semantics are in code and in the checker contract.

## Check IDs emitted

- `aws.ec2.instances`
- `aws.ec2.instances.old_generation`
- `aws.ec2.instances.security.admin_ports_open_world`
- `aws.ec2.instances.security.imdsv1_allowed`
- `aws.ec2.instances.stopped_long`
- `aws.ec2.instances.t_credit_issues`
- `aws.ec2.instances.tags.missing`
- `aws.ec2.instances.underutilized`
- `aws.ec2.security_groups.unused`

## Notes / limitations

- API access can be partial; AccessDenied should downgrade to informational findings where applicable.
- Cost estimates are best-effort unless explicitly enriched from CUR.
