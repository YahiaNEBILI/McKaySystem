# Permissions

Status: Canonical  
Last reviewed: 2026-02-01

This engine is designed to run with **read-only** permissions for AWS resources.

## General principles

- Prefer AWS managed read-only policies where possible.
- Some checks require additional describes (e.g., to detect encryption, lifecycle, policies).
- The platform must handle AccessDenied gracefully: the checker will emit an informational finding instead
  of crashing.

## Recommended approach

- Create a dedicated IAM role for scanning.
- Allow `sts:AssumeRole` from your runner environment.
- Grant permissions per service (EC2, ECS, EKS, RDS, S3, Backup, FSx, EFS, ELBv2, Lambda, CloudWatch, Pricing).

Service-specific details should live in `03_checkers/aws/*.md`.
