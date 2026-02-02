# Checker contract

Status: Canonical  
Last reviewed: 2026-02-01

This document defines how checkers behave across the platform.

## Purpose

A checker scans a cloud service and emits **Findings** (facts + best-effort cost signals).

## Invariants

A checker MUST:
- never crash the entire run because one resource call failed
- be deterministic for identical observed input
- emit findings with stable identifiers (issue_key / fingerprint inputs)
- separate **signals** from **interpretation** (interpretation belongs in correlation)
- use _common helpers, any redundant code must be avoided

A checker MUST NOT:
- mutate storage directly (no writing Parquet/JSON)
- claim exact cost unless it is sourced from CUR enrichment
- hide AccessDenied errors (emit info findings describing missing permissions)

## Best-effort and IAM

For AWS API calls:
- Missing configuration (e.g., no lifecycle) → `fail` or `warn` depending on severity.
- AccessDenied → `info` with clear remediation.
- Unexpected errors → surface (raise) unless there is a well-justified fallback.

## Findings required fields

Each finding must include:
- `check_id`
- `severity`
- `resource_id` and/or `resource_arn` when available
- `issue_key` (stable, minimal identifying fields)
- best-effort cost fields when applicable

See `04_schemas/finding_schema.md` for the canonical contract.
