# Correlation contract

Status: Canonical  
Last reviewed: 2026-02-01

This document defines **platform-level guarantees** for correlation.

## Purpose

Correlation combines multiple independent findings into:
- higher-confidence issues
- reduced noise
- actionable “meta-findings”

Correlation does **not** replace checkers:
- checkers emit **facts**
- correlation emits **interpretations based on multiple facts**

## Invariants

Correlation MUST:
- be deterministic for identical input (order independent)
- keep raw findings immutable (correlation is an enrichment step)
- never silently swallow runtime errors (fail loud unless explicitly disabled)

Correlation SHOULD:
- explain which input signals triggered the meta-finding
- emit stable identifiers based on deterministic inputs

## Inputs and outputs

- Input: raw findings Parquet (canonical schema)
- Output: correlated findings Parquet (same base schema, with correlation fields populated)

The SQL output contract is defined in `rule_contract.md`.
