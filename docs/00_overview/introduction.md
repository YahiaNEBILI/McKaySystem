# Introduction

Status: Canonical  
Last reviewed: 2026-02-01

This project is an AWS-focused FinOps engine:

1. **Checkers** scan AWS APIs and emit **Findings** (signals).
2. Findings are persisted as Parquet (system of record) and optionally exported to JSON for UI.
3. A **Correlation Engine** combines multiple signals into higher-confidence meta-findings.
4. A **CUR pipeline** can enrich findings with real costs when Cost & Usage Report data is available.

If you are new:
- read `00_overview/glossary.md`
- then `01_architecture/architecture.md`
- then `02_pipeline/pipeline_overview.md`
