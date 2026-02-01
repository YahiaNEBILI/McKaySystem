# Running the engine

Status: Canonical  
Last reviewed: 2026-02-01

## Typical run

1. Configure AWS credentials (or role) with permissions described in `permissions.md`.
2. Run the CLI / runner with:
   - tenant_id, workspace
   - output base directory
   - optional flags to enable/disable correlation and CUR enrichment

## Outputs (high level)

- Raw findings Parquet (system of record)
- Correlated findings Parquet (optional)
- JSON exports for UI (optional)

See:
- `02_pipeline/pipeline_overview.md`
- `04_schemas/finding_schema.md`
