# Running the engine

Status: Canonical  
Last reviewed: 2026-02-01

## Typical run

1. Configure AWS credentials (or role) with permissions described in `permissions.md`.
2. Run the CLI / runner with:
   - tenant_id, workspace
   - output base directory
   - optional flags to enable/disable correlation and CUR enrichment
3. (Optional) Use `mckay run-all` to run -> ingest -> export (if `DB_URL` is set).

## Outputs (high level)

- Raw findings Parquet (system of record)
- Correlated findings Parquet (optional)
- JSON exports for UI (optional)

See:
- `02_pipeline/pipeline_overview.md`
- `04_schemas/finding_schema.md`

---

## Export & ingest safety

- `export_findings.py` writes `findings.json` (UI) and optionally `findings_full.json` (legacy/diagnostic).
- `ingest_parquet.py` ingests directly from Parquet using `run_manifest.json` (preferred path).
- If you override `--out`, correlated/enriched defaults are derived next to that directory unless
  `--correlation-out` is provided.

