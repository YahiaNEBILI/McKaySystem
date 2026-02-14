# Running the engine

Status: Canonical  
Last reviewed: 2026-02-01

## Typical run

1. Configure AWS credentials (or role) with permissions described in `permissions.md`.
2. Run the CLI / runner with:
   - tenant_id, workspace
   - output base directory
   - optional flags to enable/disable correlation and CUR enrichment
3. (Optional) Use `mckay run-all` to run → export → ingest (if `DB_URL` is set).

## Outputs (high level)

- Raw findings Parquet (system of record)
- Correlated findings Parquet (optional)
- JSON exports for UI (optional)

See:
- `02_pipeline/pipeline_overview.md`
- `04_schemas/finding_schema.md`

---

## Export & ingest safety

- `export_findings.py` writes `findings_full.json` by default (unbounded) plus `findings.json` for UI.
- `ingest_exported_json.py` refuses to ingest `findings.json` unless `ALLOW_PARTIAL_INGEST=1`.
- If you override `--out`, correlated/enriched defaults are derived next to that directory unless
  `--correlation-out` is provided.
