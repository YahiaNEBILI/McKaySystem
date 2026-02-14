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
4. (Recommended before ingest) Run `mckay recover --tenant <tenant> --workspace <workspace> --db-url <url>`
   to reap expired run locks and fail stale `running` runs without active lock.

## Outputs (high level)

- Raw findings Parquet (system of record)
- Correlated findings Parquet (optional)
- JSON exports for UI (optional)

See:
- `02_pipeline/pipeline_overview.md`
- `04_schemas/finding_schema.md`

---

## Export & ingest safety

- `python -m apps.worker.export_findings` writes UI JSON artifacts from Parquet datasets.
- `python -m apps.worker.ingest_parquet` ingests directly from Parquet using `run_manifest.json` (canonical path).
- Ingest selection rule:
  - use `out_enriched` when present
  - otherwise ingest the union of `out_raw` + `out_correlated` when both exist
- If you override `--out`, correlated/enriched defaults are derived next to that directory unless
  `--correlation-out` is provided.

---

## Database migrations

Run migrations before ingesting into a fresh or upgraded DB:

```
python -m apps.backend.db_migrate
```

Or via the CLI:

```
mckay migrate
```

Recovery sweep (tenant/workspace scoped):

```
mckay recover --tenant <tenant> --workspace <workspace> --db-url <url>
```

---

## Monorepo workflows

- Backend/API code lives under `apps/flask_api/` and `apps/backend/` (deployment docs: `deploy/backend/`).
- Worker/scanner code lives in core engine paths (`checks/`, `pipeline/`, etc.; deployment docs: `deploy/worker/`).
- Enforce root layout policy with:

```
python tools/repo/check_layout.py
```

- In CloudShell, reduce checkout size with:

```
bash tools/cloudshell/sparse_checkout_worker.sh .
```

Or bootstrap sparse clone from scratch:

```
bash tools/cloudshell/bootstrap_sparse_clone.sh <repo-url> <target-dir> worker
```

## Release tracks (Phase 3)

- Backend release checks:

```
make ci-backend
```

- Worker release checks:

```
make ci-worker
```

- GitHub Actions workflows:
  - `.github/workflows/backend-ci.yml`
  - `.github/workflows/worker-ci.yml`
  - `.github/workflows/main.yml` (shared guardrails)

