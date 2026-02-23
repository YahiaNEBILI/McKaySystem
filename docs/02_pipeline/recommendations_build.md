# Building Recommendations

Status: Canonical  
Last reviewed: 2026-02-22

## Purpose

Clarify how recommendations are produced to avoid duplicate philosophies.

In this system:

1. Checkers emit **findings** with factual signals and checker guidance (`advice`).
2. Ingest persists findings into `finding_latest` / `finding_current`.
3. `/api/recommendations*` derives normalized **action plans** from `finding_current`
   using recommendation rules in `apps/flask_api/blueprints/recommendations.py`.

There is currently no separate worker "recommendations build step" table.

## Build flow (authoritative)

1. Run engine/checkers:
```bash
python -m apps.worker.runner --tenant acme --workspace prod
```
2. Ingest run output:
```bash
python -m apps.worker.ingest_parquet --manifest <path-to-run-manifest.json>
```
3. Query recommendations API:
```bash
curl "http://localhost:8000/api/recommendations?tenant_id=acme&workspace=prod&state=open&order=savings_desc"
```

## Windows PowerShell quick check

```powershell
$base = "http://localhost:8000"
$tenant = "acme"
$workspace = "prod"

Invoke-RestMethod `
  -Uri "$base/api/recommendations?tenant_id=$tenant&workspace=$workspace&state=open&order=savings_desc&limit=20" `
  -Method GET
```

## Contract split (do not mix)

1. `finding.payload.advice`:
   - free text from checker
   - explanatory
   - not workflow-contract
2. `recommendations API item`:
   - normalized plan (`recommendation_type`, `action_type`, `target`, `priority`, `requires_approval`)
   - workflow-contract for queueing/approval/remediation

## Future option (if needed)

If query-time derivation becomes too expensive, add a materialized
`recommendation_current` read model built during ingest. Until then, API derivation
is the canonical implementation.
