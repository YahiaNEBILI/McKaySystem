# Database model

This document explains the purpose of each table/view in the McKaySystem (FinOpsAnalyzer) PostgreSQL schema and the rules of how data flows through it.

## Mental model

The DB uses a simple pattern:

- **History (events):** what existed in each run → `finding_presence`
- **Snapshot (projection):** latest known state per finding → `finding_latest`
- **User intent:** ignore/snooze/resolve overlays → `finding_state_current`
- **Product truth (read model):** what the UI/API should show now → `finding_current` (view)

If you only remember one rule:

> All API/UI reads must query `finding_current` (never `finding_latest` directly).

---

## Tables and view

### `runs`

One row per ingestion run.

**Primary key**
- `(tenant_id, workspace, run_id)`

**What it stores**
- run identity (`run_id`, `run_ts`)
- ingestion lifecycle (`status`, `ingested_at`)
- artifact provenance (`artifact_prefix`)
- optional flags (`raw_present`, `correlated_present`, `enriched_present`)
- optional `engine_version`

**Used for**
- “latest run” selection
- debugging / audit
- multi-run history and future scheduling logic

---

### `finding_presence` (history / membership)

Append-only history of finding membership in a run:

> “Finding `fingerprint` existed in run `run_id`.”

**Primary key**
- `(tenant_id, workspace, run_id, fingerprint)`

**What it stores**
- light fields needed for analytics (check/service/severity/title/savings/region/account_id)
- `detected_at` (usually run timestamp)

**Used for**
- trend charts (“findings over time”)
- coverage analytics (by region/service/check_id)
- diffs between runs (new findings vs disappeared)
- run-level KPIs (counts, savings sums)

**Not used for**
- current UI lists (too expensive / requires grouping by latest run)

**Ingest contract**
- Insert N rows per run.
- Re-ingest of the same run may delete+reinsert for idempotency.

---

### `finding_latest` (snapshot / projection)

One row per fingerprint representing the **latest snapshot** of that finding:

> “What is the latest known version of finding `fingerprint`?”

**Primary key**
- `(tenant_id, workspace, fingerprint)`

**What it stores**
- summary columns (check/service/severity/title/savings/region/account_id)
- `run_id` that produced the snapshot
- `payload` (JSONB): full finding object for drilldowns
- `detected_at` timestamp
- taxonomy fields:
  - `category` (broad bucket like cost/security/reliability/other)
  - `group_key` (stable grouping key for “same type of issue”)

**Used for**
- fast “current findings” list queries
- finding detail pages (using `payload`)
- grouping and faceting (via `category`/`group_key`)

**Ingest contract**
- Upsert N rows per run (overwrite snapshot per fingerprint).

---

### `finding_state_current` (user intent / lifecycle)

User-controlled lifecycle overlay:

> “What did the user decide about this finding in this workspace?”

States are typically:
- `open` (implicit default when no row exists)
- `ignored`
- `snoozed` (with `snooze_until`)
- `resolved`

**Primary key**
- `(tenant_id, workspace, fingerprint)`

**What it stores**
- lifecycle `state`
- `snooze_until`
- optional `reason`, `updated_by`
- `updated_at` and optimistic `version`

**Used for**
- hide/snooze/resolve behavior in the UI/API
- future audit log expansion (optional: event table)

**Modified by**
- API endpoints only (`/api/lifecycle/*`)

---

### `finding_state_audit` (lifecycle audit trail)

Append-only audit log for lifecycle actions:

> “Who changed lifecycle state, on what subject, and when?”

**What it stores**
- scope (`tenant_id`, `workspace`)
- subject (`subject_type`, `subject_id`)
- action/state details (`action`, `state`, `snooze_until`)
- attribution (`reason`, `updated_by`, `created_at`)

**Used for**
- operational traceability
- incident/debug investigations

**Behavior**
- best-effort write from API lifecycle endpoints
- must never block/rollback the primary lifecycle upsert

---

### `finding_current` (canonical read model)

A DB view combining the snapshot and the lifecycle overlay:

`finding_current = finding_latest LEFT JOIN finding_state_current`

It also computes:
- `effective_state`:
  - `resolved` if state is resolved
  - `ignored` if state is ignored
  - `snoozed` if state is snoozed AND `snooze_until > now()`
  - else `open`

**Used for**
- all product/API queries:
  - `/api/findings`
  - `/api/groups`
  - `/api/findings/aggregates`
  - `/api/facets`
- anything that should reflect lifecycle decisions

**Rule**
- Treat `finding_current` as the single source of truth for reads.

---

### `dashboard_cache` (legacy / temporary)

Stores precomputed JSON payloads keyed by `(tenant_id, workspace, run_id, src)`.

**Purpose**
- temporary optimization for early UI iterations

**Important**
- Do not design future features around this table.
- Prefer query primitives (`finding_current`) and/or materialized aggregates instead.

---

## Data flow (ingest)

Typical ingestion for a run:

1. Upsert `runs` row (status = `ingesting` → `ready`)
2. Insert `finding_presence` rows for run membership (history)
3. Upsert `finding_latest` rows for current snapshots
4. `finding_current` automatically reflects lifecycle state (view)

Lifecycle updates:
- Only update `finding_state_current`
- Never rewrite historical `finding_presence`

---

## Operational invariants

- Multi-tenancy is always scoped by `(tenant_id, workspace)`.
- Lifecycle is workspace-scoped (no cross-workspace leakage).
- API/UI reads query `finding_current` only.
- `finding_latest` is a projection and can be rebuilt from artifacts if needed.
- `finding_presence` is the historical record; it grows with each run.

---

## Future extensions (planned)

- Group-level lifecycle (ignore/snooze/resolve a whole `group_key`)
- Materialized aggregates for large tenants (groups, facets, KPIs)
- richer event-sourced lifecycle model derived from `finding_state_audit`
- Partitioning `finding_presence` by time or tenant if volume requires
