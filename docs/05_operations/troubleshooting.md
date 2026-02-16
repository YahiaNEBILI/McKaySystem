# Troubleshooting

Status: Derived  
Last reviewed: 2026-02-01

This document lists **common operational issues**, how to diagnose them, and how to fix them.

It is written from a **production / on-call perspective**: most problems are *expected states*, not bugs.

---

## 1. Costs are always zero / missing in the UI

### Symptoms
- `actual.cost_30d` is `null` or `0` everywhere
- Flask UI shows costs as empty or zero

### Diagnosis checklist

1. **Is CUR available at all?**
   ```bash
   ls data/raw_cur/**/*.parquet
   ```
   - ❌ No files → CUR normalization and enrichment are skipped (expected behavior)

2. **Did normalization run?**
   ```bash
   ls data/cur_facts/**/*.parquet
   ```
   - ❌ Empty → normalization never ran or raw CUR path is wrong

3. **Did enrichment run?**
   ```bash
   ls data/finops_findings_enriched/**/*.parquet
   ```
   - ❌ Empty → enrichment skipped (no CUR facts)

4. **What does coverage say?**
   ```bash
   cat webapp_data/coverage.json
   ```

### Interpretation

| Coverage | Meaning |
|--------|--------|
| 0% | CUR missing or no match possible |
| 10–40% | Resource-level CUR partial |
| 60%+ | Good tagging / CUR quality |

Low coverage is **not an error**.

### Fixes
- Ensure CUR is exported as **Parquet**, not CSV
- Verify CUR is placed under `data/raw_cur/`
- Check `tenant_id` matches findings tenant

---

## 2. Export still uses raw dataset instead of enriched

### Symptoms
- `coverage.json` shows `dataset = raw_union`
- Enriched Parquet exists but UI ignores it

### Diagnosis

1. Verify enriched path:
   ```bash
   ls data/finops_findings_enriched/**/*.parquet
   ```

2. Verify export logs:
   ```bash
   python -m apps.worker.export_findings
   ```
   Look for:
   ```
   [export_json] enriched dataset detected, using it for export
   ```

### Root causes
- Enriched directory empty
- Different `tenant_id` used during enrichment
- Export pointed to non-standard globs

### Fix
- Re-run enrichment with correct tenant
- Do **not** hardcode enriched paths in `apps/worker/export_findings.py`

---

## 3. Correlation step is skipped

### Symptoms
- No files under `data/finops_findings_correlated/`
- Summary prints:
  ```
  correlation: disabled/skipped
  ```

### Diagnosis

1. Was correlation explicitly disabled?
   ```bash
   python -m apps.worker.runner --no-correlation
   ```

2. Is the module present?
   ```bash
   ls pipeline/correlation/
   ```

3. Did correlation rules load?
   - Check startup logs for rule count

### Fix
- Remove `--no-correlation`
- Ensure `pipeline/correlation` is importable
- Validate SQL rules (single statement, deterministic)

---

## 4. Correlation emits zero findings

### Symptoms
- Correlation runs but emits `0` findings

### Diagnosis

1. Inspect raw findings volume:
   ```bash
   ls data/finops_findings/**/*.parquet
   ```

2. Validate rule prefilters (`required_check_ids`)

3. Manually run rule SQL in DuckDB for sanity

### Interpretation

This is often **correct behavior**:
- correlation rules are intentionally conservative
- lack of signal is not a failure

---

## 5. DuckDB errors during correlation or export

### Common errors

- `Binder Error: unexpected prepared parameter`
- `Unable to merge field with incompatible types`

### Root causes

- SQL rule contains multiple statements (`;`)
- Schema drift across Parquet files
- Arrow type mismatch (string vs dictionary)

### Fixes

- Ensure **one SQL statement per rule**
- Use `union_by_name=true` (already default)
- Normalize types at the storage boundary

---

## 6. Storage cast errors / dropped records

### Symptoms
- `writer_dropped_cast_errors > 0`
- Some findings missing in Parquet

### Diagnosis

Check runner summary:
```
writer_dropped_cast_errors: X
```

Inspect sample errors printed at end of run.

### Fix
- Fix checker emitting invalid wire values
- Respect schema types (Decimal, timestamp)
- Avoid empty strings for numeric fields

---

## 7. Different results between runs (non-determinism)

### Symptoms
- Same input → different findings IDs or counts

### Diagnosis

1. Verify `finding_id_mode` is `stable`
2. Check checker ordering and sorting
3. Run stress tests

### Fix
- Sort inputs before processing
- Avoid iteration over unordered dicts
- Use deterministic hashing only

---

## 8. CUR present but coverage is very low

### Explanation

This is **expected** for some services:
- S3
- CloudWatch
- Shared services

CUR often lacks resource-level identifiers.

### Improvement paths
- Add tag-based Tier B matching
- Add service-specific matchers
- Accept roll-up attribution for governance findings

---

## 9. When to worry (and when not to)

| Symptom | Worry? |
|------|------|
| CUR missing | ❌ No |
| Coverage < 30% | ❌ No |
| Correlation emits 0 | ❌ No |
| Schema cast errors | ✅ Yes |
| Non-deterministic IDs | ✅ Yes |

---

## Mental model

> **The pipeline is resilient by design.**

Most “issues” are signals about data quality, not system failures.

If the runner exits successfully and writes Parquet, the system is working as intended.
