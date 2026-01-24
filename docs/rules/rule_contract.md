# Correlation Rule Output Contract

The correlation engine is easiest to operate when **every SQL rule returns the same schema**.

This contract standardizes:
- column names
- column types
- required vs optional columns
- how tags/labels/metrics are represented

## Required columns

| column | type (DuckDB) | notes |
|---|---|---|
| rule_id | VARCHAR | stable id of the rule |
| status | VARCHAR | `pass` / `fail` / `warn` (your convention) |
| resource_id | VARCHAR | the primary resource identifier |
| account_id | VARCHAR | AWS account id |
| region | VARCHAR | AWS region or `global` |
| title | VARCHAR | short human title |
| description | VARCHAR | longer human explanation |
| severity | VARCHAR | `info/low/medium/high/critical` (your convention) |
| detected_at | TIMESTAMP | when the rule evaluated / detected |
| tags | MAP(VARCHAR, VARCHAR) | arbitrary key/value metadata (empty allowed) |
| labels | MAP(VARCHAR, VARCHAR) | normalized labels (empty allowed) |
| metrics | MAP(VARCHAR, DOUBLE) | numeric metrics (empty allowed) |

## Optional columns (recommended)

| column | type | notes |
|---|---|---|
| service | VARCHAR | e.g. `aws.backup` |
| category | VARCHAR | e.g. `backup` |
| finding_id | VARCHAR | stable hash/id if you have it |
| remediation | VARCHAR | short remediation |
| link | VARCHAR | console / docs link |
| raw | JSON or VARCHAR | raw snippet of supporting data |

## Empty values (IMPORTANT)

DuckDB does **not** accept `{}` as a literal.
Use these instead:

### Empty tags/labels/metrics
```sql
map([],[]) AS tags,
map([],[]) AS labels,
map([],[]) AS metrics
```

### One key/value pair
```sql
map(['vault_name'], [vault_name]) AS tags
```

### Multiple keys
```sql
map(['k1','k2'], ['v1','v2']) AS tags
```

> If you prefer JSON strings instead of MAP, standardize to:
> `CAST('{}' AS VARCHAR) AS tags`
> across all rules. MAP is preferred because it round-trips cleanly into Python dicts.

## Example skeleton (copy/paste)

```sql
-- rule_id: example_rule
-- name: Example
-- severity: low
-- category: backup
-- service: aws.backup
-- enabled: true
-- tags_type: map

WITH src AS (
  SELECT * FROM aws.backup.vaults
)
SELECT
  'example_rule' AS rule_id,
  CASE WHEN ... THEN 'fail' ELSE 'pass' END AS status,
  vault_arn AS resource_id,
  account_id,
  region,
  'Example title' AS title,
  'Example description' AS description,
  'low' AS severity,
  now() AS detected_at,
  map([],[]) AS tags,
  map([],[]) AS labels,
  map([],[]) AS metrics,
  'aws.backup' AS service,
  'backup' AS category
FROM src;
```

## Implementation checklist

1. Update each `*.sql` rule to return **all required columns** with correct types.
2. Replace any `{} AS tags` with `map([],[]) AS tags`.
3. Make `ruleset.py` load rule metadata from SQL headers to reduce drift.
4. Add a CI step that runs `EXPLAIN` on each rule against a minimal schema (optional but recommended).
