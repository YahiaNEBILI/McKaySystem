import pyarrow as pa

# -----------------------------
# Common reusable sub-schemas
# -----------------------------

MONEY = pa.decimal128(18, 6)  # finance-grade (change to pa.float64() if you want simplicity)
UTC_TS_MS = pa.timestamp("ms", tz="UTC")

TAGS_MAP = pa.map_(pa.string(), pa.string())  # cost allocation tags / resource tags
LABELS_MAP = pa.map_(pa.string(), pa.string())  # internal labels (pipeline, segmentation, etc.)

# A "scope" object describing what the finding targets.
SCOPE_STRUCT = pa.struct([
    pa.field("cloud", pa.string()),              # "aws" | "azure" | "gcp" | ...
    pa.field("provider_partition", pa.string()), # optional: aws partition "aws"/"aws-cn"/"aws-us-gov"
    pa.field("organization_id", pa.string()),    # optional: org/management group/billing account id
    pa.field("billing_account_id", pa.string()), # payer / billing root
    pa.field("account_id", pa.string()),         # linked account / subscription / project
    pa.field("region", pa.string()),
    pa.field("availability_zone", pa.string()),
    pa.field("service", pa.string()),            # e.g. "AmazonEC2", "S3"
    pa.field("resource_type", pa.string()),      # e.g. "ec2_instance", "s3_bucket"
    pa.field("resource_id", pa.string()),        # e.g. "i-...", bucket name, resource ARN, etc.
    pa.field("resource_arn", pa.string()),       # optional (aws)
])

# Evidence links for UX / audit trail (console deep links, docs links, tickets...)
LINKS_LIST = pa.list_(pa.struct([
    pa.field("label", pa.string()),
    pa.field("url", pa.string()),
]))

# Pricing/cost model metadata
COST_MODEL_STRUCT = pa.struct([
    pa.field("currency", pa.string()),           # "USD", "EUR" (store amounts in that currency)
    pa.field("cost_model", pa.string()),         # "unblended" | "amortized" | "net" | "blended"
    pa.field("granularity", pa.string()),        # "daily" | "hourly" | "monthly" | "period"
    pa.field("period_start", pa.date32()),
    pa.field("period_end", pa.date32()),
])

# Attribution summary embedded in findings (high level)
ATTRIBUTION_STRUCT = pa.struct([
    pa.field("method", pa.string()),             # "exact_resource_id" | "tag" | "heuristic" | "unallocated" | "none"
    pa.field("confidence", pa.uint8()),          # 0..100
    pa.field("matched_keys", pa.list_(pa.string())),  # which keys matched (e.g., ["line_item_resource_id", "tag:Name"])
])

# A standardized severity model (string is flexible; keep numeric for sorting)
SEVERITY_STRUCT = pa.struct([
    pa.field("level", pa.string()),              # "info"|"low"|"medium"|"high"|"critical"
    pa.field("score", pa.uint16()),              # 0..1000
])

# Status lifecycle (helps dedup + long term tracking)
LIFECYCLE_STRUCT = pa.struct([
    pa.field("status", pa.string()),             # "open"|"acknowledged"|"snoozed"|"resolved"|"ignored"
    pa.field("first_seen_ts", UTC_TS_MS),
    pa.field("last_seen_ts", UTC_TS_MS),
    pa.field("resolved_ts", UTC_TS_MS),
    pa.field("snooze_until_ts", UTC_TS_MS),
])

# -----------------------------
# 1) Main table: Findings
# -----------------------------
FINOPS_FINDINGS_SCHEMA = pa.schema([
    # Multi-tenant + identity
    pa.field("tenant_id", pa.string()),          # required
    pa.field("workspace_id", pa.string()),       # optional (prod/dev, BU, etc.)

    # Stable IDs (for dedup, history, joins)
    pa.field("finding_id", pa.string()),         # recommended: deterministic hash (tenant + check + scope + fingerprint)
    pa.field("fingerprint", pa.string()),        # stable signature across runs (same issue on same target)
    pa.field("run_id", pa.string()),             # ingestion/execution run identifier
    pa.field("run_ts", UTC_TS_MS),
    pa.field("ingested_ts", UTC_TS_MS),

    # Engine metadata
    pa.field("engine_name", pa.string()),        # "finopsanalyzer" / product name
    pa.field("engine_version", pa.string()),     # semantic version
    pa.field("rulepack_version", pa.string()),   # ruleset/checks version

    # What the finding targets
    pa.field("scope", SCOPE_STRUCT),

    # Check/rule identity
    pa.field("check_id", pa.string()),           # stable machine id e.g. "aws.ec2.rightsize.graviton"
    pa.field("check_name", pa.string()),         # human name
    pa.field("category", pa.string()),           # "rightsizing"|"waste"|"commitments"|"governance"|...
    pa.field("sub_category", pa.string()),       # optional
    pa.field("frameworks", pa.list_(pa.string())),  # "FinOps", "CIS", internal frameworks, etc.

    # Result + severity
    pa.field("status", pa.string()),             # "pass"|"fail"|"info"|"unknown"
    pa.field("severity", SEVERITY_STRUCT),
    pa.field("priority", pa.uint16()),           # sorting override (optional)

    # Human-facing content
    pa.field("title", pa.string()),
    pa.field("message", pa.string()),
    pa.field("recommendation", pa.string()),
    pa.field("remediation", pa.string()),        # optional: how-to steps
    pa.field("links", LINKS_LIST),

    # Economic impact (estimated) — what your engine thinks
    pa.field("estimated", pa.struct([
        pa.field("monthly_savings", MONEY),      # e.g. if you apply the recommendation
        pa.field("monthly_cost", MONEY),         # optional: estimated current monthly cost of the target
        pa.field("one_time_savings", MONEY),     # optional: e.g., reserved cleanup
        pa.field("confidence", pa.uint8()),      # 0..100 (confidence in estimate)
        pa.field("notes", pa.string()),
    ])),

    # Economic impact (actual from CUR) — what billing shows, once attributed
    pa.field("actual", pa.struct([
        pa.field("cost_7d", MONEY),
        pa.field("cost_30d", MONEY),
        pa.field("cost_mtd", MONEY),
        pa.field("cost_prev_month", MONEY),
        pa.field("savings_7d", MONEY),           # optional if you compute realized savings
        pa.field("savings_30d", MONEY),
        pa.field("model", COST_MODEL_STRUCT),
        pa.field("attribution", ATTRIBUTION_STRUCT),
    ])),

    # State tracking in your SaaS
    pa.field("lifecycle", LIFECYCLE_STRUCT),

    # Tags/labels
    pa.field("tags", TAGS_MAP),                  # provider tags captured at scan time
    pa.field("labels", LABELS_MAP),              # internal labels for routing, teams, segments

    # Flexible extension points (keep schema stable)
    pa.field("dimensions", pa.map_(pa.string(), pa.string())),  # normalized dims (instance_family, engine, etc.)
    pa.field("metrics", pa.map_(pa.string(), MONEY)),           # generic numeric metrics (typed)
    pa.field("metadata_json", pa.string()),      # last resort (JSON string)

    # Data quality / lineage
    pa.field("source", pa.struct([
        pa.field("source_type", pa.string()),    # "scanner"|"import"|"api"
        pa.field("source_ref", pa.string()),     # file path, object key, job id, etc.
        pa.field("schema_version", pa.uint16()), # increment when you change this schema
    ])),
])

# -----------------------------
# 2) Optional: Cost attribution evidence table (high value for "explainability")
#    1 row = 1 attributed slice of CUR cost to a finding/fingerprint
# -----------------------------
FINOPS_COST_ATTRIBUTION_SCHEMA = pa.schema([
    pa.field("tenant_id", pa.string()),
    pa.field("workspace_id", pa.string()),

    # Link back to finding
    pa.field("finding_id", pa.string()),
    pa.field("fingerprint", pa.string()),

    # Period and model
    pa.field("period_start", pa.date32()),
    pa.field("period_end", pa.date32()),
    pa.field("currency", pa.string()),
    pa.field("cost_model", pa.string()),         # "unblended"|"amortized"|"net"...

    # Attribution result
    pa.field("method", pa.string()),             # "exact_resource_id"|"tag"|"heuristic"|...
    pa.field("confidence", pa.uint8()),
    pa.field("cost_amount", MONEY),

    # CUR identity hints (keep it light; full CUR remains in its own parquet)
    pa.field("cur", pa.struct([
        pa.field("payer_account_id", pa.string()),
        pa.field("linked_account_id", pa.string()),
        pa.field("region", pa.string()),
        pa.field("service", pa.string()),
        pa.field("usage_type", pa.string()),
        pa.field("operation", pa.string()),
        pa.field("resource_id", pa.string()),    # line_item_resource_id if available
        pa.field("line_item_type", pa.string()), # Usage, DiscountedUsage, RIFee, SavingsPlanCoveredUsage, etc.
    ])),

    # Keys used to match
    pa.field("matched_keys", pa.list_(pa.string())),
    pa.field("notes", pa.string()),

    # Lineage
    pa.field("ingested_ts", UTC_TS_MS),
    pa.field("source_ref", pa.string()),
])

# -----------------------------
# 3) Optional: KPI "gold" tables
#    Keep them separate; schema depends on KPI, but here's a generic pattern
# -----------------------------
FINOPS_KPI_BASE_SCHEMA = pa.schema([
    pa.field("tenant_id", pa.string()),
    pa.field("workspace_id", pa.string()),
    pa.field("period", pa.string()),             # "2026-01" or "2026-01-22"
    pa.field("kpi_name", pa.string()),
    pa.field("dimensions", pa.map_(pa.string(), pa.string())),
    pa.field("value", MONEY),
    pa.field("currency", pa.string()),
    pa.field("computed_ts", UTC_TS_MS),
    pa.field("source_ref", pa.string()),
])
