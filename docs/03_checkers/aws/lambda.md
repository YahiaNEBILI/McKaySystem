# AWS Lambda checker

Status: Canonical  
Last reviewed: 2026-02-15

**Source code:** `checks/aws/lambda_functions_analyzer.py`

## Purpose

Detect Lambda functions that are likely:
- unused/idle
- overprovisioned for memory

The checker emits deterministic infra-native signals and best-effort savings estimates.

## Checker identity

- `checker_id`: `aws.lambda.functions.analyzer`
- `spec`: `checks.aws.lambda_functions_analyzer:LambdaFunctionsAnalyzerChecker`

## Check IDs emitted

- `aws.lambda.functions.unused`
- `aws.lambda.functions.memory.overprovisioned`
- `aws.lambda.functions.access.error`
- `aws.lambda.functions.missing.permission`
- `aws.lambda.functions.cloudwatch.error`

## Detection logic

### 1) Idle Lambda functions

A function is flagged as `aws.lambda.functions.unused` when:
- CloudWatch `Invocations` metric is available with at least `min_daily_datapoints`
- Daily p95 invocations over `lookback_days` is less than or equal to `idle_p95_daily_invocations_threshold`

Metric details:
- Namespace: `AWS/Lambda`
- Metric: `Invocations`
- Period: `86400` seconds (daily)
- Stat: `Sum`

### 2) Memory overprovisioning candidates

A function is flagged as `aws.lambda.functions.memory.overprovisioned` when all conditions hold:
- Allocated memory is at least `memory_overprov_min_allocated_mb`
- `Invocations` and `Duration` each have at least `min_daily_datapoints`
- p95 `Duration` (ms) is less than or equal to `memory_overprov_max_p95_duration_ms`
- p95 duration / configured timeout is less than or equal to `memory_overprov_max_duration_to_timeout_ratio`
- total invocations in the observed window are at least `memory_overprov_min_invocations`

Metric details:
- Namespace: `AWS/Lambda`
- Metrics: `Invocations`, `Duration`
- Period: `86400` seconds (daily)
- Stats: `Sum` (`Invocations`), `p95` (`Duration`)

## Estimation model

This checker estimates compute-only Lambda cost impact (GB-second model).

### Current monthly compute estimate

- `monthly_invocations` = observed daily invocations normalized to 30 days
- `duration_seconds` = p95 duration in seconds
- `memory_gb` = configured memory MB / 1024
- `monthly_cost` = `monthly_invocations * duration_seconds * memory_gb * usd_per_gb_second`

### Savings estimate for memory right-sizing

The checker computes a target memory:
- `target_memory_mb = max(128, configured_memory_mb * memory_overprov_target_memory_ratio)`

Then computes projected cost with:
- increased duration = `current_duration * memory_overprov_duration_slowdown_factor`
- reduced memory = `target_memory_mb`

Estimated savings:
- `estimated_monthly_savings = max(0, current_monthly_cost - projected_monthly_cost)`

Pricing source:
- first choice: Pricing service (`AWSLambda`)
- fallback: `LAMBDA_FALLBACK_GB_SECOND_USD`

## Default thresholds

Defaults come from `checks/aws/defaults.py`:

- `LAMBDA_LOOKBACK_DAYS = 14`
- `LAMBDA_MIN_DAILY_DATAPOINTS = 7`
- `LAMBDA_IDLE_P95_DAILY_INVOCATIONS_THRESHOLD = 1.0`
- `LAMBDA_MEMORY_OVERPROV_MIN_ALLOCATED_MB = 1024`
- `LAMBDA_MEMORY_OVERPROV_MAX_P95_DURATION_MS = 250.0`
- `LAMBDA_MEMORY_OVERPROV_MAX_DURATION_TO_TIMEOUT_RATIO = 0.20`
- `LAMBDA_MEMORY_OVERPROV_MIN_INVOCATIONS = 100`
- `LAMBDA_MEMORY_OVERPROV_TARGET_MEMORY_RATIO = 0.50`
- `LAMBDA_MEMORY_OVERPROV_DURATION_SLOWDOWN_FACTOR = 1.20`
- `LAMBDA_FALLBACK_GB_SECOND_USD = 0.0000166667`

## IAM permissions

Required for full signal coverage:
- `lambda:ListFunctions`
- `cloudwatch:GetMetricData`

Optional for better estimate confidence:
- `pricing:GetProducts` (through the pricing service)

Behavior on missing permissions:
- `lambda:ListFunctions` denied -> emits `aws.lambda.functions.access.error`
- `cloudwatch:GetMetricData` denied -> emits `aws.lambda.functions.missing.permission`
- Unexpected CloudWatch runtime/API issues -> emits `aws.lambda.functions.cloudwatch.error`

## Determinism and fingerprint stability

- Function inventory is normalized and sorted by function name/ARN before evaluation.
- Issue keys are stable and minimal:
  - idle: `{"function_name": ..., "signal": "idle"}`
  - memory: `{"function_name": ..., "signal": "memory_overprovisioned"}`
- No timestamps or random values are used in issue keys.

## Limitations

- Memory findings are heuristic recommendations, not guaranteed safe right-sizing actions.
- Estimates cover compute usage only; they do not model request charges or downstream service costs.
- If CloudWatch metrics are unavailable, idle/overprovisioned findings are not produced.
- Correlation or CUR enrichment should be used for higher-fidelity cost attribution.

## Related correlation and tests

- Correlation rule consuming idle signal:
  - `pipeline/correlation/rules/aws_lambda_cloudwatch_logs_cost.sql`
- Unit tests:
  - `tests/test_lambda_functions_analyzer.py`
