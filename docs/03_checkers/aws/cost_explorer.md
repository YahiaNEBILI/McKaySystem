# Cost Explorer Analyzer

## Overview

The Cost Explorer Analyzer checker detects cost anomalies and trends at the AWS service level using AWS Cost Explorer API as the primary freshness source, with Postgres as the durable history store for historical context.

## Checker ID

```
aws.cost.explorer.analyzer
```

## Purpose

- Detect cost anomalies (spikes and drops)
- Identify sustained cost trends (increasing/decreasing)
- Monitor for new or absent AWS services
- Provide early warning of unexpected cost changes

## Architecture

### Data Flow

```
AWS Cost Explorer API → Fresh Data → Postgres (cost_service_monthly)
                                                    ↓
                                            Detection Layers
                                                    ↓
                                              Findings
```

### Components

1. **Cost Explorer Client** - Fetches latest cost data from AWS
2. **Postgres History Store** - Stores monthly service-level costs
3. **Detection Engine** - Runs layered detection algorithms

## Emitted Check IDs

| Check ID | Category | Description |
|----------|----------|-------------|
| `aws.cost.anomaly.spike` | Anomaly | Significant cost spike detected |
| `aws.cost.anomaly.drop` | Anomaly | Significant cost drop detected |
| `aws.cost.trend.increasing` | Trend | Sustained cost increase |
| `aws.cost.trend.decreasing` | Trend | Sustained cost decrease |
| `aws.cost.service.new` | Discovery | New service appearing in costs |
| `aws.cost.service.absent` | Discovery | Previously billed service now absent |
| `aws.cost.access.error` | Error | Access denied to Cost Explorer |

## Detection Methods

### 1. Threshold-Based Detection

Compares current month to previous month:
- **Spike**: `(current - previous) / previous * 100 >= spike_threshold_pct`
- **Drop**: `(previous - current) / previous * 100 >= drop_threshold_pct`

### 2. Moving Average / Z-score

- Computes rolling mean over configurable window
- Z-score mode: flags if `abs(z) >= zscore_threshold` (default: 2.0)
- Detects deviations from historical patterns

### 3. Year-over-Year Comparison

- Compares current month to same month last year
- Requires 12+ months of history
- Flags changes exceeding configured threshold

### 4. Trend Detection (Regression)

- Uses linear regression to detect sustained trends
- Flags if slope exceeds minimum threshold
- More robust than simple monotonic checks

### 5. Service Discovery

- **New service**: present now, absent previously
- **Absent service**: present previously, absent now

## Configuration

### Default Thresholds

| Parameter | Default | Description |
|-----------|---------|-------------|
| `COST_EXPLORER_LOOKBACK_MONTHS` | 12 | Months of history to retain |
| `COST_EXPLORER_CE_FRESHNESS_MONTHS` | 3 | Months to fetch from CE |
| `COST_EXPLORER_SPIKE_THRESHOLD_PCT` | 20.0 | Spike detection threshold (%) |
| `COST_EXPLORER_DROP_THRESHOLD_PCT` | 20.0 | Drop detection threshold (%) |
| `COST_EXPLORER_MIN_COST_ABS` | 25.0 | Minimum cost to consider ($) |
| `COST_EXPLORER_MIN_DELTA_ABS` | 50.0 | Minimum delta to consider ($) |
| `COST_EXPLORER_ZSCORE_THRESHOLD` | 2.0 | Z-score threshold |
| `COST_EXPLORER_ENABLE_ZSCORE` | True | Enable z-score detection |
| `COST_EXPLORER_ENABLE_YOY` | True | Enable year-over-year |
| `COST_EXPLORER_YOY_THRESHOLD_PCT` | 30.0 | YoY threshold (%) |

## Database Schema

### Table: cost_service_monthly

```sql
CREATE TABLE cost_service_monthly (
    tenant_id            TEXT NOT NULL,
    workspace            TEXT NOT NULL,
    account_id           TEXT NOT NULL,
    billing_account_id   TEXT,
    service              TEXT NOT NULL,
    period_start         DATE NOT NULL,
    period_end           DATE NOT NULL,
    unblended_cost       NUMERIC(18,6) NOT NULL,
    blended_cost         NUMERIC(18,6),
    amortized_cost       NUMERIC(18,6),
    currency             TEXT NOT NULL,
    source               TEXT NOT NULL,  -- 'ce' or 'cur'
    ingested_at_utc      TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, workspace, account_id, service, period_start)
);
```

## IAM Permissions

Required:
- `ce:GetCostAndUsage` - Get cost data

## Usage

The checker is automatically registered and invoked via:

```
checks.aws.cost.explorer.analyzer:CostExplorerAnalyzerChecker
```

## Determinism

- Services are processed in alphabetical order
- Monetary values use Decimal for precise calculations
- Issue keys contain no timestamps
- Same input history produces identical findings

## Limitations

- Cost Explorer data may have 24-48 hour delay
- Monthly granularity (daily is possible but more expensive)
- YoY requires 12+ months of history
