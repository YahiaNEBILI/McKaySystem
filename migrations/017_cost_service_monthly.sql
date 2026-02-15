-- Migration: 017_cost_service_monthly.sql
-- 
-- Cost Explorer Analyzer - Durable Cost History Store
--
-- This table stores monthly service-level costs from AWS Cost Explorer API
-- and optionally from CUR backfill. It enables stateless, deterministic
-- detection without relying on runner-local state.
--
-- See: cost_explorer_checker_design_v2.md

-- Create the cost_service_monthly table
CREATE TABLE IF NOT EXISTS cost_service_monthly (
    tenant_id            TEXT NOT NULL,
    workspace            TEXT NOT NULL,
    account_id           TEXT NOT NULL,
    billing_account_id   TEXT,
    service              TEXT NOT NULL,
    period_start         DATE NOT NULL,         -- first day of the month
    period_end           DATE NOT NULL,         -- first day of next month (exclusive)
    unblended_cost       NUMERIC(18,6) NOT NULL,
    blended_cost         NUMERIC(18,6),
    amortized_cost       NUMERIC(18,6),
    currency             TEXT NOT NULL DEFAULT 'USD',
    source               TEXT NOT NULL,         -- 'ce' | 'cur'
    ingested_at_utc      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, workspace, account_id, service, period_start)
);

-- Common query patterns for detection / dashboards
-- Index for period-based queries (e.g., "last 12 months")
CREATE INDEX IF NOT EXISTS idx_cost_service_monthly_period
    ON cost_service_monthly (tenant_id, workspace, account_id, period_start DESC);

-- Index for service-based queries with period filter
CREATE INDEX IF NOT EXISTS idx_cost_service_monthly_service_period
    ON cost_service_monthly (tenant_id, workspace, account_id, service, period_start DESC);

-- Index for efficient deduplication checks
CREATE INDEX IF NOT EXISTS idx_cost_service_monthly_lookup
    ON cost_service_monthly (tenant_id, workspace, account_id, service, period_start)
    INCLUDE (unblended_cost, blended_cost, amortized_cost, currency, source);

-- Comment for documentation
COMMENT ON TABLE cost_service_monthly IS
    'Monthly AWS service-level costs from Cost Explorer API (source=ce) or CUR (source=cur). '
    'Used by cost_explorer_analyzer for stateless anomaly and trend detection.';
