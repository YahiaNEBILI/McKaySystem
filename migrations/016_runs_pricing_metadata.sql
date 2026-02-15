-- Add pricing metadata fields to runs for deterministic recommendation estimation fallback.
-- Safe additive migration: nullable columns, no behavior change for existing rows.

ALTER TABLE runs
ADD COLUMN IF NOT EXISTS pricing_version TEXT NULL;

ALTER TABLE runs
ADD COLUMN IF NOT EXISTS pricing_source TEXT NULL;

CREATE INDEX IF NOT EXISTS idx_runs_tenant_ws_pricing_version
  ON runs (tenant_id, workspace, pricing_version);
