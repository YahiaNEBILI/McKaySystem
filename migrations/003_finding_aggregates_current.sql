CREATE TABLE IF NOT EXISTS finding_aggregates_current (
  tenant_id TEXT NOT NULL,
  workspace TEXT NOT NULL,
  dimension TEXT NOT NULL,
  key TEXT NOT NULL,
  finding_count BIGINT NOT NULL,
  total_savings DOUBLE PRECISION NOT NULL DEFAULT 0,
  refreshed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, workspace, dimension, key)
);

CREATE INDEX IF NOT EXISTS idx_finding_aggregates_current_tenant_ws_dim
  ON finding_aggregates_current (tenant_id, workspace, dimension);
