-- Initial schema for McKaySystem

CREATE TABLE IF NOT EXISTS finding_state_current (
  tenant_id TEXT NOT NULL,
  workspace TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  state TEXT NOT NULL,
  snooze_until TIMESTAMPTZ NULL,
  reason TEXT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_by TEXT NULL,
  version INTEGER NOT NULL DEFAULT 1,
  PRIMARY KEY (tenant_id, workspace, fingerprint)
);

CREATE INDEX IF NOT EXISTS idx_finding_state_current_tenant_ws_state
  ON finding_state_current (tenant_id, workspace, state);

CREATE TABLE IF NOT EXISTS finding_group_state_current (
  tenant_id TEXT NOT NULL,
  workspace TEXT NOT NULL,
  group_key TEXT NOT NULL,
  state TEXT NOT NULL,
  snooze_until TIMESTAMPTZ NULL,
  reason TEXT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_by TEXT NULL,
  version INTEGER NOT NULL DEFAULT 1,
  PRIMARY KEY (tenant_id, workspace, group_key)
);

CREATE INDEX IF NOT EXISTS idx_finding_group_state_current_tenant_ws_state
  ON finding_group_state_current (tenant_id, workspace, state);

CREATE TABLE IF NOT EXISTS runs (
  tenant_id TEXT NOT NULL,
  workspace TEXT NOT NULL,
  run_id TEXT NOT NULL,
  run_ts TIMESTAMPTZ NOT NULL,
  status TEXT NOT NULL,
  artifact_prefix TEXT NOT NULL,
  ingested_at TIMESTAMPTZ NULL,
  engine_version TEXT NULL,
  raw_present BOOLEAN NOT NULL DEFAULT FALSE,
  correlated_present BOOLEAN NOT NULL DEFAULT FALSE,
  enriched_present BOOLEAN NOT NULL DEFAULT FALSE,
  PRIMARY KEY (tenant_id, workspace, run_id)
);

CREATE INDEX IF NOT EXISTS idx_runs_tenant_workspace_ts
  ON runs (tenant_id, workspace, run_ts DESC);

CREATE INDEX IF NOT EXISTS idx_runs_tenant_ws_status_ts
  ON runs (tenant_id, workspace, status, run_ts DESC);

CREATE TABLE IF NOT EXISTS finding_presence (
  tenant_id TEXT NOT NULL,
  workspace TEXT NOT NULL,
  run_id TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  check_id TEXT NULL,
  service TEXT NULL,
  severity TEXT NULL,
  title TEXT NULL,
  estimated_monthly_savings DOUBLE PRECISION NULL,
  region TEXT NULL,
  account_id TEXT NULL,
  detected_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (tenant_id, workspace, run_id, fingerprint)
);

CREATE INDEX IF NOT EXISTS idx_presence_tenant_ws_run
  ON finding_presence (tenant_id, workspace, run_id);

CREATE INDEX IF NOT EXISTS idx_presence_tenant_ws_fp
  ON finding_presence (tenant_id, workspace, fingerprint);

CREATE INDEX IF NOT EXISTS idx_presence_tenant_ws_check
  ON finding_presence (tenant_id, workspace, check_id);

CREATE INDEX IF NOT EXISTS idx_presence_tenant_ws_detected
  ON finding_presence (tenant_id, workspace, detected_at DESC);

CREATE TABLE IF NOT EXISTS finding_latest (
  tenant_id TEXT NOT NULL,
  workspace TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  run_id TEXT NOT NULL,

  check_id TEXT NULL,
  service TEXT NULL,
  severity TEXT NULL,
  title TEXT NULL,
  estimated_monthly_savings DOUBLE PRECISION NULL,
  region TEXT NULL,
  account_id TEXT NULL,

  category TEXT NULL,
  group_key TEXT NULL,

  payload JSONB NOT NULL,
  detected_at TIMESTAMPTZ NOT NULL,

  PRIMARY KEY (tenant_id, workspace, fingerprint)
);

CREATE INDEX IF NOT EXISTS idx_finding_latest_tenant_ws
  ON finding_latest (tenant_id, workspace);

CREATE INDEX IF NOT EXISTS idx_finding_latest_check
  ON finding_latest (check_id);

CREATE INDEX IF NOT EXISTS idx_finding_latest_service
  ON finding_latest (service);

CREATE INDEX IF NOT EXISTS idx_finding_latest_tenant_ws_savings
  ON finding_latest (tenant_id, workspace, estimated_monthly_savings DESC);

CREATE INDEX IF NOT EXISTS idx_finding_latest_tenant_ws_service
  ON finding_latest (tenant_id, workspace, service);

CREATE INDEX IF NOT EXISTS idx_finding_latest_tenant_ws_account
  ON finding_latest (tenant_id, workspace, account_id);

CREATE INDEX IF NOT EXISTS idx_finding_latest_tenant_ws_severity
  ON finding_latest (tenant_id, workspace, severity);

CREATE INDEX IF NOT EXISTS idx_finding_latest_tenant_ws_check
  ON finding_latest (tenant_id, workspace, check_id);

CREATE INDEX IF NOT EXISTS idx_finding_latest_tenant_ws_category
  ON finding_latest (tenant_id, workspace, category);

CREATE INDEX IF NOT EXISTS idx_finding_latest_tenant_ws_group_key
  ON finding_latest (tenant_id, workspace, group_key);

CREATE INDEX IF NOT EXISTS idx_finding_group_state_current_tenant_ws_group
  ON finding_group_state_current (tenant_id, workspace, group_key);

CREATE TABLE IF NOT EXISTS dashboard_cache (
  tenant_id   TEXT NOT NULL,
  workspace   TEXT NOT NULL,
  run_id      TEXT NOT NULL,
  src         TEXT NOT NULL,
  payload     JSONB NOT NULL,
  computed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, workspace, run_id, src)
);

CREATE INDEX IF NOT EXISTS idx_dashboard_cache_latest
  ON dashboard_cache (tenant_id, workspace, computed_at DESC);

CREATE OR REPLACE VIEW finding_current AS
SELECT
  fl.tenant_id,
  fl.workspace,
  fl.fingerprint,
  fl.run_id,
  fl.check_id,
  fl.service,
  fl.severity,
  fl.title,
  fl.estimated_monthly_savings,
  fl.region,
  fl.account_id,
  fl.category,
  fl.group_key,
  fl.detected_at,
  fl.payload,

  COALESCE(gs.state, fs.state, 'open') AS state,
  COALESCE(gs.snooze_until, fs.snooze_until) AS snooze_until,
  COALESCE(gs.reason, fs.reason) AS reason,

  CASE
    WHEN gs.state = 'resolved' THEN 'resolved'
    WHEN gs.state = 'ignored' THEN 'ignored'
    WHEN gs.state = 'snoozed' AND gs.snooze_until > now() THEN 'snoozed'

    WHEN fs.state = 'resolved' THEN 'resolved'
    WHEN fs.state = 'ignored' THEN 'ignored'
    WHEN fs.state = 'snoozed' AND fs.snooze_until > now() THEN 'snoozed'

    ELSE 'open'
  END AS effective_state

FROM finding_latest fl
LEFT JOIN finding_group_state_current gs
  ON gs.tenant_id = fl.tenant_id
 AND gs.workspace = fl.workspace
 AND gs.group_key = fl.group_key

LEFT JOIN finding_state_current fs
  ON fs.tenant_id = fl.tenant_id
 AND fs.workspace = fl.workspace
 AND fs.fingerprint = fl.fingerprint;
