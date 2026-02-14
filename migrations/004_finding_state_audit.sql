CREATE TABLE IF NOT EXISTS finding_state_audit (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  workspace TEXT NOT NULL,
  subject_type TEXT NOT NULL,
  subject_id TEXT NOT NULL,
  action TEXT NOT NULL,
  state TEXT NOT NULL,
  snooze_until TIMESTAMPTZ NULL,
  reason TEXT NULL,
  updated_by TEXT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_finding_state_audit_tenant_ws_created
  ON finding_state_audit (tenant_id, workspace, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_finding_state_audit_subject_created
  ON finding_state_audit (tenant_id, workspace, subject_type, subject_id, created_at DESC);
