-- Recovery sweep performance indexes (tenant/workspace scoped).

CREATE INDEX IF NOT EXISTS idx_run_locks_tenant_ws_expires
  ON run_locks (tenant_id, workspace, expires_at);

