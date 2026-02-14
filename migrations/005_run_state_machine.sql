-- Minimal run state machine primitives:
-- - strict run status values
-- - append-only run events
-- - run-scoped lock with TTL

-- Normalize legacy status values before adding strict constraint.
UPDATE runs
SET status = 'running'
WHERE status = 'ingesting';

UPDATE runs
SET status = 'failed'
WHERE status NOT IN ('running', 'ready', 'failed');

ALTER TABLE runs
DROP CONSTRAINT IF EXISTS ck_runs_status;

ALTER TABLE runs
ADD CONSTRAINT ck_runs_status
CHECK (status IN ('running', 'ready', 'failed'));

CREATE TABLE IF NOT EXISTS run_events (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  workspace TEXT NOT NULL,
  run_id TEXT NOT NULL,
  event_type TEXT NOT NULL,
  actor TEXT NOT NULL,
  from_state TEXT NULL,
  to_state TEXT NULL,
  payload JSONB NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_run_events_tenant_ws_run_created
  ON run_events (tenant_id, workspace, run_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_run_events_tenant_ws_type_created
  ON run_events (tenant_id, workspace, event_type, created_at DESC);

CREATE TABLE IF NOT EXISTS run_locks (
  tenant_id TEXT NOT NULL,
  workspace TEXT NOT NULL,
  run_id TEXT NOT NULL,
  lock_owner TEXT NOT NULL,
  lock_token TEXT NOT NULL,
  acquired_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, workspace, run_id)
);

CREATE INDEX IF NOT EXISTS idx_run_locks_expires
  ON run_locks (expires_at);
