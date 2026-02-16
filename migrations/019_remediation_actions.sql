-- Migration 019: remediation actions queue + approval state
-- Adds a tenant/workspace-scoped action table used by remediation APIs.

CREATE TABLE IF NOT EXISTS remediation_actions (
    tenant_id TEXT NOT NULL,
    workspace TEXT NOT NULL,
    action_id TEXT NOT NULL,

    -- Finding linkage
    fingerprint TEXT NOT NULL,
    check_id TEXT NOT NULL,
    action_type TEXT NOT NULL,

    -- Deterministic execution payload (action-specific fields)
    action_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    dry_run BOOLEAN NOT NULL DEFAULT TRUE,

    -- Approval/execution state
    status TEXT NOT NULL DEFAULT 'pending_approval',
    reason TEXT NULL,

    -- Actor metadata
    requested_by TEXT NULL,
    approved_by TEXT NULL,
    rejected_by TEXT NULL,

    -- Timestamps
    requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    approved_at TIMESTAMPTZ NULL,
    rejected_at TIMESTAMPTZ NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Optimistic concurrency
    version INTEGER NOT NULL DEFAULT 1,

    PRIMARY KEY (tenant_id, workspace, action_id),

    CHECK (
        status IN (
            'pending_approval',
            'approved',
            'rejected',
            'queued',
            'running',
            'completed',
            'failed',
            'cancelled'
        )
    )
);

CREATE INDEX IF NOT EXISTS idx_remediation_actions_scope_status_updated
    ON remediation_actions (tenant_id, workspace, status, updated_at DESC);

CREATE INDEX IF NOT EXISTS idx_remediation_actions_scope_fingerprint
    ON remediation_actions (tenant_id, workspace, fingerprint);

CREATE INDEX IF NOT EXISTS idx_remediation_actions_scope_check
    ON remediation_actions (tenant_id, workspace, check_id);

CREATE INDEX IF NOT EXISTS idx_remediation_actions_scope_action_type
    ON remediation_actions (tenant_id, workspace, action_type);
