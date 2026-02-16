-- Migration 020: Closed-loop remediation impact tracking
-- Stores deterministic post-execution impact snapshots per remediation action.

CREATE TABLE IF NOT EXISTS remediation_impact (
    tenant_id TEXT NOT NULL,
    workspace TEXT NOT NULL,
    action_id TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    check_id TEXT NOT NULL,
    action_type TEXT NOT NULL,
    action_status TEXT NOT NULL,
    verification_status TEXT NOT NULL,
    baseline_estimated_monthly_savings DOUBLE PRECISION NOT NULL DEFAULT 0,
    current_estimated_monthly_savings DOUBLE PRECISION NULL,
    realized_monthly_savings DOUBLE PRECISION NOT NULL DEFAULT 0,
    realization_rate_pct DOUBLE PRECISION NULL,
    latest_run_id TEXT NULL,
    latest_run_ts TIMESTAMPTZ NULL,
    present_in_latest BOOLEAN NULL,
    finalized_at TIMESTAMPTZ NOT NULL,
    computed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    version INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id, workspace, action_id),
    CHECK (
        action_status IN (
            'pending_approval',
            'approved',
            'rejected',
            'queued',
            'running',
            'completed',
            'failed',
            'cancelled'
        )
    ),
    CHECK (
        verification_status IN (
            'pending_post_run',
            'verified_resolved',
            'verified_persistent',
            'execution_failed'
        )
    )
);

CREATE INDEX IF NOT EXISTS idx_remediation_impact_scope_computed
    ON remediation_impact (tenant_id, workspace, computed_at DESC);

CREATE INDEX IF NOT EXISTS idx_remediation_impact_scope_verification
    ON remediation_impact (tenant_id, workspace, verification_status, computed_at DESC);

CREATE INDEX IF NOT EXISTS idx_remediation_impact_scope_fingerprint
    ON remediation_impact (tenant_id, workspace, fingerprint);

INSERT INTO schema_migrations (version) VALUES ('020') ON CONFLICT (version) DO NOTHING;
