-- Migration 010: Governance Layer - Comprehensive Audit Log
-- Creates unified audit_log table (extends existing finding_state_audit)

-- Unified audit log table
CREATE TABLE IF NOT EXISTS audit_log (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    
    -- Core identifiers
    tenant_id TEXT NOT NULL,
    workspace TEXT NOT NULL,
    
    -- Event context
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    fingerprint TEXT NULL,
    
    -- Event details
    event_type TEXT NOT NULL,
    event_category TEXT NOT NULL,
    
    -- Value tracking (JSON)
    previous_value JSONB NULL,
    new_value JSONB NULL,
    
    -- Actor & source
    actor_id TEXT NULL,
    actor_email TEXT NULL,
    actor_name TEXT NULL,
    source TEXT NOT NULL DEFAULT 'system',
    ip_address TEXT NULL,
    user_agent TEXT NULL,
    
    -- Correlation
    run_id TEXT NULL,
    correlation_id TEXT NULL,
    
    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Indexes for audit queries (critical for compliance)
CREATE INDEX IF NOT EXISTS idx_audit_log_tenant_workspace_entity 
    ON audit_log (tenant_id, workspace, entity_type, entity_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_tenant_workspace_created 
    ON audit_log (tenant_id, workspace, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_log_tenant_workspace_fingerprint 
    ON audit_log (tenant_id, workspace, fingerprint) WHERE fingerprint IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_audit_log_tenant_workspace_event_type 
    ON audit_log (tenant_id, workspace, event_type);
CREATE INDEX IF NOT EXISTS idx_audit_log_tenant_workspace_actor 
    ON audit_log (tenant_id, workspace, actor_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_correlation 
    ON audit_log (tenant_id, workspace, correlation_id);

-- Prevent accidental deletion (append-only enforcement)
CREATE OR REPLACE FUNCTION prevent_audit_delete()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'Audit log entries cannot be deleted';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS audit_delete_prevention ON audit_log;
CREATE TRIGGER audit_delete_prevention
BEFORE DELETE ON audit_log
FOR EACH ROW
EXECUTE FUNCTION prevent_audit_delete();

-- Record migration
INSERT INTO schema_migrations (version) VALUES ('010') ON CONFLICT (version) DO NOTHING;
