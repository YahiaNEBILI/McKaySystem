-- Migration 013: Governance Layer hardening and SLA pause support
-- Adds integrity constraints and governance read-model improvements.

-- Ensure hierarchical teams reference is enforced in-DB.
ALTER TABLE teams
    DROP CONSTRAINT IF EXISTS teams_parent_team_id_fkey;

ALTER TABLE teams
    ADD CONSTRAINT teams_parent_team_id_fkey
    FOREIGN KEY (tenant_id, workspace, parent_team_id)
    REFERENCES teams (tenant_id, workspace, team_id)
    ON DELETE SET NULL
    NOT VALID;

-- Enforce positive SLA day values.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'ck_sla_policy_category_sla_days_positive'
    ) THEN
        ALTER TABLE sla_policy_category
            ADD CONSTRAINT ck_sla_policy_category_sla_days_positive
            CHECK (sla_days > 0)
            NOT VALID;
    END IF;
END;
$$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'ck_sla_policy_check_override_sla_days_positive'
    ) THEN
        ALTER TABLE sla_policy_check_override
            ADD CONSTRAINT ck_sla_policy_check_override_sla_days_positive
            CHECK (sla_days > 0)
            NOT VALID;
    END IF;
END;
$$;

-- Add SLA pause accounting fields required for pause/resume math.
ALTER TABLE finding_governance
    ADD COLUMN IF NOT EXISTS sla_paused_at TIMESTAMPTZ NULL,
    ADD COLUMN IF NOT EXISTS sla_total_paused_seconds BIGINT NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS idx_finding_governance_tenant_workspace_sla_paused
    ON finding_governance (tenant_id, workspace, sla_paused_at)
    WHERE sla_paused_at IS NOT NULL;

-- Enforce append-only semantics for audit_log (no UPDATE/DELETE).
CREATE OR REPLACE FUNCTION prevent_audit_mutation()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'Audit log is append-only';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS audit_delete_prevention ON audit_log;
DROP TRIGGER IF EXISTS audit_no_update ON audit_log;
DROP TRIGGER IF EXISTS audit_no_delete ON audit_log;

CREATE TRIGGER audit_no_update
BEFORE UPDATE ON audit_log
FOR EACH ROW
EXECUTE FUNCTION prevent_audit_mutation();

CREATE TRIGGER audit_no_delete
BEFORE DELETE ON audit_log
FOR EACH ROW
EXECUTE FUNCTION prevent_audit_mutation();

DROP FUNCTION IF EXISTS prevent_audit_delete();

-- Rebuild finding_current to expose governance pause fields and stronger SLA states.
DROP VIEW IF EXISTS finding_current;

CREATE OR REPLACE VIEW finding_current AS
WITH state_base AS (
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
        AND fs.fingerprint = fl.fingerprint
)
SELECT
    sb.tenant_id,
    sb.workspace,
    sb.fingerprint,
    sb.run_id,
    sb.check_id,
    sb.service,
    sb.severity,
    sb.title,
    sb.estimated_monthly_savings,
    sb.region,
    sb.account_id,
    sb.category,
    sb.group_key,
    sb.detected_at,
    sb.payload,
    sb.state,
    sb.snooze_until,
    sb.reason,
    sb.effective_state,
    fg.first_detected_at,
    fg.first_opened_at,
    fg.owner_id,
    fg.owner_email,
    fg.owner_name,
    fg.team_id,
    fg.sla_deadline,
    fg.sla_paused_at,
    fg.sla_total_paused_seconds,
    fg.sla_breached_at,
    fg.sla_extended_count,
    CASE
        WHEN fg.first_opened_at IS NOT NULL THEN EXTRACT(DAY FROM now() - fg.first_opened_at)::INTEGER
        ELSE NULL
    END AS age_days_open,
    CASE
        WHEN fg.first_detected_at IS NOT NULL THEN EXTRACT(DAY FROM now() - fg.first_detected_at)::INTEGER
        ELSE NULL
    END AS age_days_detected,
    CASE
        WHEN fg.sla_deadline IS NULL THEN 'none'
        WHEN fg.sla_breached_at IS NOT NULL THEN 'breached'
        WHEN sb.effective_state IN ('resolved', 'ignored') THEN 'closed'
        WHEN sb.effective_state = 'snoozed' AND sb.snooze_until > now() THEN 'paused'
        WHEN fg.sla_deadline < now() THEN 'breached'
        WHEN fg.sla_deadline < now() + interval '3 days' THEN 'breaching_soon'
        ELSE 'active'
    END AS sla_status,
    CASE
        WHEN fg.sla_deadline IS NOT NULL THEN EXTRACT(DAY FROM fg.sla_deadline - now())::INTEGER
        ELSE NULL
    END AS sla_days_remaining
FROM state_base sb
LEFT JOIN finding_governance fg
    ON fg.tenant_id = sb.tenant_id
    AND fg.workspace = sb.workspace
    AND fg.fingerprint = sb.fingerprint;

-- Dedicated SLA status projection for governance APIs/dashboards.
CREATE OR REPLACE VIEW finding_sla_status AS
SELECT
    tenant_id,
    workspace,
    fingerprint,
    effective_state,
    snooze_until,
    first_detected_at,
    first_opened_at,
    owner_id,
    owner_email,
    owner_name,
    team_id,
    sla_deadline,
    sla_paused_at,
    sla_total_paused_seconds,
    sla_breached_at,
    sla_extended_count,
    sla_status,
    sla_days_remaining,
    age_days_open,
    age_days_detected
FROM finding_current;

-- Record migration
INSERT INTO schema_migrations (version) VALUES ('013') ON CONFLICT (version) DO NOTHING;
