-- Migration 011: Governance Layer - Updated finding_current View
-- Adds governance fields to the primary read model view

-- Drop existing view if exists (safe due to CREATE OR REPLACE)
DROP VIEW IF EXISTS finding_current;

-- Create updated view with governance fields
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

    -- Existing state logic (unchanged)
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
    END AS effective_state,

    -- NEW: Governance fields
    fg.first_detected_at,
    fg.first_opened_at,
    fg.owner_id,
    fg.owner_email,
    fg.owner_name,
    fg.team_id,
    fg.sla_deadline,
    fg.sla_breached_at,
    fg.sla_extended_count,
    
    -- Computed: aging (days)
    CASE 
        WHEN fg.first_opened_at IS NOT NULL 
        THEN EXTRACT(DAY FROM now() - fg.first_opened_at)::INTEGER 
        ELSE NULL 
    END AS age_days_open,
    
    CASE 
        WHEN fg.first_detected_at IS NOT NULL 
        THEN EXTRACT(DAY FROM now() - fg.first_detected_at)::INTEGER 
        ELSE NULL 
    END AS age_days_detected,
    
    -- Computed: SLA status
    CASE
        WHEN fg.sla_breached_at IS NOT NULL THEN 'breached'
        WHEN fg.sla_deadline IS NOT NULL AND fg.sla_deadline < now() THEN 'breaching'
        WHEN fg.sla_deadline IS NOT NULL THEN 'active'
        ELSE 'no_sla'
    END AS sla_status,

    -- Computed: days until SLA breach (negative = breached)
    CASE
        WHEN fg.sla_deadline IS NOT NULL 
        THEN EXTRACT(DAY FROM fg.sla_deadline - now())::INTEGER
        ELSE NULL
    END AS sla_days_remaining

FROM finding_latest fl
LEFT JOIN finding_group_state_current gs
    ON gs.tenant_id = fl.tenant_id
    AND gs.workspace = fl.workspace
    AND gs.group_key = fl.group_key

LEFT JOIN finding_state_current fs
    ON fs.tenant_id = fl.tenant_id
    AND fs.workspace = fl.workspace
    AND fs.fingerprint = fl.fingerprint

LEFT JOIN finding_governance fg
    ON fg.tenant_id = fl.tenant_id
    AND fg.workspace = fl.workspace
    AND fg.fingerprint = fl.fingerprint;

-- Record migration
INSERT INTO schema_migrations (version) VALUES ('011') ON CONFLICT (version) DO NOTHING;
