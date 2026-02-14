-- Migration 015: Governance SLA manual extension support
-- Persists extension duration so deadline recalculation remains stable across state changes.

ALTER TABLE finding_governance
    ADD COLUMN IF NOT EXISTS sla_extension_seconds BIGINT NOT NULL DEFAULT 0;


CREATE OR REPLACE FUNCTION governance_sync_finding_sla(
    p_tenant_id TEXT,
    p_workspace TEXT,
    p_fingerprint TEXT,
    p_event_ts TIMESTAMPTZ
)
RETURNS VOID
LANGUAGE plpgsql
AS $$
DECLARE
    v_effective_state TEXT;
    v_check_id TEXT;
    v_category TEXT;
    v_detected_at TIMESTAMPTZ;
    v_sla_days INTEGER;

    v_first_opened_at TIMESTAMPTZ;
    v_sla_paused_at TIMESTAMPTZ;
    v_sla_total_paused_seconds BIGINT;
    v_sla_extension_seconds BIGINT;
    v_sla_deadline TIMESTAMPTZ;
    v_sla_breached_at TIMESTAMPTZ;

    v_new_first_opened_at TIMESTAMPTZ;
    v_new_sla_paused_at TIMESTAMPTZ;
    v_new_sla_total_paused_seconds BIGINT;
    v_new_sla_extension_seconds BIGINT;
    v_new_sla_deadline TIMESTAMPTZ;
    v_new_sla_breached_at TIMESTAMPTZ;
    v_pause_delta BIGINT;
BEGIN
    SELECT
        fc.effective_state,
        fc.check_id,
        fc.category,
        fc.detected_at
    INTO
        v_effective_state,
        v_check_id,
        v_category,
        v_detected_at
    FROM finding_current fc
    WHERE fc.tenant_id = p_tenant_id
      AND fc.workspace = p_workspace
      AND fc.fingerprint = p_fingerprint;

    IF NOT FOUND THEN
        RETURN;
    END IF;

    v_sla_days := governance_resolve_sla_days(
        p_tenant_id,
        p_workspace,
        v_check_id,
        v_category
    );

    INSERT INTO finding_governance
      (
        tenant_id,
        workspace,
        fingerprint,
        first_detected_at,
        first_opened_at,
        sla_deadline,
        created_at,
        updated_at
      )
    VALUES
      (
        p_tenant_id,
        p_workspace,
        p_fingerprint,
        COALESCE(v_detected_at, p_event_ts),
        CASE WHEN v_effective_state = 'open' THEN p_event_ts ELSE NULL END,
        CASE
            WHEN v_effective_state = 'open' AND v_sla_days IS NOT NULL
            THEN p_event_ts + (v_sla_days * INTERVAL '1 day')
            ELSE NULL
        END,
        now(),
        now()
      )
    ON CONFLICT (tenant_id, workspace, fingerprint) DO NOTHING;

    SELECT
        fg.first_opened_at,
        fg.sla_paused_at,
        fg.sla_total_paused_seconds,
        fg.sla_extension_seconds,
        fg.sla_deadline,
        fg.sla_breached_at
    INTO
        v_first_opened_at,
        v_sla_paused_at,
        v_sla_total_paused_seconds,
        v_sla_extension_seconds,
        v_sla_deadline,
        v_sla_breached_at
    FROM finding_governance fg
    WHERE fg.tenant_id = p_tenant_id
      AND fg.workspace = p_workspace
      AND fg.fingerprint = p_fingerprint
    FOR UPDATE;

    IF NOT FOUND THEN
        RETURN;
    END IF;

    v_new_first_opened_at := v_first_opened_at;
    v_new_sla_paused_at := v_sla_paused_at;
    v_new_sla_total_paused_seconds := COALESCE(v_sla_total_paused_seconds, 0);
    v_new_sla_extension_seconds := COALESCE(v_sla_extension_seconds, 0);
    v_new_sla_deadline := v_sla_deadline;
    v_new_sla_breached_at := v_sla_breached_at;

    IF v_effective_state = 'open' AND v_new_first_opened_at IS NULL THEN
        v_new_first_opened_at := p_event_ts;
    END IF;

    IF v_sla_paused_at IS NOT NULL AND v_effective_state IN ('open', 'resolved', 'ignored') THEN
        v_pause_delta := GREATEST(
            0,
            FLOOR(EXTRACT(EPOCH FROM (p_event_ts - v_sla_paused_at)))::BIGINT
        );
        v_new_sla_total_paused_seconds := v_new_sla_total_paused_seconds + v_pause_delta;
        v_new_sla_paused_at := NULL;
    ELSIF v_effective_state = 'snoozed' AND v_sla_paused_at IS NULL THEN
        v_new_sla_paused_at := p_event_ts;
    END IF;

    IF v_new_first_opened_at IS NOT NULL AND v_sla_days IS NOT NULL THEN
        v_new_sla_deadline :=
            v_new_first_opened_at
            + (v_sla_days * INTERVAL '1 day')
            + (v_new_sla_total_paused_seconds * INTERVAL '1 second')
            + (v_new_sla_extension_seconds * INTERVAL '1 second');
    ELSE
        v_new_sla_deadline := NULL;
    END IF;

    IF v_new_sla_deadline IS NULL THEN
        v_new_sla_breached_at := NULL;
    ELSIF v_new_sla_breached_at IS NULL AND v_new_sla_deadline < p_event_ts THEN
        v_new_sla_breached_at := p_event_ts;
    END IF;

    UPDATE finding_governance
    SET
        first_opened_at = v_new_first_opened_at,
        sla_paused_at = v_new_sla_paused_at,
        sla_total_paused_seconds = v_new_sla_total_paused_seconds,
        sla_extension_seconds = v_new_sla_extension_seconds,
        sla_deadline = v_new_sla_deadline,
        sla_breached_at = v_new_sla_breached_at,
        updated_at = now()
    WHERE tenant_id = p_tenant_id
      AND workspace = p_workspace
      AND fingerprint = p_fingerprint;
END;
$$;


DROP VIEW IF EXISTS finding_sla_status;
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
    fg.sla_extension_seconds,
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
    sla_extension_seconds,
    sla_breached_at,
    sla_extended_count,
    sla_status,
    sla_days_remaining,
    age_days_open,
    age_days_detected
FROM finding_current;

INSERT INTO schema_migrations (version) VALUES ('015') ON CONFLICT (version) DO NOTHING;
