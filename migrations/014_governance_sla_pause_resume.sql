-- Migration 014: Governance SLA pause/resume state machine
-- Keeps finding_governance SLA pause accounting aligned with lifecycle state changes.

CREATE OR REPLACE FUNCTION governance_resolve_sla_days(
    p_tenant_id TEXT,
    p_workspace TEXT,
    p_check_id TEXT,
    p_category TEXT
)
RETURNS INTEGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_days INTEGER;
BEGIN
    SELECT o.sla_days
    INTO v_days
    FROM sla_policy_check_override o
    WHERE o.tenant_id = p_tenant_id
      AND o.workspace = p_workspace
      AND o.check_id = p_check_id;
    IF v_days IS NOT NULL THEN
        RETURN v_days;
    END IF;

    SELECT c.sla_days
    INTO v_days
    FROM sla_policy_category c
    WHERE c.tenant_id = p_tenant_id
      AND c.workspace = p_workspace
      AND c.category = p_category;
    IF v_days IS NOT NULL THEN
        RETURN v_days;
    END IF;

    SELECT c.sla_days
    INTO v_days
    FROM sla_policy_category c
    WHERE c.tenant_id = 'default'
      AND c.workspace = 'default'
      AND c.category = p_category;

    RETURN v_days;
END;
$$;


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
    v_sla_deadline TIMESTAMPTZ;
    v_sla_breached_at TIMESTAMPTZ;

    v_new_first_opened_at TIMESTAMPTZ;
    v_new_sla_paused_at TIMESTAMPTZ;
    v_new_sla_total_paused_seconds BIGINT;
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
        fg.sla_deadline,
        fg.sla_breached_at
    INTO
        v_first_opened_at,
        v_sla_paused_at,
        v_sla_total_paused_seconds,
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
            + (v_new_sla_total_paused_seconds * INTERVAL '1 second');
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
        sla_deadline = v_new_sla_deadline,
        sla_breached_at = v_new_sla_breached_at,
        updated_at = now()
    WHERE tenant_id = p_tenant_id
      AND workspace = p_workspace
      AND fingerprint = p_fingerprint;
END;
$$;


CREATE OR REPLACE FUNCTION trg_sync_finding_sla_on_finding_state()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    PERFORM governance_sync_finding_sla(
        NEW.tenant_id,
        NEW.workspace,
        NEW.fingerprint,
        now()
    );
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_sync_finding_sla_on_finding_state ON finding_state_current;
CREATE TRIGGER trg_sync_finding_sla_on_finding_state
AFTER INSERT OR UPDATE OF state, snooze_until
ON finding_state_current
FOR EACH ROW
EXECUTE FUNCTION trg_sync_finding_sla_on_finding_state();


CREATE OR REPLACE FUNCTION trg_sync_finding_sla_on_group_state()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    r RECORD;
BEGIN
    FOR r IN
        SELECT fl.fingerprint
        FROM finding_latest fl
        WHERE fl.tenant_id = NEW.tenant_id
          AND fl.workspace = NEW.workspace
          AND fl.group_key = NEW.group_key
    LOOP
        PERFORM governance_sync_finding_sla(
            NEW.tenant_id,
            NEW.workspace,
            r.fingerprint,
            now()
        );
    END LOOP;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_sync_finding_sla_on_group_state ON finding_group_state_current;
CREATE TRIGGER trg_sync_finding_sla_on_group_state
AFTER INSERT OR UPDATE OF state, snooze_until
ON finding_group_state_current
FOR EACH ROW
EXECUTE FUNCTION trg_sync_finding_sla_on_group_state();

-- Best-effort backfill for currently visible findings.
DO $$
DECLARE
    r RECORD;
BEGIN
    FOR r IN
        SELECT fc.tenant_id, fc.workspace, fc.fingerprint
        FROM finding_current fc
    LOOP
        PERFORM governance_sync_finding_sla(
            r.tenant_id,
            r.workspace,
            r.fingerprint,
            now()
        );
    END LOOP;
END;
$$;

-- Record migration
INSERT INTO schema_migrations (version) VALUES ('014') ON CONFLICT (version) DO NOTHING;
