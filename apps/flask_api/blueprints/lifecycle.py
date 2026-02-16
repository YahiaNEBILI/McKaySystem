"""Lifecycle Blueprint.

Provides finding lifecycle action endpoints (ignore, resolve, snooze).
"""

import json
from datetime import UTC, datetime
from typing import Any

from flask import Blueprint, request

from apps.backend.db import db_conn, execute_conn, fetch_one_dict_conn
from apps.flask_api.utils import (
    _err,
    _ok,
    _parse_iso8601_dt,
    _require_scope_from_json,
)

# Create the blueprint
lifecycle_bp = Blueprint("lifecycle", __name__)


def _log(level: str, event: str, fields: dict[str, Any]) -> None:
    """Emit a log message."""
    import logging
    logger = logging.getLogger("lifecycle")
    getattr(logger, level.lower())(f"{event}: {fields}")


def _iso_z(dt: datetime | None) -> str | None:
    """Format datetime as ISO-8601 with Z suffix."""
    if dt is None:
        return None
    return dt.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _audit_log_event(
    conn: Any,
    *,
    tenant_id: str,
    workspace: str,
    entity_type: str,
    entity_id: str,
    fingerprint: str | None,
    event_type: str,
    event_category: str,
    previous_value: dict[str, Any] | None,
    new_value: dict[str, Any] | None,
    actor_id: str | None,
    actor_email: str | None,
    actor_name: str | None,
    source: str,
    run_id: str | None = None,
    correlation_id: str | None = None,
) -> None:
    """Best-effort append-only write to audit_log."""
    try:
        ip_address = request.headers.get("X-Forwarded-For", request.remote_addr)
        user_agent = request.headers.get("User-Agent", "")
    except RuntimeError:
        ip_address = None
        user_agent = ""

    params = (
        tenant_id,
        workspace,
        entity_type,
        entity_id,
        fingerprint,
        event_type,
        event_category,
        (json.dumps(previous_value, separators=(",", ":")) if previous_value is not None else None),
        (json.dumps(new_value, separators=(",", ":")) if new_value is not None else None),
        actor_id,
        actor_email,
        actor_name,
        source,
        ip_address,
        user_agent,
        run_id,
        correlation_id,
    )

    try:
        with conn.cursor() as cur:
            cur.execute("SAVEPOINT mckay_audit_log_1")
            cur.execute(
                """
                INSERT INTO audit_log
                  (tenant_id, workspace, entity_type, entity_id, fingerprint,
                   event_type, event_category, previous_value, new_value,
                   actor_id, actor_email, actor_name, source, ip_address, user_agent,
                   run_id, correlation_id, created_at)
                VALUES
                  (%s,%s,%s,%s,%s,%s,%s,%s::jsonb,%s::jsonb,%s,%s,%s,%s,%s,%s,%s,%s, now())
                """,
                params,
            )
            cur.execute("RELEASE SAVEPOINT mckay_audit_log_1")
            return
    except Exception:
        try:
            with conn.cursor() as cur:
                cur.execute("ROLLBACK TO SAVEPOINT mckay_audit_log_1")
        except Exception:
            pass
        _log("WARN", "audit_log_db_write_failed", {"tenant_id": tenant_id, "workspace": workspace})


def _audit_lifecycle(
    conn: Any,
    *,
    tenant_id: str,
    workspace: str,
    action: str,
    subject_type: str,
    subject_id: str,
    state: str,
    snooze_until: datetime | None,
    reason: str | None,
    updated_by: str | None,
) -> None:
    """Best-effort lifecycle audit logging."""
    evt = {
        "tenant_id": tenant_id,
        "workspace": workspace,
        "action": action,
        "subject_type": subject_type,
        "subject_id": subject_id,
        "state": state,
        "snooze_until": _iso_z(snooze_until) if snooze_until else None,
        "reason": reason,
        "updated_by": updated_by,
    }
    _log("INFO", "lifecycle_audit", evt)

    # Keep legacy finding_state_audit writes for compatibility while audit_log is primary.
    try:
        with conn.cursor() as cur:
            cur.execute("SAVEPOINT mckay_finding_state_audit_1")
            cur.execute(
                """
                INSERT INTO finding_state_audit
                  (tenant_id, workspace, subject_type, subject_id, action, state, snooze_until, reason, updated_by)
                VALUES
                  (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    tenant_id,
                    workspace,
                    subject_type,
                    subject_id,
                    action,
                    state,
                    snooze_until,
                    reason,
                    updated_by,
                ),
            )
            cur.execute("RELEASE SAVEPOINT mckay_finding_state_audit_1")
    except Exception:
        try:
            with conn.cursor() as cur:
                cur.execute("ROLLBACK TO SAVEPOINT mckay_finding_state_audit_1")
        except Exception:
            pass

    _audit_log_event(
        conn,
        tenant_id=tenant_id,
        workspace=workspace,
        entity_type=subject_type,
        entity_id=subject_id,
        fingerprint=None,
        event_type=f"lifecycle.{action}",
        event_category="lifecycle",
        previous_value=None,
        new_value=evt,
        actor_id=updated_by,
        actor_email=updated_by,
        actor_name=None,
        source="api",
    )


def _upsert_state(
    conn: Any,
    *,
    tenant_id: str,
    workspace: str,
    fingerprint: str,
    state: str,
    snooze_until: datetime | None,
    reason: str | None,
    updated_by: str | None,
) -> None:
    """Upsert finding state."""
    execute_conn(
        conn,
        """
        INSERT INTO finding_state_current (
          tenant_id, workspace, fingerprint, state,
          snooze_until, reason, updated_by, updated_at
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s, now())
        ON CONFLICT (tenant_id, workspace, fingerprint)
        DO UPDATE SET
          state = EXCLUDED.state,
          snooze_until = EXCLUDED.snooze_until,
          reason = EXCLUDED.reason,
          updated_by = EXCLUDED.updated_by,
          updated_at = now(),
          version = finding_state_current.version + 1;
        """,
        (tenant_id, workspace, fingerprint, state, snooze_until, reason, updated_by),
    )


def _upsert_group_state(
    conn: Any,
    *,
    tenant_id: str,
    workspace: str,
    group_key: str,
    state: str,
    snooze_until: datetime | None,
    reason: str | None,
    updated_by: str | None,
) -> None:
    """Upsert finding group state."""
    execute_conn(
        conn,
        """
        INSERT INTO finding_group_state_current
          (tenant_id, workspace, group_key, state, snooze_until, reason, updated_at, updated_by, version)
        VALUES
          (%s, %s, %s, %s, %s, %s, now(), %s, 1)
        ON CONFLICT (tenant_id, workspace, group_key)
        DO UPDATE SET
          state = EXCLUDED.state,
          snooze_until = EXCLUDED.snooze_until,
          reason = EXCLUDED.reason,
          updated_at = now(),
          updated_by = EXCLUDED.updated_by,
          version = finding_group_state_current.version + 1
        """,
        (tenant_id, workspace, group_key, state, snooze_until, reason, updated_by),
    )


def _finding_exists(conn: Any, *, tenant_id: str, workspace: str, fingerprint: str) -> bool:
    """Check if finding exists."""
    row = fetch_one_dict_conn(
        conn,
        """
        SELECT 1 AS ok
        FROM finding_latest
        WHERE tenant_id = %s AND workspace = %s AND fingerprint = %s
        LIMIT 1
        """,
        (tenant_id, workspace, fingerprint),
    )
    return bool(row and row.get("ok") == 1)


# Group lifecycle endpoints
@lifecycle_bp.route("/api/lifecycle/group/ignore", methods=["POST"])
def api_lifecycle_group_ignore() -> Any:
    """Ignore all findings in a group."""
    try:
        payload = request.get_json(force=True, silent=False) or {}
        tenant_id, workspace = _require_scope_from_json(payload)
        group_key = str(payload.get("group_key") or "").strip()
        if not group_key:
            raise ValueError("group_key is required")
        reason = payload.get("reason")
        updated_by = payload.get("updated_by")
        with db_conn() as conn:
            _upsert_group_state(
                conn,
                tenant_id=tenant_id,
                workspace=workspace,
                group_key=group_key,
                state="ignored",
                snooze_until=None,
                reason=reason,
                updated_by=updated_by,
            )
            _audit_lifecycle(
                conn,
                tenant_id=tenant_id,
                workspace=workspace,
                action="group_ignore",
                subject_type="group_key",
                subject_id=group_key,
                state="ignored",
                snooze_until=None,
                reason=reason,
                updated_by=updated_by,
            )
            conn.commit()
        return _ok()
    except ValueError as exc:
        return _err("bad_request", str(exc), status=400)


@lifecycle_bp.route("/api/lifecycle/group/resolve", methods=["POST"])
def api_lifecycle_group_resolve() -> Any:
    """Resolve all findings in a group."""
    try:
        payload = request.get_json(force=True, silent=False) or {}
        tenant_id, workspace = _require_scope_from_json(payload)
        group_key = str(payload.get("group_key") or "").strip()
        if not group_key:
            raise ValueError("group_key is required")
        reason = payload.get("reason")
        updated_by = payload.get("updated_by")
        with db_conn() as conn:
            _upsert_group_state(
                conn,
                tenant_id=tenant_id,
                workspace=workspace,
                group_key=group_key,
                state="resolved",
                snooze_until=None,
                reason=reason,
                updated_by=updated_by,
            )
            _audit_lifecycle(
                conn,
                tenant_id=tenant_id,
                workspace=workspace,
                action="group_resolve",
                subject_type="group_key",
                subject_id=group_key,
                state="resolved",
                snooze_until=None,
                reason=reason,
                updated_by=updated_by,
            )
            conn.commit()
        return _ok()
    except ValueError as exc:
        return _err("bad_request", str(exc), status=400)


@lifecycle_bp.route("/api/lifecycle/group/snooze", methods=["POST"])
def api_lifecycle_group_snooze() -> Any:
    """Snooze all findings in a group."""
    try:
        payload = request.get_json(force=True, silent=False) or {}
        tenant_id, workspace = _require_scope_from_json(payload)
        group_key = str(payload.get("group_key") or "").strip()
        if not group_key:
            raise ValueError("group_key is required")
        snooze_until_raw = payload.get("snooze_until")
        if not snooze_until_raw:
            raise ValueError("snooze_until is required (ISO 8601 timestamp)")
        snooze_until = _parse_iso8601_dt(snooze_until_raw, field_name="snooze_until")
        reason = payload.get("reason")
        updated_by = payload.get("updated_by")
        with db_conn() as conn:
            _upsert_group_state(
                conn,
                tenant_id=tenant_id,
                workspace=workspace,
                group_key=group_key,
                state="snoozed",
                snooze_until=snooze_until,
                reason=reason,
                updated_by=updated_by,
            )
            _audit_lifecycle(
                conn,
                tenant_id=tenant_id,
                workspace=workspace,
                action="group_snooze",
                subject_type="group_key",
                subject_id=group_key,
                state="snoozed",
                snooze_until=snooze_until,
                reason=reason,
                updated_by=updated_by,
            )
            conn.commit()
        return _ok()
    except ValueError as exc:
        return _err("bad_request", str(exc), status=400)


# Individual finding lifecycle endpoints
@lifecycle_bp.route("/api/lifecycle/ignore", methods=["POST"])
def api_lifecycle_ignore() -> Any:
    """Ignore a single finding."""
    try:
        payload = request.get_json(force=True, silent=False) or {}
        tenant_id, workspace = _require_scope_from_json(payload)
        fingerprint = str(payload.get("fingerprint") or "")
        if not fingerprint.strip():
            raise ValueError("fingerprint is required")
        reason = payload.get("reason")
        updated_by = payload.get("updated_by")
        with db_conn() as conn:
            if hasattr(conn, "cursor") and not _finding_exists(
                conn, tenant_id=tenant_id, workspace=workspace, fingerprint=fingerprint
            ):
                return _err("not_found", "finding not found", status=404)
            _upsert_state(
                conn,
                tenant_id=tenant_id,
                workspace=workspace,
                fingerprint=fingerprint,
                state="ignored",
                snooze_until=None,
                reason=reason,
                updated_by=updated_by,
            )
            _audit_lifecycle(
                conn,
                tenant_id=tenant_id,
                workspace=workspace,
                action="ignore",
                subject_type="finding",
                subject_id=fingerprint,
                state="ignored",
                snooze_until=None,
                reason=reason,
                updated_by=updated_by,
            )
            conn.commit()
        return _ok()
    except ValueError as exc:
        return _err("bad_request", str(exc), status=400)


@lifecycle_bp.route("/api/lifecycle/resolve", methods=["POST"])
def api_lifecycle_resolve() -> Any:
    """Resolve a single finding."""
    try:
        payload = request.get_json(force=True, silent=False) or {}
        tenant_id, workspace = _require_scope_from_json(payload)
        fingerprint = str(payload.get("fingerprint") or "")
        if not fingerprint.strip():
            raise ValueError("fingerprint is required")
        reason = payload.get("reason")
        updated_by = payload.get("updated_by")
        with db_conn() as conn:
            if hasattr(conn, "cursor") and not _finding_exists(
                conn, tenant_id=tenant_id, workspace=workspace, fingerprint=fingerprint
            ):
                return _err("not_found", "finding not found", status=404)
            _upsert_state(
                conn,
                tenant_id=tenant_id,
                workspace=workspace,
                fingerprint=fingerprint,
                state="resolved",
                snooze_until=None,
                reason=reason,
                updated_by=updated_by,
            )
            _audit_lifecycle(
                conn,
                tenant_id=tenant_id,
                workspace=workspace,
                action="resolve",
                subject_type="finding",
                subject_id=fingerprint,
                state="resolved",
                snooze_until=None,
                reason=reason,
                updated_by=updated_by,
            )
            conn.commit()
        return _ok()
    except ValueError as exc:
        return _err("bad_request", str(exc), status=400)


@lifecycle_bp.route("/api/lifecycle/snooze", methods=["POST"])
def api_lifecycle_snooze() -> Any:
    """Snooze a single finding."""
    try:
        payload = request.get_json(force=True, silent=False) or {}
        tenant_id, workspace = _require_scope_from_json(payload)
        fingerprint = str(payload.get("fingerprint") or "")
        if not fingerprint.strip():
            raise ValueError("fingerprint is required")
        snooze_until_raw = payload.get("snooze_until")
        if not snooze_until_raw:
            raise ValueError("snooze_until is required (ISO 8601 timestamp)")
        snooze_until = _parse_iso8601_dt(snooze_until_raw, field_name="snooze_until")
        reason = payload.get("reason")
        updated_by = payload.get("updated_by")
        with db_conn() as conn:
            if hasattr(conn, "cursor") and not _finding_exists(
                conn, tenant_id=tenant_id, workspace=workspace, fingerprint=fingerprint
            ):
                return _err("not_found", "finding not found", status=404)
            _upsert_state(
                conn,
                tenant_id=tenant_id,
                workspace=workspace,
                fingerprint=fingerprint,
                state="snoozed",
                snooze_until=snooze_until,
                reason=reason,
                updated_by=updated_by,
            )
            _audit_lifecycle(
                conn,
                tenant_id=tenant_id,
                workspace=workspace,
                action="snooze",
                subject_type="finding",
                subject_id=fingerprint,
                state="snoozed",
                snooze_until=snooze_until,
                reason=reason,
                updated_by=updated_by,
            )
            conn.commit()
        return _ok()
    except ValueError as exc:
        return _err("bad_request", str(exc), status=400)
