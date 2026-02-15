"""Run state machine helpers for ingestion workflows.

This module centralizes:
- atomic state transitions on ``runs``
- append-only run events in ``run_events``
- run-scoped lock acquisition with TTL in ``run_locks``
"""

from __future__ import annotations

import os
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Mapping, Optional


STATE_RUNNING = "running"
STATE_READY = "ready"
STATE_FAILED = "failed"


@dataclass(frozen=True)
class RunLock:
    """Lock token and expiry returned by lock acquisition."""

    token: str
    expires_at: datetime


@dataclass(frozen=True)
class RunRecoveryStats:
    """Summary of stale-run recovery in one tenant/workspace scope."""

    expired_locks_reaped: int
    stale_runs_failed: int
    recovered_run_ids: tuple[str, ...]


def default_owner(prefix: str) -> str:
    """Build a deterministic lock owner id for this process."""
    return f"{prefix}:{os.getpid()}"


def _event_payload_json(payload: Optional[Mapping[str, Any]]) -> Optional[str]:
    """Serialize event payload to JSON string for JSONB insertion."""
    if payload is None:
        return None
    import json

    return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))


def append_run_event(
    conn: Any,
    *,
    tenant_id: str,
    workspace: str,
    run_id: str,
    event_type: str,
    actor: str,
    from_state: Optional[str] = None,
    to_state: Optional[str] = None,
    payload: Optional[Mapping[str, Any]] = None,
) -> None:
    """Append a run event (best effort inside caller transaction)."""
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO run_events
              (tenant_id, workspace, run_id, event_type, actor, from_state, to_state, payload)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s::jsonb)
            """,
            (
                tenant_id,
                workspace,
                run_id,
                event_type,
                actor,
                from_state,
                to_state,
                _event_payload_json(payload),
            ),
        )


def acquire_run_lock(
    conn: Any,
    *,
    tenant_id: str,
    workspace: str,
    run_id: str,
    owner: str,
    ttl_seconds: int,
) -> Optional[RunLock]:
    """Acquire/refresh a run lock if free or expired.

    Returns ``None`` when another non-expired owner already holds the lock.
    """
    token = uuid.uuid4().hex
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO run_locks
              (tenant_id, workspace, run_id, lock_owner, lock_token, acquired_at, expires_at, updated_at)
            VALUES
              (%s, %s, %s, %s, %s, now(), now() + make_interval(secs => %s), now())
            ON CONFLICT (tenant_id, workspace, run_id) DO UPDATE SET
              lock_owner = EXCLUDED.lock_owner,
              lock_token = EXCLUDED.lock_token,
              acquired_at = now(),
              expires_at = now() + make_interval(secs => %s),
              updated_at = now()
            WHERE run_locks.expires_at <= now()
               OR run_locks.lock_owner = EXCLUDED.lock_owner
            RETURNING lock_token, expires_at
            """,
            (
                tenant_id,
                workspace,
                run_id,
                owner,
                token,
                int(ttl_seconds),
                int(ttl_seconds),
            ),
        )
        row = cur.fetchone()
    if not row:
        return None
    return RunLock(token=str(row[0]), expires_at=row[1])


def release_run_lock(
    conn: Any,
    *,
    tenant_id: str,
    workspace: str,
    run_id: str,
    lock_token: str,
) -> bool:
    """Release a run lock only when token matches."""
    with conn.cursor() as cur:
        cur.execute(
            """
            DELETE FROM run_locks
            WHERE tenant_id=%s
              AND workspace=%s
              AND run_id=%s
              AND lock_token=%s
            """,
            (tenant_id, workspace, run_id, lock_token),
        )
        return int(cur.rowcount or 0) > 0


def begin_run_running(
    conn: Any,
    *,
    tenant_id: str,
    workspace: str,
    run_id: str,
    run_ts: datetime,
    artifact_prefix: str,
    engine_version: Optional[str],
    pricing_version: Optional[str],
    pricing_source: Optional[str],
    raw_present: bool,
    correlated_present: bool,
    enriched_present: bool,
    actor: str,
) -> str:
    """Transition a run to ``running`` atomically (or keep ``ready``)."""
    previous_status: Optional[str]
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT status
            FROM runs
            WHERE tenant_id=%s AND workspace=%s AND run_id=%s
            FOR UPDATE
            """,
            (tenant_id, workspace, run_id),
        )
        row = cur.fetchone()
        previous_status = str(row[0]) if row and row[0] else None

        if previous_status == STATE_READY:
            return STATE_READY

        if previous_status is None:
            cur.execute(
                """
                INSERT INTO runs
                  (tenant_id, workspace, run_id, run_ts, status, artifact_prefix, ingested_at, engine_version,
                   pricing_version, pricing_source,
                   raw_present, correlated_present, enriched_present)
                VALUES
                  (%s, %s, %s, %s, %s, %s, NULL, %s, %s, %s, %s, %s, %s)
                """,
                (
                    tenant_id,
                    workspace,
                    run_id,
                    run_ts,
                    STATE_RUNNING,
                    artifact_prefix,
                    engine_version,
                    pricing_version,
                    pricing_source,
                    bool(raw_present),
                    bool(correlated_present),
                    bool(enriched_present),
                ),
            )
        else:
            cur.execute(
                """
                UPDATE runs
                SET run_ts=%s,
                    status=%s,
                    artifact_prefix=%s,
                    engine_version=%s,
                    pricing_version=%s,
                    pricing_source=%s,
                    raw_present=%s,
                    correlated_present=%s,
                    enriched_present=%s,
                    ingested_at=NULL
                WHERE tenant_id=%s AND workspace=%s AND run_id=%s
                """,
                (
                    run_ts,
                    STATE_RUNNING,
                    artifact_prefix,
                    engine_version,
                    pricing_version,
                    pricing_source,
                    bool(raw_present),
                    bool(correlated_present),
                    bool(enriched_present),
                    tenant_id,
                    workspace,
                    run_id,
                ),
            )

    append_run_event(
        conn,
        tenant_id=tenant_id,
        workspace=workspace,
        run_id=run_id,
        event_type="run.state.changed",
        actor=actor,
        from_state=previous_status,
        to_state=STATE_RUNNING,
        payload=None,
    )
    return STATE_RUNNING


def transition_run_to_ready(
    conn: Any,
    *,
    tenant_id: str,
    workspace: str,
    run_id: str,
    actor: str,
    raw_present: bool,
    correlated_present: bool,
    enriched_present: bool,
) -> None:
    """Atomically transition ``running -> ready``."""
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE runs
            SET status=%s,
                ingested_at=now(),
                raw_present=%s,
                correlated_present=%s,
                enriched_present=%s
            WHERE tenant_id=%s
              AND workspace=%s
              AND run_id=%s
              AND status=%s
            """,
            (
                STATE_READY,
                bool(raw_present),
                bool(correlated_present),
                bool(enriched_present),
                tenant_id,
                workspace,
                run_id,
                STATE_RUNNING,
            ),
        )
        if int(cur.rowcount or 0) != 1:
            raise RuntimeError(
                "run_state_transition_failed: expected running -> ready for "
                f"{tenant_id}/{workspace}/{run_id}"
            )

    append_run_event(
        conn,
        tenant_id=tenant_id,
        workspace=workspace,
        run_id=run_id,
        event_type="run.state.changed",
        actor=actor,
        from_state=STATE_RUNNING,
        to_state=STATE_READY,
        payload=None,
    )


def transition_run_to_failed(
    conn: Any,
    *,
    tenant_id: str,
    workspace: str,
    run_id: str,
    run_ts: datetime,
    artifact_prefix: str,
    engine_version: Optional[str],
    pricing_version: Optional[str],
    pricing_source: Optional[str],
    actor: str,
    reason: str,
) -> None:
    """Upsert a run and transition it to ``failed`` with an event."""
    previous_status: Optional[str]
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT status
            FROM runs
            WHERE tenant_id=%s AND workspace=%s AND run_id=%s
            FOR UPDATE
            """,
            (tenant_id, workspace, run_id),
        )
        row = cur.fetchone()
        previous_status = str(row[0]) if row and row[0] else None

        if previous_status is None:
            cur.execute(
                """
                INSERT INTO runs
                  (tenant_id, workspace, run_id, run_ts, status, artifact_prefix, ingested_at, engine_version,
                   pricing_version, pricing_source,
                   raw_present, correlated_present, enriched_present)
                VALUES
                  (%s, %s, %s, %s, %s, %s, NULL, %s, %s, %s, FALSE, FALSE, FALSE)
                """,
                (
                    tenant_id,
                    workspace,
                    run_id,
                    run_ts,
                    STATE_FAILED,
                    artifact_prefix,
                    engine_version,
                    pricing_version,
                    pricing_source,
                ),
            )
        else:
            cur.execute(
                """
                UPDATE runs
                SET status=%s,
                    pricing_version=COALESCE(%s, pricing_version),
                    pricing_source=COALESCE(%s, pricing_source)
                WHERE tenant_id=%s AND workspace=%s AND run_id=%s
                """,
                (STATE_FAILED, pricing_version, pricing_source, tenant_id, workspace, run_id),
            )

    append_run_event(
        conn,
        tenant_id=tenant_id,
        workspace=workspace,
        run_id=run_id,
        event_type="run.state.changed",
        actor=actor,
        from_state=previous_status,
        to_state=STATE_FAILED,
        payload={"reason": reason[:2000]},
    )


def recover_stale_runs_for_scope(
    conn: Any,
    *,
    tenant_id: str,
    workspace: str,
    actor: str,
    limit: int = 200,
) -> RunRecoveryStats:
    """Recover stale orchestration state for one tenant/workspace.

    Recovery policy:
    - remove expired locks (TTL enforcement)
    - transition ``running`` runs to ``failed`` when no active lock exists
    """
    if int(limit) <= 0:
        raise ValueError("limit must be >= 1")
    max_rows = int(limit)

    expired_rows: list[tuple[str, str, datetime]] = []
    with conn.cursor() as cur:
        cur.execute(
            """
            WITH expired AS (
              SELECT tenant_id, workspace, run_id, lock_owner, expires_at
              FROM run_locks
              WHERE tenant_id=%s
                AND workspace=%s
                AND expires_at <= now()
              ORDER BY expires_at ASC, run_id ASC
              LIMIT %s
              FOR UPDATE SKIP LOCKED
            )
            DELETE FROM run_locks l
            USING expired
            WHERE l.tenant_id = expired.tenant_id
              AND l.workspace = expired.workspace
              AND l.run_id = expired.run_id
            RETURNING expired.run_id, expired.lock_owner, expired.expires_at
            """,
            (tenant_id, workspace, max_rows),
        )
        rows = cur.fetchall() or []
        for row in rows:
            if not row or row[0] is None:
                continue
            expired_rows.append((str(row[0]), str(row[1] or ""), row[2]))

    expired_run_ids = {run_id for run_id, _, _ in expired_rows}
    for run_id, lock_owner, expires_at in expired_rows:
        expires_at_iso = (
            expires_at.isoformat() if hasattr(expires_at, "isoformat") else str(expires_at)
        )
        append_run_event(
            conn,
            tenant_id=tenant_id,
            workspace=workspace,
            run_id=run_id,
            event_type="run.lock.expired",
            actor=actor,
            payload={
                "expired_lock_owner": lock_owner,
                "expired_at": expires_at_iso,
            },
        )

    stale_run_ids: list[str] = []
    with conn.cursor() as cur:
        cur.execute(
            """
            WITH candidates AS (
              SELECT r.tenant_id, r.workspace, r.run_id
              FROM runs r
              LEFT JOIN run_locks l
                ON l.tenant_id = r.tenant_id
               AND l.workspace = r.workspace
               AND l.run_id = r.run_id
               AND l.expires_at > now()
              WHERE r.tenant_id=%s
                AND r.workspace=%s
                AND r.status=%s
                AND l.run_id IS NULL
              ORDER BY r.run_ts ASC, r.run_id ASC
              LIMIT %s
              FOR UPDATE OF r SKIP LOCKED
            )
            UPDATE runs r
            SET status=%s
            FROM candidates
            WHERE r.tenant_id = candidates.tenant_id
              AND r.workspace = candidates.workspace
              AND r.run_id = candidates.run_id
            RETURNING r.run_id
            """,
            (tenant_id, workspace, STATE_RUNNING, max_rows, STATE_FAILED),
        )
        rows = cur.fetchall() or []
        stale_run_ids = [str(row[0]) for row in rows if row and row[0]]

    for run_id in stale_run_ids:
        reason = "recovery:expired_lock" if run_id in expired_run_ids else "recovery:no_active_lock"
        append_run_event(
            conn,
            tenant_id=tenant_id,
            workspace=workspace,
            run_id=run_id,
            event_type="run.state.changed",
            actor=actor,
            from_state=STATE_RUNNING,
            to_state=STATE_FAILED,
            payload={"reason": reason},
        )

    return RunRecoveryStats(
        expired_locks_reaped=len(expired_rows),
        stale_runs_failed=len(stale_run_ids),
        recovered_run_ids=tuple(stale_run_ids),
    )
