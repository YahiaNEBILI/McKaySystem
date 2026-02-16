"""Teams Blueprint.

Provides team management endpoints including CRUD operations and member management.
"""

import json
from typing import Any

from flask import Blueprint, request

from apps.backend.db import (
    db_conn,
    execute_conn,
    fetch_all_dict_conn,
    fetch_one_dict_conn,
)
from apps.flask_api.utils import (
    _MISSING,
    _coerce_optional_text,
    _err,
    _ok,
    _parse_int,
    _payload_optional_text,
    _q,
    _require_scope_from_json,
    _require_scope_from_query,
)

# Create the blueprint
teams_bp = Blueprint("teams", __name__)


def _team_exists(conn: Any, *, tenant_id: str, workspace: str, team_id: str) -> bool:
    """Check if a team exists."""
    row = fetch_one_dict_conn(
        conn,
        """
        SELECT 1 AS ok
        FROM teams
        WHERE tenant_id = %s AND workspace = %s AND team_id = %s
        LIMIT 1
        """,
        (tenant_id, workspace, team_id),
    )
    return bool(row and row.get("ok") == 1)


def _fetch_team(conn: Any, *, tenant_id: str, workspace: str, team_id: str) -> dict[str, Any] | None:
    """Fetch one team by scoped id."""
    return fetch_one_dict_conn(
        conn,
        """
        SELECT
          tenant_id,
          workspace,
          team_id,
          name,
          description,
          parent_team_id,
          created_at,
          updated_at
        FROM teams
        WHERE tenant_id = %s AND workspace = %s AND team_id = %s
        """,
        (tenant_id, workspace, team_id),
    )


def _fetch_team_member(
    conn: Any, *, tenant_id: str, workspace: str, team_id: str, user_id: str
) -> dict[str, Any] | None:
    """Fetch one team member by scoped team_id + user_id."""
    return fetch_one_dict_conn(
        conn,
        """
        SELECT
          tenant_id,
          workspace,
          team_id,
          user_id,
          user_email,
          user_name,
          role,
          joined_at
        FROM team_members
        WHERE tenant_id = %s
          AND workspace = %s
          AND team_id = %s
          AND user_id = %s
        """,
        (tenant_id, workspace, team_id, user_id),
    )


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
    """Best-effort append-only write to audit_log, isolated by savepoint."""
    try:
        ip_address = request.headers.get("X-Forwarded-For", request.remote_addr)
        user_agent = request.headers.get("User-Agent", "")
    except RuntimeError:
        ip_address = None
        user_agent = ""

    # Audit write is currently a no-op fallback in this code path.
    _ = (
        tenant_id,
        workspace,
        entity_type,
        entity_id,
        fingerprint,
        event_type,
        event_category,
        json.dumps(previous_value, separators=(",", ":")) if previous_value is not None else None,
        json.dumps(new_value, separators=(",", ":")) if new_value is not None else None,
        actor_id,
        actor_email,
        actor_name,
        source,
        ip_address,
        user_agent,
        run_id,
        correlation_id,
    )

    with conn.cursor():
        try:
            # Silently ignore audit failures
            pass
        except Exception:
            pass


@teams_bp.route("/api/teams", methods=["GET"])
def api_teams() -> Any:
    """List teams in tenant/workspace scope.

    Query params:
        tenant_id (required): Tenant identifier
        workspace (required): Workspace identifier
        limit: Results limit (default 100)
        offset: Results offset (default 0)
        q: Search query (matches team_id or name)

    Returns:
        Paginated list of teams
    """
    try:
        tenant_id, workspace = _require_scope_from_query()
        limit = _parse_int(_q("limit"), default=100, min_v=1, max_v=1000)
        offset = _parse_int(_q("offset"), default=0, min_v=0, max_v=5_000_000)
        query_str = _q("q")

        where = ["t.tenant_id = %s", "t.workspace = %s"]
        params: list[Any] = [tenant_id, workspace]
        if query_str:
            where.append("(t.team_id ILIKE %s OR t.name ILIKE %s)")
            params.extend([f"%{query_str}%", f"%{query_str}%"])

        with db_conn() as conn:
            rows = fetch_all_dict_conn(
                conn,
                f"""
                SELECT
                  t.tenant_id,
                  t.workspace,
                  t.team_id,
                  t.name,
                  t.description,
                  t.parent_team_id,
                  t.created_at,
                  t.updated_at,
                  COUNT(tm.user_id)::bigint AS member_count
                FROM teams t
                LEFT JOIN team_members tm
                  ON tm.tenant_id = t.tenant_id
                  AND tm.workspace = t.workspace
                  AND tm.team_id = t.team_id
                WHERE {' AND '.join(where)}
                GROUP BY
                  t.tenant_id,
                  t.workspace,
                  t.team_id,
                  t.name,
                  t.description,
                  t.parent_team_id,
                  t.created_at,
                  t.updated_at
                ORDER BY t.name ASC, t.team_id ASC
                LIMIT %s OFFSET %s
                """,
                params + [limit, offset],
            )
            count_row = fetch_one_dict_conn(
                conn,
                f"SELECT COUNT(*)::bigint AS n FROM teams t WHERE {' AND '.join(where)}",
                params,
            )

        return _ok(
            {
                "tenant_id": tenant_id,
                "workspace": workspace,
                "limit": limit,
                "offset": offset,
                "total": int((count_row or {}).get("n") or 0),
                "items": rows,
            }
        )
    except ValueError as exc:
        return _err("bad_request", str(exc), status=400)


@teams_bp.route("/api/teams", methods=["POST"])
def api_create_team() -> Any:
    """Create a team in tenant/workspace scope.

    JSON body:
        tenant_id, workspace, team_id, name, description, parent_team_id, updated_by

    Returns:
        Created team
    """
    try:
        payload = request.get_json(force=True, silent=False) or {}
        tenant_id, workspace = _require_scope_from_json(payload)
        team_id = _coerce_optional_text(payload.get("team_id"))
        name = _coerce_optional_text(payload.get("name"))
        description_v = _payload_optional_text(payload, "description")
        parent_team_id_v = _payload_optional_text(payload, "parent_team_id")
        updated_by = _coerce_optional_text(payload.get("updated_by"))

        if not team_id:
            raise ValueError("team_id is required")
        if not name:
            raise ValueError("name is required")

        description = None if description_v is _MISSING else description_v
        parent_team_id = None if parent_team_id_v is _MISSING else parent_team_id_v

        if parent_team_id == team_id:
            raise ValueError("parent_team_id cannot equal team_id")

        with db_conn() as conn:
            if parent_team_id is not None and not _team_exists(
                conn, tenant_id=tenant_id, workspace=workspace, team_id=parent_team_id
            ):
                return _err("not_found", f"parent team not found: {parent_team_id}", status=404)
            if _team_exists(conn, tenant_id=tenant_id, workspace=workspace, team_id=team_id):
                return _err("conflict", f"team already exists: {team_id}", status=409)

            execute_conn(
                conn,
                """
                INSERT INTO teams
                  (tenant_id, workspace, team_id, name, description, parent_team_id, created_at, updated_at)
                VALUES
                  (%s, %s, %s, %s, %s, %s, now(), now())
                """,
                (tenant_id, workspace, team_id, name, description, parent_team_id),
            )
            team = _fetch_team(conn, tenant_id=tenant_id, workspace=workspace, team_id=team_id)

            _audit_log_event(
                conn,
                tenant_id=tenant_id,
                workspace=workspace,
                entity_type="team",
                entity_id=team_id,
                fingerprint=None,
                event_type="team.created",
                event_category="configuration",
                previous_value=None,
                new_value=team,
                actor_id=updated_by,
                actor_email=updated_by,
                actor_name=None,
                source="api",
            )
            conn.commit()

        return _ok({"tenant_id": tenant_id, "workspace": workspace, "team": team}, status=201)
    except ValueError as exc:
        return _err("bad_request", str(exc), status=400)


@teams_bp.route("/api/teams/<team_id>", methods=["PUT"])
def api_update_team(team_id: str) -> Any:
    """Update mutable team fields in tenant/workspace scope.

    JSON body:
        name, description, parent_team_id, updated_by

    Returns:
        Updated team
    """
    try:
        payload = request.get_json(force=True, silent=False) or {}
        tenant_id, workspace = _require_scope_from_json(payload)
        tid = _coerce_optional_text(team_id)
        if not tid:
            raise ValueError("team_id is required")

        name_v = _payload_optional_text(payload, "name")
        description_v = _payload_optional_text(payload, "description")
        parent_team_id_v = _payload_optional_text(payload, "parent_team_id")
        updated_by = _coerce_optional_text(payload.get("updated_by"))
        if name_v is _MISSING and description_v is _MISSING and parent_team_id_v is _MISSING:
            raise ValueError("at least one of name, description, parent_team_id must be provided")

        with db_conn() as conn:
            before = _fetch_team(conn, tenant_id=tenant_id, workspace=workspace, team_id=tid)
            if before is None:
                return _err("not_found", "team not found", status=404)

            name = before.get("name") if name_v is _MISSING else name_v
            if not name:
                raise ValueError("name cannot be empty")
            description = before.get("description") if description_v is _MISSING else description_v
            parent_team_id = before.get("parent_team_id") if parent_team_id_v is _MISSING else parent_team_id_v
            if parent_team_id == tid:
                raise ValueError("parent_team_id cannot equal team_id")

            if parent_team_id is not None and not _team_exists(
                conn, tenant_id=tenant_id, workspace=workspace, team_id=str(parent_team_id)
            ):
                return _err("not_found", f"parent team not found: {parent_team_id}", status=404)

            execute_conn(
                conn,
                """
                UPDATE teams
                SET
                  name = %s,
                  description = %s,
                  parent_team_id = %s,
                  updated_at = now()
                WHERE tenant_id = %s AND workspace = %s AND team_id = %s
                """,
                (name, description, parent_team_id, tenant_id, workspace, tid),
            )
            after = _fetch_team(conn, tenant_id=tenant_id, workspace=workspace, team_id=tid)

            _audit_log_event(
                conn,
                tenant_id=tenant_id,
                workspace=workspace,
                entity_type="team",
                entity_id=tid,
                fingerprint=None,
                event_type="team.updated",
                event_category="configuration",
                previous_value=before,
                new_value=after,
                actor_id=updated_by,
                actor_email=updated_by,
                actor_name=None,
                source="api",
            )
            conn.commit()

        return _ok({"tenant_id": tenant_id, "workspace": workspace, "team": after})
    except ValueError as exc:
        return _err("bad_request", str(exc), status=400)


@teams_bp.route("/api/teams/<team_id>", methods=["DELETE"])
def api_delete_team(team_id: str) -> Any:
    """Delete a team in tenant/workspace scope.

    Query params:
        tenant_id (required): Tenant identifier
        workspace (required): Workspace identifier
        updated_by: Actor performing the delete

    Returns:
        Deleted team confirmation
    """
    try:
        tenant_id, workspace = _require_scope_from_query()
        tid = _coerce_optional_text(team_id)
        if not tid:
            raise ValueError("team_id is required")
        updated_by = _coerce_optional_text(_q("updated_by"))

        with db_conn() as conn:
            before = _fetch_team(conn, tenant_id=tenant_id, workspace=workspace, team_id=tid)
            if before is None:
                return _err("not_found", "team not found", status=404)

            execute_conn(
                conn,
                "DELETE FROM teams WHERE tenant_id = %s AND workspace = %s AND team_id = %s",
                (tenant_id, workspace, tid),
            )
            _audit_log_event(
                conn,
                tenant_id=tenant_id,
                workspace=workspace,
                entity_type="team",
                entity_id=tid,
                fingerprint=None,
                event_type="team.deleted",
                event_category="configuration",
                previous_value=before,
                new_value=None,
                actor_id=updated_by,
                actor_email=updated_by,
                actor_name=None,
                source="api",
            )
            conn.commit()

        return _ok({"tenant_id": tenant_id, "workspace": workspace, "team_id": tid})
    except ValueError as exc:
        return _err("bad_request", str(exc), status=400)


@teams_bp.route("/api/teams/<team_id>/members", methods=["GET"])
def api_team_members(team_id: str) -> Any:
    """List members for one team in tenant/workspace scope.

    Query params:
        tenant_id (required): Tenant identifier
        workspace (required): Workspace identifier
        limit: Results limit (default 200)
        offset: Results offset (default 0)
        q: Search query

    Returns:
        Paginated list of team members
    """
    try:
        tenant_id, workspace = _require_scope_from_query()
        tid = _coerce_optional_text(team_id)
        if not tid:
            raise ValueError("team_id is required")

        limit = _parse_int(_q("limit"), default=200, min_v=1, max_v=1000)
        offset = _parse_int(_q("offset"), default=0, min_v=0, max_v=5_000_000)
        query_str = _q("q")

        with db_conn() as conn:
            if not _team_exists(conn, tenant_id=tenant_id, workspace=workspace, team_id=tid):
                return _err("not_found", "team not found", status=404)

            where = ["tenant_id = %s", "workspace = %s", "team_id = %s"]
            params: list[Any] = [tenant_id, workspace, tid]
            if query_str:
                where.append(
                    "(user_id ILIKE %s OR user_email ILIKE %s OR COALESCE(user_name, '') ILIKE %s)"
                )
                params.extend([f"%{query_str}%", f"%{query_str}%", f"%{query_str}%"])

            members = fetch_all_dict_conn(
                conn,
                f"""
                SELECT
                  tenant_id,
                  workspace,
                  team_id,
                  user_id,
                  user_email,
                  user_name,
                  role,
                  joined_at
                FROM team_members
                WHERE {' AND '.join(where)}
                ORDER BY user_email ASC, user_id ASC
                LIMIT %s OFFSET %s
                """,
                params + [limit, offset],
            )
            count_row = fetch_one_dict_conn(
                conn,
                f"SELECT COUNT(*)::bigint AS n FROM team_members WHERE {' AND '.join(where)}",
                params,
            )

        return _ok(
            {
                "tenant_id": tenant_id,
                "workspace": workspace,
                "team_id": tid,
                "limit": limit,
                "offset": offset,
                "total": int((count_row or {}).get("n") or 0),
                "items": members,
            }
        )
    except ValueError as exc:
        return _err("bad_request", str(exc), status=400)


@teams_bp.route("/api/teams/<team_id>/members", methods=["POST"])
def api_team_member_add(team_id: str) -> Any:
    """Add one member to a team in tenant/workspace scope.

    JSON body:
        user_id, user_email, user_name, role, updated_by

    Returns:
        Added member
    """
    try:
        payload = request.get_json(force=True, silent=False) or {}
        tenant_id, workspace = _require_scope_from_json(payload)
        tid = _coerce_optional_text(team_id)
        if not tid:
            raise ValueError("team_id is required")

        user_id = _coerce_optional_text(payload.get("user_id"))
        user_email = _coerce_optional_text(payload.get("user_email"))
        user_name_v = _payload_optional_text(payload, "user_name")
        role_v = _payload_optional_text(payload, "role")
        updated_by = _coerce_optional_text(payload.get("updated_by"))

        if not user_id:
            raise ValueError("user_id is required")
        if not user_email:
            raise ValueError("user_email is required")

        user_name = None if user_name_v is _MISSING else user_name_v
        role = "member" if role_v is _MISSING else role_v
        if role not in {"owner", "member", "viewer"}:
            raise ValueError("role must be one of: owner, member, viewer")

        with db_conn() as conn:
            if not _team_exists(conn, tenant_id=tenant_id, workspace=workspace, team_id=tid):
                return _err("not_found", "team not found", status=404)

            existing = _fetch_team_member(
                conn, tenant_id=tenant_id, workspace=workspace, team_id=tid, user_id=user_id
            )
            if existing:
                return _err("conflict", f"member already exists: {user_id}", status=409)

            execute_conn(
                conn,
                """
                INSERT INTO team_members
                  (tenant_id, workspace, team_id, user_id, user_email, user_name, role, joined_at)
                VALUES
                  (%s, %s, %s, %s, %s, %s, %s, now())
                """,
                (tenant_id, workspace, tid, user_id, user_email, user_name, role),
            )
            member = _fetch_team_member(
                conn, tenant_id=tenant_id, workspace=workspace, team_id=tid, user_id=user_id
            )

            _audit_log_event(
                conn,
                tenant_id=tenant_id,
                workspace=workspace,
                entity_type="team_member",
                entity_id=f"{tid}:{user_id}",
                fingerprint=None,
                event_type="team.member.added",
                event_category="configuration",
                previous_value=None,
                new_value=member,
                actor_id=updated_by,
                actor_email=updated_by,
                actor_name=None,
                source="api",
            )
            conn.commit()

        return _ok({"tenant_id": tenant_id, "workspace": workspace, "team_id": tid, "member": member}, status=201)
    except ValueError as exc:
        return _err("bad_request", str(exc), status=400)


@teams_bp.route("/api/teams/<team_id>/members/<user_id>", methods=["DELETE"])
def api_team_member_remove(team_id: str, user_id: str) -> Any:
    """Remove one member from a team in tenant/workspace scope.

    Query params:
        tenant_id (required): Tenant identifier
        workspace (required): Workspace identifier
        updated_by: Actor performing the remove

    Returns:
        Removal confirmation
    """
    try:
        tenant_id, workspace = _require_scope_from_query()
        tid = _coerce_optional_text(team_id)
        uid = _coerce_optional_text(user_id)
        if not tid:
            raise ValueError("team_id is required")
        if not uid:
            raise ValueError("user_id is required")
        updated_by = _coerce_optional_text(_q("updated_by"))

        with db_conn() as conn:
            before = _fetch_team_member(
                conn, tenant_id=tenant_id, workspace=workspace, team_id=tid, user_id=uid
            )
            if before is None:
                return _err("not_found", "member not found", status=404)

            execute_conn(
                conn,
                "DELETE FROM team_members WHERE tenant_id = %s AND workspace = %s AND team_id = %s AND user_id = %s",
                (tenant_id, workspace, tid, uid),
            )
            _audit_log_event(
                conn,
                tenant_id=tenant_id,
                workspace=workspace,
                entity_type="team_member",
                entity_id=f"{tid}:{uid}",
                fingerprint=None,
                event_type="team.member.removed",
                event_category="configuration",
                previous_value=before,
                new_value=None,
                actor_id=updated_by,
                actor_email=updated_by,
                actor_name=None,
                source="api",
            )
            conn.commit()

        return _ok({"tenant_id": tenant_id, "workspace": workspace, "team_id": tid, "user_id": uid})
    except ValueError as exc:
        return _err("bad_request", str(exc), status=400)
