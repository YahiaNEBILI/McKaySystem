"""Database helpers for RBAC data access.

All queries are explicitly scoped by `tenant_id` and `workspace`.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from apps.backend.db import fetch_all_dict_conn, fetch_one_dict_conn


def _dict_from_cursor_row(cursor: Any, row: Sequence[Any] | None) -> dict[str, Any] | None:
    """Build a dict from a cursor row using cursor.description metadata."""
    if row is None:
        return None
    columns = [str(desc[0]) for desc in (getattr(cursor, "description", None) or [])]
    if not columns:
        return None
    return dict(zip(columns, row, strict=False))


# Column-mapped DTOs intentionally mirror table schemas for explicitness.
# pylint: disable=too-many-instance-attributes
@dataclass(frozen=True)
class UserUpsert:
    """Input payload for idempotent user upsert operations."""

    tenant_id: str
    workspace: str
    user_id: str
    email: str
    password_hash: str | None
    full_name: str | None = None
    external_id: str | None = None
    auth_provider: str = "local"
    is_active: bool = True
    is_superadmin: bool = False


@dataclass(frozen=True)
class ApiKeyUpsert:
    """Input payload for idempotent API key upsert operations."""

    tenant_id: str
    workspace: str
    key_id: str
    key_hash: str
    name: str
    description: str | None = None
    user_id: str | None = None
    key_type: str = "secret"
    expires_at: Any | None = None


@dataclass(frozen=True)
class SessionUpsert:
    """Input payload for idempotent session upsert operations."""

    tenant_id: str
    workspace: str
    session_id: str
    session_token_hash: str
    user_id: str
    expires_at: datetime


@dataclass(frozen=True)
class UserListQuery:
    """Input payload for scoped user list queries."""

    tenant_id: str
    workspace: str
    limit: int = 100
    offset: int = 0
    query: str | None = None
    include_inactive: bool = False


# pylint: enable=too-many-instance-attributes


def get_user_by_email(
    conn: Any,
    *,
    tenant_id: str,
    workspace: str,
    email: str,
) -> dict[str, Any] | None:
    """Return one user row by scoped email."""
    return fetch_one_dict_conn(
        conn,
        """
        SELECT
          tenant_id,
          workspace,
          user_id,
          email,
          password_hash,
          full_name,
          external_id,
          auth_provider,
          is_active,
          is_superadmin,
          last_login_at,
          created_at,
          updated_at
        FROM users
        WHERE tenant_id = %s
          AND workspace = %s
          AND email = %s
        """,
        (tenant_id, workspace, email),
    )


def get_user_by_id(
    conn: Any,
    *,
    tenant_id: str,
    workspace: str,
    user_id: str,
) -> dict[str, Any] | None:
    """Return one user row by scoped user identifier."""
    return fetch_one_dict_conn(
        conn,
        """
        SELECT
          tenant_id,
          workspace,
          user_id,
          email,
          password_hash,
          full_name,
          external_id,
          auth_provider,
          is_active,
          is_superadmin,
          last_login_at,
          created_at,
          updated_at
        FROM users
        WHERE tenant_id = %s
          AND workspace = %s
          AND user_id = %s
        """,
        (tenant_id, workspace, user_id),
    )


def create_user(conn: Any, *, user: UserUpsert) -> dict[str, Any] | None:
    """Create or update a scoped user row in an idempotent way."""
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO users (
              tenant_id,
              workspace,
              user_id,
              email,
              password_hash,
              full_name,
              external_id,
              auth_provider,
              is_active,
              is_superadmin,
              updated_at
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, now())
            ON CONFLICT (tenant_id, workspace, user_id)
            DO UPDATE SET
              email = EXCLUDED.email,
              password_hash = EXCLUDED.password_hash,
              full_name = EXCLUDED.full_name,
              external_id = EXCLUDED.external_id,
              auth_provider = EXCLUDED.auth_provider,
              is_active = EXCLUDED.is_active,
              is_superadmin = EXCLUDED.is_superadmin,
              updated_at = now()
            RETURNING
              tenant_id,
              workspace,
              user_id,
              email,
              password_hash,
              full_name,
              external_id,
              auth_provider,
              is_active,
              is_superadmin,
              last_login_at,
              created_at,
              updated_at
            """,
            (
                user.tenant_id,
                user.workspace,
                user.user_id,
                user.email,
                user.password_hash,
                user.full_name,
                user.external_id,
                user.auth_provider,
                user.is_active,
                user.is_superadmin,
            ),
        )
        return _dict_from_cursor_row(cur, cur.fetchone())


def list_users_page(conn: Any, *, query: UserListQuery) -> tuple[list[dict[str, Any]], int]:
    """List users with deterministic paging and scoped total count."""
    where = ["tenant_id = %s", "workspace = %s"]
    params: list[Any] = [query.tenant_id, query.workspace]

    if not query.include_inactive:
        where.append("is_active = TRUE")
    if query.query:
        where.append("(user_id ILIKE %s OR email ILIKE %s OR COALESCE(full_name, '') ILIKE %s)")
        pattern = f"%{query.query}%"
        params.extend([pattern, pattern, pattern])

    sql_items = f"""
        SELECT
          tenant_id,
          workspace,
          user_id,
          email,
          full_name,
          external_id,
          auth_provider,
          is_active,
          is_superadmin,
          last_login_at,
          created_at,
          updated_at
        FROM users
        WHERE {" AND ".join(where)}
        ORDER BY email ASC, user_id ASC
        LIMIT %s OFFSET %s
    """
    sql_count = f"SELECT COUNT(*)::bigint AS n FROM users WHERE {' AND '.join(where)}"
    rows = fetch_all_dict_conn(conn, sql_items, tuple(params + [query.limit, query.offset]))
    count_row = fetch_one_dict_conn(conn, sql_count, tuple(params))
    total = int((count_row or {}).get("n") or 0)
    return rows, total


def set_user_active(
    conn: Any,
    *,
    tenant_id: str,
    workspace: str,
    user_id: str,
    is_active: bool,
) -> bool:
    """Set user active status and report whether a row was updated."""
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE users
            SET
              is_active = %s,
              updated_at = now()
            WHERE tenant_id = %s
              AND workspace = %s
              AND user_id = %s
            """,
            (is_active, tenant_id, workspace, user_id),
        )
        return bool(cur.rowcount)


def list_api_keys(
    conn: Any,
    *,
    tenant_id: str,
    workspace: str,
    user_id: str | None = None,
    include_inactive: bool = False,
) -> list[dict[str, Any]]:
    """List API keys for one tenant/workspace scope."""
    where = ["tenant_id = %s", "workspace = %s"]
    params: list[Any] = [tenant_id, workspace]

    if user_id:
        where.append("user_id = %s")
        params.append(user_id)
    if not include_inactive:
        where.append("is_active = TRUE")

    sql = f"""
        SELECT
          tenant_id,
          workspace,
          key_id,
          key_hash,
          key_type,
          name,
          description,
          user_id,
          last_used_at,
          expires_at,
          is_active,
          created_at
        FROM api_keys
        WHERE {" AND ".join(where)}
        ORDER BY created_at DESC, key_id ASC
    """
    return fetch_all_dict_conn(conn, sql, tuple(params))


def create_api_key(conn: Any, *, api_key: ApiKeyUpsert) -> dict[str, Any] | None:
    """Create or update an API key row in an idempotent way."""
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO api_keys (
              tenant_id,
              workspace,
              key_id,
              key_hash,
              key_type,
              name,
              description,
              user_id,
              expires_at,
              is_active
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, TRUE)
            ON CONFLICT (tenant_id, workspace, key_id)
            DO UPDATE SET
              key_hash = EXCLUDED.key_hash,
              key_type = EXCLUDED.key_type,
              name = EXCLUDED.name,
              description = EXCLUDED.description,
              user_id = EXCLUDED.user_id,
              expires_at = EXCLUDED.expires_at,
              is_active = TRUE
            RETURNING
              tenant_id,
              workspace,
              key_id,
              key_hash,
              key_type,
              name,
              description,
              user_id,
              last_used_at,
              expires_at,
              is_active,
              created_at
            """,
            (
                api_key.tenant_id,
                api_key.workspace,
                api_key.key_id,
                api_key.key_hash,
                api_key.key_type,
                api_key.name,
                api_key.description,
                api_key.user_id,
                api_key.expires_at,
            ),
        )
        return _dict_from_cursor_row(cur, cur.fetchone())


def revoke_api_key(conn: Any, *, tenant_id: str, workspace: str, key_id: str) -> bool:
    """Disable one API key and report whether a row was updated."""
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE api_keys
            SET is_active = FALSE
            WHERE tenant_id = %s
              AND workspace = %s
              AND key_id = %s
              AND is_active = TRUE
            """,
            (tenant_id, workspace, key_id),
        )
        return bool(cur.rowcount)


def get_user_workspace_role(
    conn: Any,
    *,
    tenant_id: str,
    workspace: str,
    user_id: str,
) -> dict[str, Any] | None:
    """Return one scoped user-workspace-role mapping."""
    return fetch_one_dict_conn(
        conn,
        """
        SELECT
          tenant_id,
          workspace,
          user_id,
          role_id,
          granted_by,
          granted_at
        FROM user_workspace_roles
        WHERE tenant_id = %s
          AND workspace = %s
          AND user_id = %s
        """,
        (tenant_id, workspace, user_id),
    )


def get_role_permissions(conn: Any, *, tenant_id: str, workspace: str, role_id: str) -> list[str]:
    """Return permission identifiers for one role in scope."""
    rows = fetch_all_dict_conn(
        conn,
        """
        SELECT rp.permission_id
        FROM role_permissions rp
        WHERE rp.tenant_id = %s
          AND rp.workspace = %s
          AND rp.role_id = %s
        ORDER BY rp.permission_id ASC
        """,
        (tenant_id, workspace, role_id),
    )
    return [str(row["permission_id"]) for row in rows if row.get("permission_id")]


def check_permission(
    conn: Any,
    *,
    tenant_id: str,
    workspace: str,
    user_id: str,
    permission_id: str,
) -> bool:
    """Return True when a user has the requested permission in scope."""
    row = fetch_one_dict_conn(
        conn,
        """
        SELECT 1 AS allowed
        FROM user_workspace_roles uwr
        JOIN users u
          ON u.tenant_id = uwr.tenant_id
         AND u.workspace = uwr.workspace
         AND u.user_id = uwr.user_id
        JOIN role_permissions rp
          ON rp.tenant_id = uwr.tenant_id
         AND rp.workspace = uwr.workspace
         AND rp.role_id = uwr.role_id
        WHERE uwr.tenant_id = %s
          AND uwr.workspace = %s
          AND uwr.user_id = %s
          AND rp.permission_id = %s
          AND u.is_active = TRUE
        LIMIT 1
        """,
        (tenant_id, workspace, user_id, permission_id),
    )
    return bool(row and row.get("allowed") == 1)


def touch_user_last_login(conn: Any, *, tenant_id: str, workspace: str, user_id: str) -> None:
    """Update the last login timestamp for one scoped user."""
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE users
            SET
              last_login_at = now(),
              updated_at = now()
            WHERE tenant_id = %s
              AND workspace = %s
              AND user_id = %s
            """,
            (tenant_id, workspace, user_id),
        )


def upsert_user_session(
    conn: Any,
    *,
    session: SessionUpsert,
) -> dict[str, Any] | None:
    """Create or update a scoped user session by deterministic session_id."""
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO user_sessions (
              tenant_id,
              workspace,
              session_id,
              session_token_hash,
              user_id,
              expires_at
            )
            VALUES (%s, %s, %s, %s, %s, %s)
            ON CONFLICT (tenant_id, workspace, session_id)
            DO UPDATE SET
              session_token_hash = EXCLUDED.session_token_hash,
              user_id = EXCLUDED.user_id,
              expires_at = EXCLUDED.expires_at
            RETURNING
              tenant_id,
              workspace,
              session_id,
              session_token_hash,
              user_id,
              expires_at,
              created_at
            """,
            (
                session.tenant_id,
                session.workspace,
                session.session_id,
                session.session_token_hash,
                session.user_id,
                session.expires_at,
            ),
        )
        return _dict_from_cursor_row(cur, cur.fetchone())


def delete_session_by_hash(
    conn: Any,
    *,
    tenant_id: str,
    workspace: str,
    session_token_hash: str,
) -> bool:
    """Delete one session by token hash and return whether a row was removed."""
    with conn.cursor() as cur:
        cur.execute(
            """
            DELETE FROM user_sessions
            WHERE tenant_id = %s
              AND workspace = %s
              AND session_token_hash = %s
            """,
            (tenant_id, workspace, session_token_hash),
        )
        return bool(cur.rowcount)


def touch_api_key_last_used(
    conn: Any,
    *,
    tenant_id: str,
    workspace: str,
    key_id: str,
) -> None:
    """Set API key last_used_at timestamp for one scoped key identifier."""
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE api_keys
            SET last_used_at = now()
            WHERE tenant_id = %s
              AND workspace = %s
              AND key_id = %s
            """,
            (tenant_id, workspace, key_id),
        )


def get_user_by_api_key_hash(
    conn: Any,
    *,
    tenant_id: str,
    workspace: str,
    key_hash: str,
) -> dict[str, Any] | None:
    """Resolve active user context from scoped API key hash."""
    return fetch_one_dict_conn(
        conn,
        """
        SELECT
          u.tenant_id,
          u.workspace,
          u.user_id,
          u.email,
          u.full_name,
          u.auth_provider,
          u.is_active,
          u.is_superadmin,
          ak.key_id
        FROM api_keys ak
        JOIN users u
          ON u.tenant_id = ak.tenant_id
         AND u.workspace = ak.workspace
         AND u.user_id = ak.user_id
        WHERE ak.tenant_id = %s
          AND ak.workspace = %s
          AND ak.key_hash = %s
          AND ak.is_active = TRUE
          AND (ak.expires_at IS NULL OR ak.expires_at > now())
          AND u.is_active = TRUE
        LIMIT 1
        """,
        (tenant_id, workspace, key_hash),
    )


def get_user_by_session_hash(
    conn: Any,
    *,
    tenant_id: str,
    workspace: str,
    session_token_hash: str,
) -> dict[str, Any] | None:
    """Resolve active user context from scoped session token hash."""
    return fetch_one_dict_conn(
        conn,
        """
        SELECT
          u.tenant_id,
          u.workspace,
          u.user_id,
          u.email,
          u.full_name,
          u.auth_provider,
          u.is_active,
          u.is_superadmin,
          s.session_id,
          s.expires_at
        FROM user_sessions s
        JOIN users u
          ON u.tenant_id = s.tenant_id
         AND u.workspace = s.workspace
         AND u.user_id = s.user_id
        WHERE s.tenant_id = %s
          AND s.workspace = %s
          AND s.session_token_hash = %s
          AND s.expires_at > now()
          AND u.is_active = TRUE
        LIMIT 1
        """,
        (tenant_id, workspace, session_token_hash),
    )


def get_user_permissions(
    conn: Any,
    *,
    tenant_id: str,
    workspace: str,
    user_id: str,
) -> list[str]:
    """Return all effective scoped permissions for a user."""
    rows = fetch_all_dict_conn(
        conn,
        """
        SELECT DISTINCT rp.permission_id
        FROM user_workspace_roles uwr
        JOIN role_permissions rp
          ON rp.tenant_id = uwr.tenant_id
         AND rp.workspace = uwr.workspace
         AND rp.role_id = uwr.role_id
        JOIN users u
          ON u.tenant_id = uwr.tenant_id
         AND u.workspace = uwr.workspace
         AND u.user_id = uwr.user_id
        WHERE uwr.tenant_id = %s
          AND uwr.workspace = %s
          AND uwr.user_id = %s
          AND u.is_active = TRUE
        ORDER BY rp.permission_id ASC
        """,
        (tenant_id, workspace, user_id),
    )
    return [str(row["permission_id"]) for row in rows if row.get("permission_id")]
