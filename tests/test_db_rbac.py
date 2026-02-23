"""Unit tests for RBAC database helper query contracts."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, Literal

from apps.backend import db_rbac


class _FakeCursor:
    """Cursor test double for write helpers."""

    def __init__(
        self,
        *,
        row: Sequence[Any] | None = None,
        description: Sequence[Sequence[Any]] | None = None,
        rowcount: int = 1,
    ) -> None:
        self._row = row
        self.description = description or []
        self.rowcount = rowcount
        self.executed_sql: str | None = None
        self.executed_params: Sequence[Any] | None = None
        self.executed_statements: list[tuple[str, Sequence[Any] | None]] = []

    def __enter__(self) -> _FakeCursor:
        return self

    def __exit__(self, exc_type, exc, tb) -> Literal[False]:  # type: ignore[no-untyped-def]
        return False

    def execute(self, sql: str, params: Sequence[Any] | None = None) -> None:
        self.executed_sql = sql
        self.executed_params = params
        self.executed_statements.append((sql, params))

    def fetchone(self) -> Sequence[Any] | None:
        return self._row


class _FakeConn:
    """Connection test double that exposes one cursor instance."""

    def __init__(self, cursor: _FakeCursor) -> None:
        self._cursor = cursor

    def cursor(self) -> _FakeCursor:
        return self._cursor

    def commit(self) -> None:
        return


def test_get_user_by_email_includes_tenant_and_workspace(monkeypatch: Any) -> None:
    captured: dict[str, Any] = {}

    def _fake_fetch_one(
        _conn: object, sql: str, params: Sequence[Any] | None = None
    ) -> dict[str, Any]:
        captured["sql"] = sql
        captured["params"] = params
        return {"user_id": "user-1"}

    monkeypatch.setattr(db_rbac, "fetch_one_dict_conn", _fake_fetch_one)
    row = db_rbac.get_user_by_email(
        object(),
        tenant_id="acme",
        workspace="prod",
        email="alice@acme.io",
    )

    assert row == {"user_id": "user-1"}
    assert captured["params"] == ("acme", "prod", "alice@acme.io")
    sql = str(captured["sql"]).lower()
    assert "from users" in sql
    assert "tenant_id = %s" in sql
    assert "workspace = %s" in sql


def test_create_user_is_idempotent_and_scoped() -> None:
    cursor = _FakeCursor(
        row=("acme", "prod", "user-1"),
        description=(("tenant_id",), ("workspace",), ("user_id",)),
    )
    conn = _FakeConn(cursor)

    row = db_rbac.create_user(
        conn,
        user=db_rbac.UserUpsert(
            tenant_id="acme",
            workspace="prod",
            user_id="user-1",
            email="alice@acme.io",
            password_hash="hash",
        ),
    )

    assert row == {"tenant_id": "acme", "workspace": "prod", "user_id": "user-1"}
    assert cursor.executed_params is not None
    assert tuple(cursor.executed_params)[0:3] == ("acme", "prod", "user-1")
    sql = str(cursor.executed_sql).lower()
    assert "insert into users" in sql
    assert "on conflict (tenant_id, workspace, user_id)" in sql


def test_list_users_page_applies_scope_and_count(monkeypatch: Any) -> None:
    captured: dict[str, Any] = {}

    def _fake_fetch_all(
        _conn: object, sql: str, params: Sequence[Any] | None = None
    ) -> list[dict[str, Any]]:
        captured["items_sql"] = sql
        captured["items_params"] = params
        return [{"user_id": "u-1"}]

    def _fake_fetch_one(
        _conn: object, sql: str, params: Sequence[Any] | None = None
    ) -> dict[str, Any]:
        captured["count_sql"] = sql
        captured["count_params"] = params
        return {"n": 1}

    monkeypatch.setattr(db_rbac, "fetch_all_dict_conn", _fake_fetch_all)
    monkeypatch.setattr(db_rbac, "fetch_one_dict_conn", _fake_fetch_one)

    rows, total = db_rbac.list_users_page(
        object(),
        query=db_rbac.UserListQuery(
            tenant_id="acme",
            workspace="prod",
            limit=50,
            offset=10,
            query="alice",
            include_inactive=False,
        ),
    )

    assert rows == [{"user_id": "u-1"}]
    assert total == 1
    assert captured["items_params"] == ("acme", "prod", "%alice%", "%alice%", "%alice%", 50, 10)
    assert captured["count_params"] == ("acme", "prod", "%alice%", "%alice%", "%alice%")
    assert "from users" in str(captured["items_sql"]).lower()
    assert "count(*)::bigint" in str(captured["count_sql"]).lower()


def test_list_roles_applies_scope_and_returns_permissions(monkeypatch: Any) -> None:
    captured: dict[str, Any] = {}

    def _fake_fetch_all(
        _conn: object, sql: str, params: Sequence[Any] | None = None
    ) -> list[dict[str, Any]]:
        captured["sql"] = sql
        captured["params"] = params
        return [
            {
                "tenant_id": "acme",
                "workspace": "prod",
                "role_id": "viewer",
                "name": "Viewer",
                "description": "Read-only",
                "is_system": True,
                "permissions": ["findings:read", "runs:read"],
            }
        ]

    monkeypatch.setattr(db_rbac, "fetch_all_dict_conn", _fake_fetch_all)

    rows = db_rbac.list_roles(
        object(),
        tenant_id="acme",
        workspace="prod",
    )

    assert rows[0]["role_id"] == "viewer"
    assert rows[0]["permissions"] == ["findings:read", "runs:read"]
    assert captured["params"] == ("acme", "prod")
    sql = str(captured["sql"]).lower()
    assert "from roles r" in sql
    assert "left join role_permissions" in sql


def test_list_api_keys_applies_scope_and_active_filter(monkeypatch: Any) -> None:
    captured: dict[str, Any] = {}

    def _fake_fetch_all(
        _conn: object, sql: str, params: Sequence[Any] | None = None
    ) -> list[dict[str, Any]]:
        captured["sql"] = sql
        captured["params"] = params
        return []

    monkeypatch.setattr(db_rbac, "fetch_all_dict_conn", _fake_fetch_all)
    rows = db_rbac.list_api_keys(
        object(),
        tenant_id="acme",
        workspace="prod",
        user_id="user-1",
        include_inactive=False,
    )

    assert rows == []
    assert captured["params"] == ("acme", "prod", "user-1")
    sql = str(captured["sql"]).lower()
    assert "from api_keys" in sql
    assert "tenant_id = %s" in sql
    assert "workspace = %s" in sql
    assert "is_active = true" in sql


def test_set_user_active_updates_scoped_user() -> None:
    cursor = _FakeCursor(rowcount=1)
    conn = _FakeConn(cursor)

    changed = db_rbac.set_user_active(
        conn,
        tenant_id="acme",
        workspace="prod",
        user_id="user-1",
        is_active=False,
    )

    assert changed is True
    assert cursor.executed_params == (False, "acme", "prod", "user-1")
    sql = str(cursor.executed_sql).lower()
    assert "update users" in sql
    assert "tenant_id = %s" in sql
    assert "workspace = %s" in sql


def test_revoke_api_key_returns_false_when_no_rows_updated() -> None:
    cursor = _FakeCursor(rowcount=0)
    conn = _FakeConn(cursor)

    changed = db_rbac.revoke_api_key(
        conn,
        tenant_id="acme",
        workspace="prod",
        key_id="key-1",
    )

    assert changed is False
    assert cursor.executed_params == ("acme", "prod", "key-1")
    sql = str(cursor.executed_sql).lower()
    assert "update api_keys" in sql
    assert "tenant_id = %s" in sql
    assert "workspace = %s" in sql


def test_check_permission_uses_scoped_join(monkeypatch: Any) -> None:
    captured: dict[str, Any] = {}

    def _fake_fetch_one(
        _conn: object, sql: str, params: Sequence[Any] | None = None
    ) -> dict[str, Any]:
        captured["sql"] = sql
        captured["params"] = params
        return {"allowed": 1}

    monkeypatch.setattr(db_rbac, "fetch_one_dict_conn", _fake_fetch_one)
    allowed = db_rbac.check_permission(
        object(),
        tenant_id="acme",
        workspace="prod",
        user_id="user-1",
        permission_id="findings:read",
    )

    assert allowed is True
    assert captured["params"] == ("acme", "prod", "user-1", "findings:read")
    sql = str(captured["sql"]).lower()
    assert "from user_workspace_roles" in sql
    assert "join role_permissions" in sql
    assert "uwr.tenant_id = %s" in sql
    assert "uwr.workspace = %s" in sql


def test_get_role_by_id_includes_scope(monkeypatch: Any) -> None:
    captured: dict[str, Any] = {}

    def _fake_fetch_one(
        _conn: object, sql: str, params: Sequence[Any] | None = None
    ) -> dict[str, Any]:
        captured["sql"] = sql
        captured["params"] = params
        return {"role_id": "viewer"}

    monkeypatch.setattr(db_rbac, "fetch_one_dict_conn", _fake_fetch_one)
    row = db_rbac.get_role_by_id(
        object(),
        tenant_id="acme",
        workspace="prod",
        role_id="viewer",
    )

    assert row == {"role_id": "viewer"}
    assert captured["params"] == ("acme", "prod", "viewer")
    sql = str(captured["sql"]).lower()
    assert "from roles" in sql
    assert "tenant_id = %s" in sql
    assert "workspace = %s" in sql


def test_list_tenant_workspaces_uses_anchor_scope(monkeypatch: Any) -> None:
    captured: dict[str, Any] = {}

    def _fake_fetch_all(
        _conn: object, sql: str, params: Sequence[Any] | None = None
    ) -> list[dict[str, Any]]:
        captured["sql"] = sql
        captured["params"] = params
        return [{"workspace": "dev"}, {"workspace": "prod"}]

    monkeypatch.setattr(db_rbac, "fetch_all_dict_conn", _fake_fetch_all)
    rows = db_rbac.list_tenant_workspaces(
        object(),
        tenant_id="acme",
        anchor_workspace="prod",
    )

    assert rows == ["dev", "prod"]
    assert captured["params"] == ("acme", "prod")
    sql = str(captured["sql"]).lower()
    assert "from roles r_anchor" in sql
    assert "join roles r_all" in sql
    assert "r_anchor.tenant_id = %s" in sql
    assert "r_anchor.workspace = %s" in sql


def test_upsert_user_workspace_role_is_idempotent_and_scoped() -> None:
    cursor = _FakeCursor(
        row=("acme", "prod", "u-1", "editor"),
        description=(("tenant_id",), ("workspace",), ("user_id",), ("role_id",)),
    )
    conn = _FakeConn(cursor)

    row = db_rbac.upsert_user_workspace_role(
        conn,
        assignment=db_rbac.UserWorkspaceRoleUpsert(
            tenant_id="acme",
            workspace="prod",
            user_id="u-1",
            role_id="editor",
            granted_by="admin@acme.io",
        ),
    )

    assert row == {
        "tenant_id": "acme",
        "workspace": "prod",
        "user_id": "u-1",
        "role_id": "editor",
    }
    assert cursor.executed_params == ("acme", "prod", "u-1", "editor", "admin@acme.io")
    sql = str(cursor.executed_sql).lower()
    assert "insert into user_workspace_roles" in sql
    assert "on conflict (tenant_id, workspace, user_id)" in sql


def test_bootstrap_rbac_scope_copies_template_scope_idempotently() -> None:
    cursor = _FakeCursor()
    conn = _FakeConn(cursor)

    db_rbac.bootstrap_rbac_scope(
        conn,
        tenant_id="acme",
        workspace="prod",
    )

    assert len(cursor.executed_statements) == 3
    first_sql, first_params = cursor.executed_statements[0]
    second_sql, second_params = cursor.executed_statements[1]
    third_sql, third_params = cursor.executed_statements[2]

    assert first_params == ("acme", "prod", "default", "default")
    assert second_params == ("acme", "prod", "default", "default")
    assert third_params == ("acme", "prod", "default", "default")

    assert "insert into roles" in str(first_sql).lower()
    assert "from roles src" in str(first_sql).lower()
    assert "on conflict (tenant_id, workspace, role_id) do nothing" in str(first_sql).lower()

    assert "insert into permissions" in str(second_sql).lower()
    assert "from permissions src" in str(second_sql).lower()
    assert (
        "on conflict (tenant_id, workspace, permission_id) do nothing"
        in str(second_sql).lower()
    )

    assert "insert into role_permissions" in str(third_sql).lower()
    assert "from role_permissions src" in str(third_sql).lower()
    assert (
        "on conflict (tenant_id, workspace, role_id, permission_id) do nothing"
        in str(third_sql).lower()
    )
