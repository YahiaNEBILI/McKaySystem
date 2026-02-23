"""Scoped RBAC bootstrap helpers for operator-driven onboarding."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from apps.backend import db_rbac
from apps.backend.auth.passwords import hash_password
from apps.backend.auth.tokens import derive_key_id, generate_api_key, hash_api_key
from apps.backend.db import db_conn


@dataclass(frozen=True)
class ScopeBootstrapOptions:
    """Optional controls for scope bootstrap behavior."""

    full_name: str | None = None
    role_id: str = "admin"
    granted_by: str | None = "bootstrap-cli"
    is_superadmin: bool = False
    create_api_key: bool = False
    api_key_name: str = "bootstrap-cli"
    api_key_description: str | None = None


@dataclass(frozen=True)
class ScopeBootstrapRequest:
    """Required scope bootstrap request payload."""

    tenant_id: str
    workspace: str
    user_id: str
    email: str
    password: str
    options: ScopeBootstrapOptions | None = None


@dataclass(frozen=True)
class _NormalizedCore:
    """Normalized required fields for persistence calls."""

    tenant_id: str
    workspace: str
    user_id: str
    email: str
    password_hash: str


def _required_text(value: str, *, field_name: str) -> str:
    """Normalize one required text field.

    Args:
        value: Candidate field value.
        field_name: Field label used in validation errors.

    Returns:
        Trimmed, non-empty string.

    Raises:
        ValueError: Field value is empty.
    """
    text = str(value or "").strip()
    if not text:
        raise ValueError(f"{field_name} is required")
    return text


def _normalize_core_inputs(
    *,
    tenant_id: str,
    workspace: str,
    user_id: str,
    email: str,
    password: str,
) -> tuple[str, str, str, str, str]:
    """Normalize and validate required bootstrap fields.

    Args:
        tenant_id: Target tenant identifier.
        workspace: Target workspace identifier.
        user_id: Scoped user identifier.
        email: User email.
        password: Plaintext password.

    Returns:
        Tuple of normalized values in the same field order.
    """
    return (
        _required_text(tenant_id, field_name="tenant_id"),
        _required_text(workspace, field_name="workspace"),
        _required_text(user_id, field_name="user_id"),
        _required_text(email, field_name="email").lower(),
        _required_text(password, field_name="password"),
    )


def _normalize_options(options: ScopeBootstrapOptions | None) -> ScopeBootstrapOptions:
    """Return sanitized bootstrap options.

    Args:
        options: Caller-provided options, if any.

    Returns:
        Normalized options with defaults applied.
    """
    opt = options or ScopeBootstrapOptions()
    role_id = _required_text(opt.role_id, field_name="role_id")
    granted_by = str(opt.granted_by).strip() if opt.granted_by is not None else None
    full_name = str(opt.full_name).strip() if opt.full_name is not None else None
    key_name = opt.api_key_name
    if opt.create_api_key:
        key_name = _required_text(opt.api_key_name, field_name="api_key_name")
    return ScopeBootstrapOptions(
        full_name=full_name,
        role_id=role_id,
        granted_by=granted_by,
        is_superadmin=bool(opt.is_superadmin),
        create_api_key=bool(opt.create_api_key),
        api_key_name=key_name,
        api_key_description=opt.api_key_description,
    )


def _apply_bootstrap(
    conn: Any,
    *,
    core: _NormalizedCore,
    options: ScopeBootstrapOptions,
) -> tuple[str | None, str | None]:
    """Persist user/role bootstrap changes and optional API key.

    Args:
        conn: Open DB connection.
        core: Normalized required bootstrap fields.
        options: Sanitized bootstrap options.

    Returns:
        Tuple `(api_key_raw, key_id)` for optional key issuance.

    Raises:
        ValueError: Role is unavailable in target scope.
    """
    db_rbac.bootstrap_rbac_scope(
        conn,
        tenant_id=core.tenant_id,
        workspace=core.workspace,
    )
    role = db_rbac.get_role_by_id(
        conn,
        tenant_id=core.tenant_id,
        workspace=core.workspace,
        role_id=options.role_id,
    )
    if role is None:
        raise ValueError(f"role not found after bootstrap: {options.role_id}")

    db_rbac.create_user(
        conn,
        user=db_rbac.UserUpsert(
            tenant_id=core.tenant_id,
            workspace=core.workspace,
            user_id=core.user_id,
            email=core.email,
            password_hash=core.password_hash,
            full_name=options.full_name,
            auth_provider="local",
            is_active=True,
            is_superadmin=options.is_superadmin,
        ),
    )
    db_rbac.upsert_user_workspace_role(
        conn,
        assignment=db_rbac.UserWorkspaceRoleUpsert(
            tenant_id=core.tenant_id,
            workspace=core.workspace,
            user_id=core.user_id,
            role_id=options.role_id,
            granted_by=options.granted_by,
        ),
    )

    if not options.create_api_key:
        return None, None

    api_key_raw = generate_api_key(prefix="mck")
    key_hash = hash_api_key(api_key_raw)
    key_id = derive_key_id(key_hash)
    db_rbac.create_api_key(
        conn,
        api_key=db_rbac.ApiKeyUpsert(
            tenant_id=core.tenant_id,
            workspace=core.workspace,
            key_id=key_id,
            key_hash=key_hash,
            key_type="secret",
            name=options.api_key_name,
            description=options.api_key_description,
            user_id=core.user_id,
        ),
    )
    return api_key_raw, key_id


def bootstrap_scope_admin(request: ScopeBootstrapRequest) -> dict[str, Any]:
    """Bootstrap RBAC access for one tenant/workspace scope.

    This helper is intentionally idempotent for user + role assignment:
    - seeds roles/permissions into the scope from templates
    - creates or updates one scoped user
    - assigns one role to that user in the scope

    API key creation is optional and non-idempotent by nature (new key material).

    Args:
        request: Full bootstrap request payload.

    Returns:
        JSON-serializable result payload with resolved scope and optional key.

    Raises:
        ValueError: Any required field is missing or role is not found after scope bootstrap.
    """
    tenant, ws, uid, email_norm, pw = _normalize_core_inputs(
        tenant_id=request.tenant_id,
        workspace=request.workspace,
        user_id=request.user_id,
        email=request.email,
        password=request.password,
    )
    opt = _normalize_options(request.options)

    with db_conn() as conn:
        core = _NormalizedCore(
            tenant_id=tenant,
            workspace=ws,
            user_id=uid,
            email=email_norm,
            password_hash=hash_password(pw),
        )
        api_key_raw, key_id = _apply_bootstrap(conn, core=core, options=opt)
        conn.commit()

    return {
        "tenant_id": tenant,
        "workspace": ws,
        "user_id": uid,
        "email": email_norm,
        "role_id": opt.role_id,
        "is_superadmin": opt.is_superadmin,
        "api_key": api_key_raw,
        "key_id": key_id,
    }
