"""Scoped RBAC bootstrap helpers for operator-driven onboarding."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from apps.backend import db_rbac
from apps.backend.auth.passwords import hash_password
from apps.backend.auth.tokens import derive_key_id, generate_api_key, hash_api_key
from apps.backend.db import db_conn


@dataclass(frozen=True)
class ScopeBootstrapResult:
    """Structured result for one scope bootstrap operation."""

    tenant_id: str
    workspace: str
    user_id: str
    email: str
    role_id: str
    is_superadmin: bool
    api_key: str | None
    key_id: str | None

    def to_dict(self) -> dict[str, Any]:
        """Return JSON-serializable payload.

        Returns:
            Dictionary payload with stable field names.
        """
        return {
            "tenant_id": self.tenant_id,
            "workspace": self.workspace,
            "user_id": self.user_id,
            "email": self.email,
            "role_id": self.role_id,
            "is_superadmin": self.is_superadmin,
            "api_key": self.api_key,
            "key_id": self.key_id,
        }


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


def bootstrap_scope_admin(
    *,
    tenant_id: str,
    workspace: str,
    user_id: str,
    email: str,
    password: str,
    full_name: str | None = None,
    role_id: str = "admin",
    granted_by: str | None = "bootstrap-cli",
    is_superadmin: bool = False,
    create_api_key: bool = False,
    api_key_name: str = "bootstrap-cli",
    api_key_description: str | None = None,
) -> ScopeBootstrapResult:
    """Bootstrap RBAC access for one tenant/workspace scope.

    This helper is intentionally idempotent for user + role assignment:
    - seeds roles/permissions into the scope from templates
    - creates or updates one scoped user
    - assigns one role to that user in the scope

    API key creation is optional and non-idempotent by nature (new key material).

    Args:
        tenant_id: Target tenant identifier.
        workspace: Target workspace identifier.
        user_id: Scoped user identifier.
        email: User login email.
        password: Plaintext password for hashing.
        full_name: Optional display name.
        role_id: Role identifier to assign.
        granted_by: Grant actor marker for role assignment.
        is_superadmin: Whether to set global superadmin bypass for this user.
        create_api_key: Whether to issue a new API key for the user.
        api_key_name: API key display name when `create_api_key=True`.
        api_key_description: Optional API key description.

    Returns:
        ScopeBootstrapResult containing resolved user/role scope and optional key.

    Raises:
        ValueError: Any required field is missing or role is not found after scope bootstrap.
    """
    tenant = _required_text(tenant_id, field_name="tenant_id")
    ws = _required_text(workspace, field_name="workspace")
    uid = _required_text(user_id, field_name="user_id")
    email_norm = _required_text(email, field_name="email").lower()
    pw = _required_text(password, field_name="password")
    rid = _required_text(role_id, field_name="role_id")
    name_norm = str(full_name).strip() if full_name is not None else None
    granted_by_norm = str(granted_by).strip() if granted_by is not None else None

    if create_api_key:
        key_name_norm = _required_text(api_key_name, field_name="api_key_name")
    else:
        key_name_norm = api_key_name

    api_key_raw: str | None = None
    key_id: str | None = None

    with db_conn() as conn:
        db_rbac.bootstrap_rbac_scope(
            conn,
            tenant_id=tenant,
            workspace=ws,
        )
        role = db_rbac.get_role_by_id(
            conn,
            tenant_id=tenant,
            workspace=ws,
            role_id=rid,
        )
        if role is None:
            raise ValueError(f"role not found after bootstrap: {rid}")

        db_rbac.create_user(
            conn,
            user=db_rbac.UserUpsert(
                tenant_id=tenant,
                workspace=ws,
                user_id=uid,
                email=email_norm,
                password_hash=hash_password(pw),
                full_name=name_norm,
                auth_provider="local",
                is_active=True,
                is_superadmin=bool(is_superadmin),
            ),
        )
        db_rbac.upsert_user_workspace_role(
            conn,
            assignment=db_rbac.UserWorkspaceRoleUpsert(
                tenant_id=tenant,
                workspace=ws,
                user_id=uid,
                role_id=rid,
                granted_by=granted_by_norm,
            ),
        )

        if create_api_key:
            api_key_raw = generate_api_key(prefix="mck")
            key_hash = hash_api_key(api_key_raw)
            key_id = derive_key_id(key_hash)
            db_rbac.create_api_key(
                conn,
                api_key=db_rbac.ApiKeyUpsert(
                    tenant_id=tenant,
                    workspace=ws,
                    key_id=key_id,
                    key_hash=key_hash,
                    key_type="secret",
                    name=key_name_norm,
                    description=api_key_description,
                    user_id=uid,
                ),
            )
        conn.commit()

    return ScopeBootstrapResult(
        tenant_id=tenant,
        workspace=ws,
        user_id=uid,
        email=email_norm,
        role_id=rid,
        is_superadmin=bool(is_superadmin),
        api_key=api_key_raw,
        key_id=key_id,
    )
