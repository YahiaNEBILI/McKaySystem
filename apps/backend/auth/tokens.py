"""Token helpers for RBAC sessions and API keys."""

from __future__ import annotations

import hashlib
import secrets

_DEFAULT_SESSION_TOKEN_BYTES = 48
_DEFAULT_API_KEY_BYTES = 32


def generate_session_token(*, token_bytes: int = _DEFAULT_SESSION_TOKEN_BYTES) -> str:
    """Create a random session token.

    Args:
        token_bytes: Number of random bytes used by `secrets.token_urlsafe`.

    Returns:
        URL-safe random session token.

    Raises:
        ValueError: If token_bytes is not positive.
    """
    if token_bytes <= 0:
        raise ValueError("token_bytes must be > 0")
    return secrets.token_urlsafe(token_bytes)


def generate_api_key(*, prefix: str = "mck", token_bytes: int = _DEFAULT_API_KEY_BYTES) -> str:
    """Create a random API key string.

    Args:
        prefix: Optional stable prefix used for operator readability.
        token_bytes: Number of random bytes used by `secrets.token_urlsafe`.

    Returns:
        API key string suitable for client use.

    Raises:
        ValueError: If token_bytes is not positive.
    """
    if token_bytes <= 0:
        raise ValueError("token_bytes must be > 0")
    secret = secrets.token_urlsafe(token_bytes)
    clean_prefix = str(prefix or "").strip()
    if not clean_prefix:
        return secret
    return f"{clean_prefix}_{secret}"


def hash_api_key(api_key: str) -> str:
    """Return a SHA-256 hex digest for API key storage.

    Args:
        api_key: Raw API key string.

    Returns:
        Lowercase SHA-256 hex digest.

    Raises:
        ValueError: If api_key is empty.
    """
    if not api_key:
        raise ValueError("api_key must not be empty")
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


def hash_session_token(session_token: str) -> str:
    """Return a SHA-256 hex digest for session token storage.

    Args:
        session_token: Raw session token string.

    Returns:
        Lowercase SHA-256 hex digest.

    Raises:
        ValueError: If session_token is empty.
    """
    if not session_token:
        raise ValueError("session_token must not be empty")
    return hashlib.sha256(session_token.encode("utf-8")).hexdigest()


def derive_key_id(api_key_hash: str, *, length: int = 16) -> str:
    """Derive a deterministic key identifier from an API key hash.

    Args:
        api_key_hash: SHA-256 hash returned by `hash_api_key`.
        length: Prefix length used for the derived key identifier.

    Returns:
        Stable key identifier with a fixed `key_` prefix.

    Raises:
        ValueError: If api_key_hash is empty or length is invalid.
    """
    if not api_key_hash:
        raise ValueError("api_key_hash must not be empty")
    if length <= 0:
        raise ValueError("length must be > 0")
    return f"key_{api_key_hash[:length]}"
