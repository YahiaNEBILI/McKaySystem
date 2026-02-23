"""Unit tests for RBAC password and token helpers."""

from __future__ import annotations

from apps.backend.auth.passwords import hash_password, verify_password
from apps.backend.auth.tokens import (
    derive_key_id,
    generate_api_key,
    generate_session_token,
    hash_api_key,
    hash_session_token,
)


def test_hash_password_and_verify_round_trip() -> None:
    plain = "S3cure-Password!"
    encoded = hash_password(plain)

    assert encoded.startswith("pbkdf2_sha256$")
    assert verify_password(plain, encoded) is True
    assert verify_password("wrong-password", encoded) is False


def test_hash_password_uses_random_salt() -> None:
    plain = "same-password"
    first = hash_password(plain)
    second = hash_password(plain)

    assert first != second
    assert verify_password(plain, first) is True
    assert verify_password(plain, second) is True


def test_verify_password_rejects_malformed_hash() -> None:
    assert verify_password("secret", "not-a-valid-hash") is False
    assert verify_password("secret", "pbkdf2_sha256$bad$format$!") is False


def test_generate_session_token_is_random() -> None:
    first = generate_session_token()
    second = generate_session_token()

    assert first
    assert second
    assert first != second


def test_hash_session_token_is_deterministic() -> None:
    token = generate_session_token()
    digest_a = hash_session_token(token)
    digest_b = hash_session_token(token)

    assert len(digest_a) == 64
    assert digest_a == digest_b


def test_generate_api_key_prefix_and_hash() -> None:
    key = generate_api_key(prefix="mck")
    digest = hash_api_key(key)

    assert key.startswith("mck_")
    assert len(digest) == 64
    assert digest == hash_api_key(key)


def test_derive_key_id_is_stable_prefix() -> None:
    digest = "1f" * 32
    key_id = derive_key_id(digest, length=12)

    assert key_id == "key_" + digest[:12]
