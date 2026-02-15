"""Unit tests for centralized configuration parsing and validation."""

from __future__ import annotations

from typing import Any

import pytest

from infra.config import Settings, ValidationError, clear_settings_cache, get_settings


def test_settings_reads_legacy_env_keys() -> None:
    """Legacy flat env keys should map to nested settings models."""
    env = {
        "DB_URL": "postgres://legacy/db",
        "DB_POOL_MAXCONN": "15",
        "DB_CONNECT_TIMEOUT": "9",
        "AWS_REGIONS": "us-east-1,eu-west-1",
        "AWS_MAX_RETRIES": "7",
        "API_VERSION": "v2",
        "API_DEBUG_ERRORS": "1",
        "PORT": "7001",
    }
    settings = Settings.from_env(env=env, env_file=".missing.env")

    assert settings.db.url == "postgres://legacy/db"
    assert settings.db.pool_maxconn == 15
    assert settings.db.connect_timeout == 9
    assert settings.aws.regions == ["us-east-1", "eu-west-1"]
    assert settings.aws.max_retries == 7
    assert settings.api.version == "v2"
    assert settings.api.debug_errors is True
    assert settings.api.port == 7001


def test_settings_reads_nested_env_keys() -> None:
    """Nested env keys should be supported with `__` delimiter."""
    env = {
        "DB__URL": "postgres://nested/db",
        "DB__POOL_MAXCONN": "11",
        "AWS__REGIONS": "us-east-2,us-east-2,eu-central-1",
        "API__HOST": "127.0.0.1",
        "API__PORT": "5050",
    }
    settings = Settings.from_env(env=env, env_file=".missing.env")

    assert settings.db.url == "postgres://nested/db"
    assert settings.db.pool_maxconn == 11
    assert settings.aws.regions == ["us-east-2", "eu-central-1"]
    assert settings.api.host == "127.0.0.1"
    assert settings.api.port == 5050


def test_settings_invalid_pool_size_raises_validation_error() -> None:
    """Invalid constrained values should fail schema validation."""
    env = {"DB_POOL_MAXCONN": "0"}

    with pytest.raises(ValidationError):
        Settings.from_env(env=env, env_file=".missing.env")


def test_settings_invalid_api_version_falls_back_to_v1() -> None:
    """Invalid API version values should normalize to v1 for compatibility."""
    settings = Settings.from_env(env={"API_VERSION": "latest"}, env_file=".missing.env")
    assert settings.api.version == "v1"


def test_get_settings_reload_rebuilds_cache(monkeypatch: Any) -> None:
    """Reload should rebuild cached settings from current process env."""
    clear_settings_cache()
    monkeypatch.setenv("DB_URL", "postgres://first/db")
    first = get_settings(reload=True)

    monkeypatch.setenv("DB_URL", "postgres://second/db")
    second = get_settings(reload=True)

    assert first.db.url == "postgres://first/db"
    assert second.db.url == "postgres://second/db"
