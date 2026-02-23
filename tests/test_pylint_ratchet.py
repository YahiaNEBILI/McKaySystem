"""Tests for pylint ratchet guard behavior."""

from __future__ import annotations

import json
from pathlib import Path

from tools.ci import pylint_ratchet


def _write_baseline(path: Path, payload: dict) -> Path:
    """Write a baseline payload to disk and return the file path."""
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_count_paths_by_prefix_normalizes_windows_paths() -> None:
    """Prefix counting should handle Windows separators and case consistently."""
    messages = [
        {"path": r"apps\worker\runner.py", "symbol": "line-too-long"},
        {"path": r"Apps\flask_api\flask_app.py", "symbol": "line-too-long"},
        {"path": "checks/aws/ec2_instances.py", "symbol": "unused-argument"},
    ]
    counts = pylint_ratchet._count_paths_by_prefix(
        messages,
        limits={"apps": 0, "checks": 0},
    )
    assert counts == {"apps": 2, "checks": 1}


def test_main_fails_on_new_symbols_when_enabled(tmp_path: Path, monkeypatch) -> None:
    """Ratchet should fail when a new symbol appears and strict symbol mode is on."""
    baseline_path = _write_baseline(
        tmp_path / "baseline.json",
        {
            "max_messages": 10,
            "paths": ["apps"],
            "fail_on_new_symbols": True,
            "symbol_max_messages": {"line-too-long": 10},
        },
    )
    monkeypatch.setattr(
        pylint_ratchet,
        "_run_pylint",
        lambda _paths: [{"path": "apps/a.py", "symbol": "unused-argument"}],
    )

    rc = pylint_ratchet.main(["--baseline", str(baseline_path)])
    assert rc == 1


def test_main_fails_on_path_regression(tmp_path: Path, monkeypatch) -> None:
    """Ratchet should fail when a path exceeds its configured message ceiling."""
    baseline_path = _write_baseline(
        tmp_path / "baseline.json",
        {
            "max_messages": 10,
            "paths": ["apps", "checks"],
            "symbol_max_messages": {"line-too-long": 10},
            "path_max_messages": {"apps": 1, "checks": 5},
        },
    )
    monkeypatch.setattr(
        pylint_ratchet,
        "_run_pylint",
        lambda _paths: [
            {"path": "apps/a.py", "symbol": "line-too-long"},
            {"path": "apps/b.py", "symbol": "line-too-long"},
        ],
    )

    rc = pylint_ratchet.main(["--baseline", str(baseline_path)])
    assert rc == 1


def test_main_passes_when_all_limits_hold(tmp_path: Path, monkeypatch) -> None:
    """Ratchet should pass when global, symbol, and path limits are satisfied."""
    baseline_path = _write_baseline(
        tmp_path / "baseline.json",
        {
            "max_messages": 3,
            "paths": ["apps", "checks"],
            "fail_on_new_symbols": True,
            "symbol_max_messages": {"line-too-long": 2, "unused-argument": 1},
            "path_max_messages": {"apps": 2, "checks": 1},
        },
    )
    monkeypatch.setattr(
        pylint_ratchet,
        "_run_pylint",
        lambda _paths: [
            {"path": r"apps\worker\a.py", "symbol": "line-too-long"},
            {"path": "apps/flask_api/b.py", "symbol": "line-too-long"},
            {"path": "checks/aws/c.py", "symbol": "unused-argument"},
        ],
    )

    rc = pylint_ratchet.main(["--baseline", str(baseline_path)])
    assert rc == 0
