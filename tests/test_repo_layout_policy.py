"""Tests for repository layout policy enforcement."""

from __future__ import annotations

from pathlib import Path

from tools.repo.check_layout import list_unexpected_root_entries


def test_layout_policy_passes_for_current_repo() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    assert list_unexpected_root_entries(repo_root) == []


def test_layout_policy_detects_unexpected_entry(tmp_path: Path) -> None:
    # Minimal policy-compliant root subset for this isolated test.
    (tmp_path / "apps").mkdir()
    (tmp_path / "docs").mkdir()
    (tmp_path / "tests").mkdir()
    (tmp_path / "tools").mkdir()
    (tmp_path / "README.md").write_text("x", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text("x", encoding="utf-8")

    # Introduce a policy violation.
    (tmp_path / "random_file.txt").write_text("x", encoding="utf-8")

    violations = list_unexpected_root_entries(tmp_path)
    assert violations == ["random_file.txt"]
