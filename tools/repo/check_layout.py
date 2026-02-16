"""Validate root-level repository layout against policy."""

from __future__ import annotations

import argparse
from pathlib import Path

ROOT_ALLOWED = {
    ".git",
    ".github",
    ".gitignore",
    "AGENTS.md",
    "LICENSE",
    "Makefile",
    "README.md",
    "__init__.py",
    "apps",
    "checks",
    "contracts",
    "deploy",
    "docs",
    "infra",
    "migrations",
    "pipeline",
    "pyproject.toml",
    "pytest.ini",
    "services",
    "tests",
    "tools",
    "version.py",
}

ROOT_IGNORED_PREFIXES = (
    ".hypothesis",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "__pycache__",
)


def list_unexpected_root_entries(repo_root: Path) -> list[str]:
    """Return sorted root entries that violate the structure policy."""
    unexpected: list[str] = []
    for entry in repo_root.iterdir():
        name = entry.name
        if any(name.startswith(prefix) for prefix in ROOT_IGNORED_PREFIXES):
            continue
        if name not in ROOT_ALLOWED:
            unexpected.append(name)
    return sorted(unexpected)


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint."""
    parser = argparse.ArgumentParser(description="Check root layout policy.")
    parser.add_argument(
        "--repo-root",
        default=str(Path(__file__).resolve().parents[2]),
        help="Repository root path (default: auto-detected).",
    )
    args = parser.parse_args(argv)

    repo_root = Path(args.repo_root).resolve()
    violations = list_unexpected_root_entries(repo_root)
    if not violations:
        print("OK: repository root layout matches policy.")
        return 0

    print("ERROR: unexpected root-level entries found:")
    for name in violations:
        print(f"- {name}")
    print("Move these under apps/, tools/, docs/, or another owned subtree.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
