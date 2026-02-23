"""Pylint ratchet guard for CI.

This script enforces that pylint debt does not regress beyond a committed
baseline by checking:
- total message count
- per-symbol message caps
- optional new-symbol detection
- optional per-path message caps
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any


def _load_baseline(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"Missing baseline file: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def _run_pylint(paths: list[str]) -> list[dict[str, Any]]:
    cmd = [
        sys.executable,
        "-m",
        "pylint",
        *paths,
        "--score=n",
        "-f",
        "json",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    stdout = proc.stdout.strip()
    if not stdout:
        return []
    return json.loads(stdout)


def _normalize_path(path: str) -> str:
    """Normalize filesystem paths for stable prefix matching across platforms."""
    return path.replace("\\", "/").lstrip("./").lower()


def _count_symbols(messages: list[dict[str, Any]]) -> Counter[str]:
    """Count pylint messages by symbol."""
    return Counter(str(msg.get("symbol") or "unknown") for msg in messages)


def _count_paths_by_prefix(
    messages: list[dict[str, Any]],
    *,
    limits: dict[str, int],
) -> dict[str, int]:
    """Count messages matched under each configured path prefix.

    Prefixes are matched on normalized, lower-cased paths and use longest-prefix
    match when overlaps exist.
    """
    normalized_limits = {
        prefix: _normalize_path(prefix).rstrip("/")
        for prefix in limits
    }
    ordered_prefixes = sorted(
        normalized_limits.items(),
        key=lambda item: len(item[1]),
        reverse=True,
    )
    counts = {prefix: 0 for prefix in limits}
    for msg in messages:
        raw_path = str(msg.get("path") or "")
        current = _normalize_path(raw_path)
        for original_prefix, normalized_prefix in ordered_prefixes:
            if current == normalized_prefix or current.startswith(normalized_prefix + "/"):
                counts[original_prefix] += 1
                break
    return counts


def _write_baseline(
    path: Path,
    *,
    max_messages: int,
    paths: list[str],
    symbol_max_messages: dict[str, int] | None = None,
    path_max_messages: dict[str, int] | None = None,
    fail_on_new_symbols: bool | None = None,
) -> None:
    payload = {
        "max_messages": int(max_messages),
        "paths": paths,
    }
    if symbol_max_messages:
        payload["symbol_max_messages"] = {
            str(k): int(v)
            for k, v in symbol_max_messages.items()
        }
    if path_max_messages:
        payload["path_max_messages"] = {
            str(k): int(v)
            for k, v in path_max_messages.items()
        }
    if fail_on_new_symbols is not None:
        payload["fail_on_new_symbols"] = bool(fail_on_new_symbols)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _top_symbols(messages: list[dict[str, Any]], *, limit: int = 10) -> list[tuple[str, int]]:
    counts = _count_symbols(messages)
    return counts.most_common(limit)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Fail CI when pylint message count regresses.")
    parser.add_argument(
        "--baseline",
        default="tools/ci/pylint_baseline.json",
        help="Path to baseline JSON file.",
    )
    parser.add_argument(
        "--update-baseline",
        action="store_true",
        help="Rewrite baseline with current count and exit 0.",
    )
    args = parser.parse_args(argv)

    baseline_path = Path(args.baseline)
    baseline = _load_baseline(baseline_path)

    paths = [str(p) for p in baseline.get("paths", []) if str(p).strip()]
    if not paths:
        raise ValueError("Baseline must include non-empty 'paths'.")

    max_messages = int(baseline.get("max_messages", 0))
    symbol_limits = {
        str(k): int(v)
        for k, v in dict(baseline.get("symbol_max_messages", {})).items()
    }
    path_limits = {
        str(k): int(v)
        for k, v in dict(baseline.get("path_max_messages", {})).items()
    }
    fail_on_new_symbols = bool(baseline.get("fail_on_new_symbols", False))
    messages = _run_pylint(paths)
    current = len(messages)
    symbol_counts = _count_symbols(messages)
    path_counts = _count_paths_by_prefix(messages, limits=path_limits) if path_limits else {}

    if args.update_baseline:
        updated_symbols = {
            symbol: int(symbol_counts.get(symbol, 0))
            for symbol in symbol_limits
        }
        updated_paths = {
            prefix: int(path_counts.get(prefix, 0))
            for prefix in path_limits
        }
        _write_baseline(
            baseline_path,
            max_messages=current,
            paths=paths,
            symbol_max_messages=updated_symbols or None,
            path_max_messages=updated_paths or None,
            fail_on_new_symbols=fail_on_new_symbols,
        )
        print(f"[pylint-ratchet] baseline updated: {baseline_path} max_messages={current}")
        return 0

    print(f"[pylint-ratchet] baseline={max_messages} current={current}")
    for symbol, count in _top_symbols(messages):
        print(f"[pylint-ratchet] top: {symbol}={count}")

    if current > max_messages:
        print(
            "[pylint-ratchet] FAIL: pylint regression detected. "
            "Reduce messages or refresh baseline intentionally."
        )
        return 1

    if fail_on_new_symbols:
        unknown_symbols = sorted(symbol for symbol in symbol_counts if symbol not in symbol_limits)
        if unknown_symbols:
            print(
                "[pylint-ratchet] FAIL: new pylint symbols detected without baseline limits: "
                + ", ".join(unknown_symbols)
            )
            return 1

    for symbol, limit in sorted(symbol_limits.items()):
        current_symbol = int(symbol_counts.get(symbol, 0))
        print(f"[pylint-ratchet] symbol: {symbol} baseline={limit} current={current_symbol}")
        if current_symbol > limit:
            print(
                "[pylint-ratchet] FAIL: pylint symbol regression detected for "
                f"{symbol!r}. Reduce findings or refresh baseline intentionally."
            )
            return 1

    for prefix, limit in sorted(path_limits.items()):
        current_path = int(path_counts.get(prefix, 0))
        print(f"[pylint-ratchet] path: {prefix} baseline={limit} current={current_path}")
        if current_path > limit:
            print(
                "[pylint-ratchet] FAIL: pylint path regression detected for "
                f"{prefix!r}. Reduce findings or refresh baseline intentionally."
            )
            return 1

    print("[pylint-ratchet] PASS: no regression.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
