"""Pylint ratchet guard for CI.

This script enforces that pylint message count does not regress beyond a
committed baseline.
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


def _write_baseline(
    path: Path,
    *,
    max_messages: int,
    paths: list[str],
    symbol_max_messages: dict[str, int] | None = None,
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
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _top_symbols(messages: list[dict[str, Any]], *, limit: int = 10) -> list[tuple[str, int]]:
    counts = Counter(str(msg.get("symbol") or "unknown") for msg in messages)
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
    messages = _run_pylint(paths)
    current = len(messages)
    symbol_counts = Counter(str(msg.get("symbol") or "unknown") for msg in messages)

    if args.update_baseline:
        updated_symbols = {
            symbol: int(symbol_counts.get(symbol, 0))
            for symbol in symbol_limits
        }
        _write_baseline(
            baseline_path,
            max_messages=current,
            paths=paths,
            symbol_max_messages=updated_symbols or None,
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

    for symbol, limit in sorted(symbol_limits.items()):
        current_symbol = int(symbol_counts.get(symbol, 0))
        print(f"[pylint-ratchet] symbol: {symbol} baseline={limit} current={current_symbol}")
        if current_symbol > limit:
            print(
                "[pylint-ratchet] FAIL: pylint symbol regression detected for "
                f"{symbol!r}. Reduce findings or refresh baseline intentionally."
            )
            return 1

    print("[pylint-ratchet] PASS: no regression.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
