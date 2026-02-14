"""Compatibility wrapper for debug ingest helper."""

from __future__ import annotations

import runpy


def main() -> None:
    """Execute the worker debug helper module as a script."""
    runpy.run_module("apps.worker.debug_ingest", run_name="__main__")


if __name__ == "__main__":
    main()
