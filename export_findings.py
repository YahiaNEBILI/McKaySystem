"""Compatibility wrapper for worker JSON export entrypoint."""

from apps.worker.export_findings import main

__all__ = ["main"]


if __name__ == "__main__":
    main()
