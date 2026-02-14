"""Compatibility wrapper for legacy exported JSON ingest entrypoint."""

from apps.worker.ingest_exported_json import ingest_latest_export, main

__all__ = ["ingest_latest_export", "main"]


if __name__ == "__main__":
    main()
