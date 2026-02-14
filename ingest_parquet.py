"""Compatibility wrapper for worker Parquet ingest entrypoint."""

from apps.worker.ingest_parquet import DbApi, IngestStats, ingest_from_manifest, main

__all__ = ["DbApi", "IngestStats", "ingest_from_manifest", "main"]


if __name__ == "__main__":
    main()
