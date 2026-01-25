"""Typed Parquet writer for FinOps findings.

This is the storage boundary: it validates records against the Arrow schema and
writes partitioned Parquet datasets. The writer is designed to be deterministic
and append-friendly.
"""

from __future__ import annotations

import os
import uuid
from dataclasses import dataclass, field
from decimal import Decimal
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Mapping, Sequence

import pyarrow as pa
import pyarrow.parquet as pq

from contracts.schema import FINOPS_FINDINGS_SCHEMA
from contracts.storage_cast import StorageCastError, cast_for_storage


class ParquetWriteError(RuntimeError):
    """Raised when Parquet writing fails."""


def _utc_today_str() -> str:
    return datetime.now(timezone.utc).date().isoformat()


def _safe_str(value: Any) -> str:
    return "" if value is None else str(value)


def _assert_money_fields_numeric(wire_record: Mapping[str, Any]) -> None:
    """Fail fast if any cost/savings fields are non-numeric.

    This is a storage-boundary guardrail (Option B): money must be numeric (int/float/Decimal) or None.
    """

    def _is_money(v: Any) -> bool:
        return v is None or isinstance(v, (int, float, Decimal)) and not isinstance(v, bool)

    for path, obj, keys in (
        ("estimated", wire_record.get("estimated"), ("monthly_savings", "monthly_cost", "one_time_savings")),
        ("actual", wire_record.get("actual"), ("cost_7d", "cost_30d", "cost_mtd", "cost_prev_month", "savings_7d", "savings_30d")),
    ):
        if not isinstance(obj, Mapping):
            continue
        for k in keys:
            if k not in obj:
                continue
            v = obj.get(k)
            if not _is_money(v):
                raise ParquetWriteError(
                    f"Money field must be numeric or None: {path}.{k}={v!r} ({type(v).__name__}) "
                    f"check_id={wire_record.get('check_id')!r}"
                )


@dataclass
class ParquetWriterConfig:
    """
    Writer config for a SaaS-grade Parquet layout.
    """
    base_dir: str
    schema: pa.Schema = FINOPS_FINDINGS_SCHEMA

    # Partitioning layout (directory-style partitions)
    partition_tenant_field: str = "tenant_id"
    partition_date_field: str = "run_date"  # derived from run_ts

    # Write behavior
    compression: str = "zstd"
    use_dictionary: bool = True

    # Batching controls
    max_rows_per_file: int = 200_000     # adjust based on row width
    max_buffered_rows: int = 200_000     # flush when reaching this

    # Error policy
    drop_invalid_on_cast: bool = False   # if True: skip records failing cast
    max_error_samples: int = 50          # keep only N errors in memory


@dataclass
class ParquetWriterStats:
    received: int = 0
    written: int = 0
    dropped_cast_errors: int = 0
    cast_errors: List[str] = field(default_factory=list)


class FindingsParquetWriter:
    """
    Writes finops_findings records to partitioned Parquet.

    Expected input: WIRE records (JSON-friendly dicts) that already passed contract validation.
    This writer enforces the STORAGE boundary by casting each record to Arrow-compatible types
    using the provided schema.

    Layout:
      {base_dir}/tenant_id=<tenant>/run_date=<YYYY-MM-DD>/part-<uuid>.parquet
    """

    def __init__(self, config: ParquetWriterConfig) -> None:
        self._cfg = config
        self._buffer: List[Dict[str, Any]] = []
        self.stats = ParquetWriterStats()

        os.makedirs(self._cfg.base_dir, exist_ok=True)

    def append(self, wire_record: Mapping[str, Any]) -> None:
        """
        Append one wire record. It will be cast to storage format and buffered.
        """
        self.stats.received += 1

        try:
            storage_record = self._cast_and_add_partition_fields(wire_record)
        except (StorageCastError, ValueError) as exc:
            if len(self.stats.cast_errors) < self._cfg.max_error_samples:
                self.stats.cast_errors.append(str(exc))
            self.stats.dropped_cast_errors += 1

            if self._cfg.drop_invalid_on_cast:
                return
            raise ParquetWriteError(f"Storage cast failed: {exc}") from exc

        self._buffer.append(storage_record)

        if len(self._buffer) >= self._cfg.max_buffered_rows:
            self.flush()

    def extend(self, wire_records: Iterable[Mapping[str, Any]]) -> None:
        """
        Append many wire records.
        """
        for rec in wire_records:
            self.append(rec)

    def flush(self) -> None:
        """
        Flush buffered storage-format records to partitioned Parquet files.
        """
        if not self._buffer:
            return

        # Group by (tenant_id, run_date) to avoid mixing partitions in one file
        groups: Dict[tuple[str, str], List[Dict[str, Any]]] = {}
        for rec in self._buffer:
            tenant = _safe_str(rec.get(self._cfg.partition_tenant_field))
            run_date = _safe_str(rec.get(self._cfg.partition_date_field)) or _utc_today_str()
            groups.setdefault((tenant, run_date), []).append(rec)

        # Clear buffer early (reduce memory peak)
        self._buffer = []

        for (tenant, run_date), rows in groups.items():
            self._write_partition_group(tenant, run_date, rows)

    def close(self) -> ParquetWriterStats:
        """
        Finalize writer (flush remaining buffered records).
        """
        self.flush()
        return self.stats

    # -------------------------
    # Internal helpers
    # -------------------------

    def _cast_and_add_partition_fields(self, wire_record: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Cast wire record to storage types and add derived partition fields (run_date).
        """
        _assert_money_fields_numeric(wire_record)
        storage = cast_for_storage(wire_record, self._cfg.schema)

        # Derive run_date from run_ts if possible; fallback to today.
        # Note: schema.py may or may not include run_date as a field.
        # If your schema doesn't include run_date, you can still partition by directory name only.
        run_ts = storage.get("run_ts")
        if isinstance(run_ts, datetime):
            run_date = run_ts.date().isoformat()
        else:
            run_date = _utc_today_str()

        storage[self._cfg.partition_date_field] = run_date
        return storage

    def _write_partition_group(self, tenant: str, run_date: str, rows: Sequence[Dict[str, Any]]) -> None:
        """
        Write a list of storage-format records into one or more Parquet files, splitting by max_rows_per_file.
        """
        # Directory-style partitions
        out_dir = os.path.join(
            self._cfg.base_dir,
            f"{self._cfg.partition_tenant_field}={tenant}",
            f"{self._cfg.partition_date_field}={run_date}",
        )
        os.makedirs(out_dir, exist_ok=True)

        # Write in chunks to control file sizes
        start = 0
        total = len(rows)
        while start < total:
            end = min(start + self._cfg.max_rows_per_file, total)
            chunk = rows[start:end]

            # If your schema does NOT include run_date, drop it before building the table.
            # If your schema DOES include it, keep it (and add it to schema.py).
            table = self._table_from_rows(chunk)

            filename = f"part-{uuid.uuid4().hex}.parquet"
            out_path = os.path.join(out_dir, filename)

            pq.write_table(
                table,
                out_path,
                compression=self._cfg.compression,
                use_dictionary=self._cfg.use_dictionary,
                write_statistics=True,
            )

            self.stats.written += len(chunk)
            start = end

    def _table_from_rows(self, rows: Sequence[Dict[str, Any]]) -> pa.Table:
        """
        Build an Arrow table from storage-format rows using the configured schema.

        If partition_date_field is not part of the schema, we drop it.
        """
        schema_field_names = set(self._cfg.schema.names)

        if self._cfg.partition_date_field not in schema_field_names:
            cleaned = [
                {k: v for k, v in row.items() if k in schema_field_names}
                for row in rows
            ]
        else:
            cleaned = list(rows)

        return pa.Table.from_pylist(cleaned, schema=self._cfg.schema)
