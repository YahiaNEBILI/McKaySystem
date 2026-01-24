"""
pipeline/correlation/engine.py

Scalable correlation engine for McKaySystem / FinOpsAnalyzer-style pipelines.

Design goals
------------
- Operate on Parquet (not JSON) and use DuckDB for set-based correlation.
- Never mutate raw findings; emit *meta-findings* that are first-class rows
  in the same FINOPS_FINDINGS_SCHEMA.
- Rule-driven: rules declare required_check_ids (for scan reduction) and a SQL
  query that returns "wire-format" findings (dict-like) ready for contract IDs
  and parquet write.
- Future-proof: add rules by dropping new SQL specs; engine stays stable.

How to use
----------
1) You already have raw findings written to Parquet:
     data/finops_findings/**/*.parquet

2) Create correlation rules (SQL) that SELECT rows shaped like a finding record.
   Rule SQL should return at least:
     - tenant_id
     - workspace_id
     - run_id
     - run_ts
     - engine_name, engine_version, rulepack_version
     - scope (STRUCT with FINOPS scope fields)
     - check_id, check_name, category, status, severity (STRUCT)
     - title, message, recommendation
     - source (STRUCT with schema_version etc.)
   You may omit some optional fields; the engine will fill safe defaults.

3) Run correlation engine to write correlated findings parquet:
     engine.run(cfg)

Notes on performance
--------------------
- DuckDB will apply projection + predicate pushdown into Parquet scans.
- Each rule pre-filters the dataset by check_id IN required_check_ids to avoid
  scanning irrelevant row groups.
- The engine streams DuckDB results in batches (fetchmany) and writes to Parquet
  using FindingsParquetWriter (typed + partitioned).

IMPORTANT DuckDB compatibility note
-----------------------------------
DuckDB does not allow prepared parameters in certain DDL statements (e.g. CREATE VIEW).
Therefore this engine avoids passing parameters into CREATE VIEW and instead:
- escapes literals for view definitions (tenant/workspace/run + parquet glob)
- materializes rule required_check_ids into a TEMP table and joins
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence

import duckdb

from contracts.finops_contracts import build_ids_and_validate, normalize_str
from pipeline.writer_parquet import ParquetWriterConfig, FindingsParquetWriter

from .contracts import CorrelationRule


class CorrelationError(RuntimeError):
    """Raised when correlation execution fails."""


# -------------------------------
# Config + rule specs
# -------------------------------


@dataclass(frozen=True)
class CorrelationConfig:
    """
    Configuration for correlation execution.

    findings_glob:
      - Parquet dataset glob, e.g. "data/finops_findings/**/*.parquet"
      - Should be unionable by name (writer uses stable schema)

    out_dir:
      - Where correlated findings will be written as Parquet (same schema)
      - You can point this to the same base_dir as raw findings if you want the
        meta-findings to live alongside raw findings, or to a separate dataset
        (recommended initially for safety).
    """
    findings_glob: str
    tenant_id: str
    out_dir: str

    # Optional filtering (keep correlation tight and fast)
    workspace_id: str = ""
    run_id: str = ""  # if set, correlate one run only

    # DuckDB knobs
    threads: int = 4

    # Writing knobs
    compression: str = "zstd"
    max_rows_per_file: int = 200_000
    max_buffered_rows: int = 50_000

    # Contract knobs
    finding_id_salt: Optional[str] = None  # if you want per-run/per-day salt, pass it here

    # Safety
    fail_fast: bool = True  # if False, keep going on rule failures and record errors


@dataclass
class CorrelationStats:
    rules_total: int = 0
    rules_enabled: int = 0
    emitted: int = 0
    emitted_by_rule: Dict[str, int] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)


# -------------------------------
# Engine
# -------------------------------


class CorrelationEngine:
    """
    Rule-driven correlation engine.

    Produces *meta-findings* as standard FINOPS findings and writes them to Parquet.
    """

    def __init__(self, rules: Sequence[CorrelationRule]) -> None:
        self._rules = list(rules)

    def run(self, cfg: CorrelationConfig) -> CorrelationStats:
        stats = CorrelationStats(rules_total=len(self._rules))
        enabled_rules = [r for r in self._rules if r.enabled]
        stats.rules_enabled = len(enabled_rules)

        if not enabled_rules:
            return stats

        # Ensure output directory exists
        Path(cfg.out_dir).mkdir(parents=True, exist_ok=True)

        writer: FindingsParquetWriter | None = None

        con = duckdb.connect(database=":memory:")
        try:
            con.execute(f"PRAGMA threads={int(cfg.threads)};")
            con.execute("PRAGMA enable_progress_bar=false;")

            # 1) Raw findings view (avoid prepared params in DDL)
            glob_escaped = str(cfg.findings_glob).replace("'", "''")
            con.execute(
                f"""
                CREATE OR REPLACE VIEW findings_raw AS
                SELECT *
                FROM read_parquet('{glob_escaped}', union_by_name=true)
                """
            )

            # 2) Base filter view (avoid prepared params in DDL)
            tenant_escaped = str(cfg.tenant_id).replace("'", "''")
            workspace_escaped = str(cfg.workspace_id or "").replace("'", "''")
            run_id_escaped = str(cfg.run_id or "").replace("'", "''")

            where_parts = [f"tenant_id = '{tenant_escaped}'"]
            if workspace_escaped:
                where_parts.append(f"workspace_id = '{workspace_escaped}'")
            if run_id_escaped:
                where_parts.append(f"run_id = '{run_id_escaped}'")
            where_sql = " AND ".join(where_parts)

            con.execute(
                f"""
                CREATE OR REPLACE VIEW findings_base AS
                SELECT *
                FROM findings_raw
                WHERE {where_sql}
                """
            )

            # 3) Writer for meta-findings
            writer = FindingsParquetWriter(
                ParquetWriterConfig(
                    base_dir=cfg.out_dir,
                    compression=cfg.compression,
                    max_rows_per_file=cfg.max_rows_per_file,
                    max_buffered_rows=cfg.max_buffered_rows,
                    drop_invalid_on_cast=False,
                )
            )

            # 4) Apply each rule
            for rule in enabled_rules:
                try:
                    emitted = self._apply_rule(con, writer, rule, cfg)
                    stats.emitted += emitted
                    stats.emitted_by_rule[rule.rule_id] = emitted
                except Exception as exc:  # pylint: disable=broad-except
                    msg = f"[{rule.rule_id}] {exc}"
                    stats.errors.append(msg)
                    if cfg.fail_fast:
                        raise CorrelationError(msg) from exc
            return stats

        finally:
            if writer is not None:
                writer.close()
            con.close()


    @staticmethod
    def _strip_sql_comments(sql: str) -> str:
        """
        Remove line comments (--) and trim whitespace.
        This is a lightweight guard, not a full SQL parser.
        """
        lines: List[str] = []
        for line in sql.splitlines():
            s = line.strip()
            if s.startswith("--"):
                continue
            lines.append(line)
        return "\n".join(lines).strip()

    @classmethod
    def _normalize_single_statement(cls, sql: str) -> str:
        """
        Ensure the rule SQL is a single statement.

        Allowed:
          - semicolons inside string literals
          - semicolons inside comments
          - one or more trailing semicolons at the very end (common copy/paste)

        Rejected:
          - any semicolon that appears outside comments/strings (multi-statement)
        """
        if sql is None:
            raise CorrelationError("Rule SQL is empty")

        cleaned = sql.strip()
        if not cleaned:
            raise CorrelationError("Rule SQL is empty")

        # Strip trailing semicolons (and trailing whitespace) only.
        cleaned = cleaned.rstrip()
        while cleaned.endswith(";"):
            cleaned = cleaned[:-1].rstrip()

        # Scan for semicolons outside comments/strings (simple state machine).
        i = 0
        n = len(cleaned)
        in_squote = False
        in_line_comment = False
        in_block_comment = False

        while i < n:
            ch = cleaned[i]
            nxt = cleaned[i + 1] if i + 1 < n else ""

            if in_line_comment:
                if ch == "\n":
                    in_line_comment = False
                i += 1
                continue

            if in_block_comment:
                if ch == "*" and nxt == "/":
                    in_block_comment = False
                    i += 2
                    continue
                i += 1
                continue

            if in_squote:
                if ch == "'":
                    # handle escaped quote ''
                    if nxt == "'":
                        i += 2
                        continue
                    in_squote = False
                i += 1
                continue

            # entering comment or string?
            if ch == "-" and nxt == "-":
                in_line_comment = True
                i += 2
                continue
            if ch == "/" and nxt == "*":
                in_block_comment = True
                i += 2
                continue
            if ch == "'":
                in_squote = True
                i += 1
                continue

            if ch == ";":
                raise CorrelationError(
                    "Rule SQL must be a single statement: remove extra ';' (only trailing ';' is allowed)."
                )

            i += 1

        return cleaned

    @classmethod
    def _validate_rule_sql(cls, con: duckdb.DuckDBPyConnection, sql: str) -> str:
        """
        Validate rule SQL early to fail fast with clearer errors.

        Returns a normalized single-statement SQL string.
        """
        normalized = cls._normalize_single_statement(sql)
        # EXPLAIN is cheap and catches parser/binder errors early.
        con.execute("EXPLAIN " + normalized)
        return normalized

    # -------------------------------
    # Internals
    # -------------------------------

    def _apply_rule(
        self,
        con: duckdb.DuckDBPyConnection,
        writer: FindingsParquetWriter,
        rule: CorrelationRule,
        cfg: CorrelationConfig,
    ) -> int:
        """
        Execute one rule and write emitted meta-findings.
        Returns emitted count.
        """
        required = [normalize_str(x, lower=False) for x in rule.required_check_ids if str(x).strip()]
        if not required:
            # If a rule declares nothing, it risks scanning everything. Block it.
            raise CorrelationError("required_check_ids is empty; add `-- required_check_ids: ...` to the SQL rule header to avoid scanning the full dataset")

        # Pre-filter to reduce parquet scan cost.
        # DuckDB does not allow prepared parameters in CREATE VIEW statements,
        # so we materialize required check_ids into a temporary table and join.
        con.execute("DROP TABLE IF EXISTS tmp_required_check_ids")
        con.execute("CREATE TEMP TABLE tmp_required_check_ids(check_id VARCHAR)")
        con.executemany(
            "INSERT INTO tmp_required_check_ids VALUES (?)",
            [(x,) for x in required],
        )
        con.execute(
            """
            CREATE OR REPLACE TEMP VIEW rule_input AS
            SELECT b.*
            FROM findings_base b
            INNER JOIN tmp_required_check_ids r
              ON b.check_id = r.check_id
            """
        )

        sql = self._validate_rule_sql(con, rule.sql)

        cur = con.execute(sql)

        cols = [d[0] for d in cur.description]
        if not cols:
            return 0

        emitted = 0
        now_ts = datetime.now(timezone.utc)

        # Stream results (don't fetchall on huge result sets)
        while True:
            rows = cur.fetchmany(10_000)
            if not rows:
                break

            wire_findings: List[Dict[str, Any]] = []
            for row in rows:
                rec = dict(zip(cols, row))
                wire = self._finalize_wire_meta_finding(
                    raw=rec,
                    rule=rule,
                    cfg=cfg,
                    now_ts=now_ts,
                )
                wire_findings.append(wire)

            writer.extend(wire_findings)
            emitted += len(wire_findings)

        return emitted

    def _finalize_wire_meta_finding(
        self,
        *,
        raw: Dict[str, Any],
        rule: CorrelationRule,
        cfg: CorrelationConfig,
        now_ts: datetime,
    ) -> Dict[str, Any]:
        """
        Take a row returned by rule SQL and:
          - fill safe defaults for optional fields
          - build issue_key from source fingerprints (if present) for deterministic identity
          - build fingerprint + finding_id + validate using contract
        """
        tenant_id = normalize_str(raw.get("tenant_id") or cfg.tenant_id, lower=False)
        workspace_id = normalize_str(raw.get("workspace_id") or cfg.workspace_id, lower=False)
        run_id = normalize_str(raw.get("run_id") or cfg.run_id, lower=False)

        run_ts = raw.get("run_ts") or now_ts
        ingested_ts = now_ts

        engine_name = raw.get("engine_name") or "mckay"
        engine_version = raw.get("engine_version") or ""
        rulepack_version = raw.get("rulepack_version") or ""

        check_id = raw.get("check_id") or f"correlation.{rule.rule_id}"
        check_name = raw.get("check_name") or rule.name
        category = raw.get("category") or "governance"
        sub_category = raw.get("sub_category") or ""
        frameworks = raw.get("frameworks") or ["FinOps"]

        status = normalize_str(raw.get("status") or "fail", lower=True)

        severity = raw.get("severity")
        if not severity:
            severity = {"level": "medium", "score": 700}

        title = raw.get("title") or f"Correlated signal: {rule.name}"
        message = raw.get("message") or ""
        recommendation = raw.get("recommendation") or ""

        remediation = raw.get("remediation") or ""
        links = raw.get("links") or []

        estimated = raw.get("estimated")
        if not estimated:
            estimated = {
                "monthly_savings": None,
                "monthly_cost": None,
                "one_time_savings": None,
                "confidence": 0,
                "notes": "Correlated meta-finding.",
            }

        actual = raw.get("actual") or None
        lifecycle = raw.get("lifecycle") or None

        tags = raw.get("tags") or {}
        labels = raw.get("labels") or {}
        dimensions = raw.get("dimensions") or {}
        metrics = raw.get("metrics") or {}
        metadata_json = raw.get("metadata_json") or ""

        scope = raw.get("scope")
        if not isinstance(scope, Mapping):
            raise CorrelationError(
                f"Rule '{rule.rule_id}' returned no valid scope; SQL must select an anchor scope struct"
            )

        source = raw.get("source") or {
            "source_type": "scanner",
            "source_ref": f"correlation:{rule.rule_id}",
            "schema_version": 1,
        }

        issue_key = self._build_issue_key_for_correlation(raw, rule)

        wire: Dict[str, Any] = {
            "tenant_id": tenant_id,
            "workspace_id": workspace_id,
            "run_id": run_id,
            "run_ts": run_ts,
            "ingested_ts": ingested_ts,
            "engine_name": engine_name,
            "engine_version": engine_version,
            "rulepack_version": rulepack_version,
            "scope": dict(scope),
            "check_id": str(check_id),
            "check_name": str(check_name),
            "category": str(category),
            "sub_category": str(sub_category),
            "frameworks": list(frameworks) if isinstance(frameworks, (list, tuple)) else [str(frameworks)],
            "status": status,
            "severity": dict(severity) if isinstance(severity, Mapping) else severity,
            "priority": raw.get("priority") or 0,
            "title": str(title),
            "message": str(message),
            "recommendation": str(recommendation),
            "remediation": str(remediation),
            "links": list(links) if isinstance(links, list) else [],
            "estimated": dict(estimated) if isinstance(estimated, Mapping) else estimated,
            "actual": actual,
            "lifecycle": lifecycle,
            "tags": dict(tags) if isinstance(tags, Mapping) else {},
            "labels": dict(labels) if isinstance(labels, Mapping) else {},
            "dimensions": dict(dimensions) if isinstance(dimensions, Mapping) else {},
            "metrics": dict(metrics) if isinstance(metrics, Mapping) else {},
            "metadata_json": str(metadata_json),
            "source": dict(source) if isinstance(source, Mapping) else source,
        }

        build_ids_and_validate(
            wire,
            issue_key=issue_key,
            finding_id_salt=cfg.finding_id_salt,
        )

        return wire

    @staticmethod
    def _build_issue_key_for_correlation(raw: Mapping[str, Any], rule: CorrelationRule) -> Dict[str, Any]:
        """
        Build issue_key for deterministic fingerprinting.

        Expected optional SQL output fields:
          - source_fingerprints: LIST(VARCHAR) OR
          - source_fingerprint: VARCHAR OR
          - anchor_fingerprint: VARCHAR

        If none are present, we still build a key with just rule_id, but dedup stability
        depends on scope-only changes.
        """
        sources: List[str] = []

        if "source_fingerprints" in raw and raw["source_fingerprints"] is not None:
            val = raw["source_fingerprints"]
            if isinstance(val, list):
                sources = [str(x) for x in val if str(x).strip()]
            else:
                try:
                    sources = [str(x) for x in list(val) if str(x).strip()]
                except Exception:  # pragma: no cover
                    sources = []

        if not sources and "source_fingerprint" in raw and raw["source_fingerprint"]:
            sources = [str(raw["source_fingerprint"])]

        if not sources and "anchor_fingerprint" in raw and raw["anchor_fingerprint"]:
            sources = [str(raw["anchor_fingerprint"])]

        sources = sorted(set(sources))

        return {
            "rule_id": rule.rule_id,
            "sources": ",".join(sources),
        }


def load_rule_sql(path: str) -> str:
    p = Path(path)
    return p.read_text(encoding="utf-8")
