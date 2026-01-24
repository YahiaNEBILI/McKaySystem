"""
Correlation ruleset loader.

This module loads correlation rules from *.sql files stored in a directory, and
returns a list[CorrelationRule] that your CorrelationEngine already expects.

SQL header format (top of file, '--' comments):

-- rule_id: aws_backup_vault_risk
-- name: AWS Backup vault risk
-- enabled: true
-- required_check_ids: aws.backup.vaults, aws.backup.plans

Only rule_id is recommended. If missing, filename stem is used.
required_check_ids is optional; if missing, an empty list is used.

Why this exists:
- avoids hardcoding rules in Python (scales with more rules)
- keeps rule metadata close to SQL
- stable ordering for deterministic runs
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple


# ---- Keep this type identical to your engine expectation ----

@dataclass(frozen=True)
class CorrelationRule:
    """
    A correlation rule expressed as SQL.

    required_check_ids is used to pre-filter findings for scan reduction.

    The SQL runs against a view named `rule_input` (created by the engine),
    and should return 1 row == 1 *meta finding*.
    """
    rule_id: str
    name: str
    required_check_ids: Sequence[str]
    sql: str
    enabled: bool = True


# ---- SQL header parsing ----

def _parse_sql_header(sql_text: str) -> Dict[str, str]:
    """
    Parse leading SQL comment lines of the form:
      -- key: value

    Stops at the first non-comment, non-empty line.
    Keys are lowercased.
    """
    meta: Dict[str, str] = {}
    for line in sql_text.splitlines():
        s = line.strip()
        if not s:
            continue
        if not s.startswith("--"):
            break

        body = s[2:].strip()
        if ":" not in body:
            continue

        key, value = body.split(":", 1)
        meta[key.strip().lower()] = value.strip()
    return meta


def _coerce_bool(value: Optional[str], default: bool = True) -> bool:
    if value is None:
        return default
    s = value.strip().lower()
    if s in ("1", "true", "yes", "y", "on", "enabled"):
        return True
    if s in ("0", "false", "no", "n", "off", "disabled"):
        return False
    return default


def _parse_csv_list(value: str) -> Tuple[str, ...]:
    """
    Parses 'a, b, c' -> ('a','b','c')
    """
    if not value:
        return ()
    items = []
    for part in value.split(","):
        p = part.strip()
        if p:
            items.append(p)
    return tuple(items)


# ---- Public API ----

def default_rules_dir(repo_root: Path) -> Path:
    """
    Expected repository layout:
      pipeline/correlation/rules/*.sql
    """
    return repo_root / "pipeline" / "correlation" / "rules"


def load_rules_from_dir(
    rules_dir: Path,
    allow_rule_ids: Optional[Sequence[str]] = None,
    deny_rule_ids: Optional[Sequence[str]] = None,
) -> List[CorrelationRule]:
    """
    Load rules from a directory and return List[CorrelationRule] for the engine.

    - Stable ordering (by rule_id)
    - Optional allow/deny filtering
    """
    if not rules_dir.exists() or not rules_dir.is_dir():
        raise FileNotFoundError(f"Rules directory not found: {rules_dir}")

    allow = {r.strip().lower() for r in (allow_rule_ids or []) if r.strip()}
    deny = {r.strip().lower() for r in (deny_rule_ids or []) if r.strip()}

    rules: List[CorrelationRule] = []

    for sql_path in sorted(rules_dir.glob("*.sql")):
        sql_text = sql_path.read_text(encoding="utf-8")
        meta = _parse_sql_header(sql_text)

        rule_id = (meta.get("rule_id") or sql_path.stem).strip()
        if not rule_id:
            # Should never happen due to stem fallback, but keep it safe.
            continue

        rid_l = rule_id.lower()
        if allow and rid_l not in allow:
            continue
        if rid_l in deny:
            continue

        name = (meta.get("name") or rule_id).strip()
        enabled = _coerce_bool(meta.get("enabled"), True)

        required_check_ids = _parse_csv_list(meta.get("required_check_ids", ""))

        rules.append(
            CorrelationRule(
                rule_id=rule_id,
                name=name,
                required_check_ids=list(required_check_ids),
                sql=sql_text,
                enabled=enabled,
            )
        )

    # deterministic ordering (enabled rules first, then rule_id)
    rules.sort(key=lambda r: (not r.enabled, r.rule_id.lower()))
    return rules


# Backward-compatible alias if you had build_rules() before.
def build_rules(rules_dir: Path) -> List[CorrelationRule]:
    """
    Backward-compatible wrapper.
    If old code calls build_rules(...), it still works.
    """
    return load_rules_from_dir(rules_dir)
