# pipeline/correlation/ruleset.py
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from pipeline.correlation.engine import CorrelationRule, load_rule_sql


@dataclass(frozen=True)
class RuleSetConfig:
    """
    Ruleset configuration.

    - rules_dir: directory containing *.sql files
    - allow_rule_ids: if set, only these rule_ids are enabled
    - deny_rule_ids: if set, these rule_ids are disabled
    """
    rules_dir: str = "pipeline/correlation/rules"
    allow_rule_ids: Optional[Sequence[str]] = None
    deny_rule_ids: Optional[Sequence[str]] = None


@dataclass(frozen=True)
class RuleSpec:
    """
    Declarative mapping for one SQL rule file.

    We keep rule_id & name here for stability, but we also allow SQL header comments:
      -- rule_id: ...
      -- name: ...
      -- REQUIRED CHECK IDS for this rule:
      --   <check_id>
    """
    filename: str
    rule_id: str
    name: str
    enabled: bool = True


# Keep ordering deterministic (important for predictable outputs / tests)
RULE_SPECS: Tuple[RuleSpec, ...] = (
    RuleSpec(
        filename="aws_backup_vault_risk.sql",
        rule_id="aws.backup.correlation.vault_risk",
        name="AWS Backup vault risk (correlated)",
        enabled=True,
    ),
)


def build_rules(cfg: RuleSetConfig | None = None) -> List[CorrelationRule]:
    """
    Build enabled correlation rules.

    required_check_ids are parsed from the SQL header block so the rule remains
    self-contained. This is important for:
      - scalability (engine pre-filters findings)
      - correctness (no mismatch between SQL and Python)
    """
    cfg = cfg or RuleSetConfig()

    allow = set(cfg.allow_rule_ids or [])
    deny = set(cfg.deny_rule_ids or [])

    rules: List[CorrelationRule] = []
    for spec in RULE_SPECS:
        sql_path = Path(cfg.rules_dir) / spec.filename
        sql_text = load_rule_sql(str(sql_path))

        meta = _parse_sql_header_metadata(sql_text)

        rule_id = meta.get("rule_id") or spec.rule_id
        name = meta.get("name") or spec.name
        required_check_ids = _parse_required_check_ids(sql_text)

        enabled = spec.enabled
        if allow and rule_id not in allow:
            enabled = False
        if deny and rule_id in deny:
            enabled = False

        rules.append(
            CorrelationRule(
                rule_id=rule_id,
                name=name,
                required_check_ids=tuple(required_check_ids),
                sql=sql_text,
                enabled=enabled,
            )
        )

    return rules


_META_LINE_RE = re.compile(
    r"^--\s*(?P<key>[a-zA-Z_][a-zA-Z0-9_\- ]*)\s*:\s*(?P<value>.+?)\s*$"
)


def _parse_sql_header_metadata(sql_text: str) -> Dict[str, str]:
    """
    Parse simple header metadata lines like:
      -- rule_id: foo
      -- name: Bar
    """
    meta: Dict[str, str] = {}
    for line in sql_text.splitlines()[:50]:
        m = _META_LINE_RE.match(line.strip())
        if not m:
            continue
        key = m.group("key").strip().lower()
        value = m.group("value").strip()
        if key and value:
            meta[key] = value
    return meta


def _parse_required_check_ids(sql_text: str) -> Sequence[str]:
    """
    Parse the 'REQUIRED CHECK IDS' block from SQL comments.

    Accepted formats:

      -- REQUIRED CHECK IDS for this rule:
      --   a.b.c
      --   d.e.f

    or

      -- REQUIRED CHECK IDS:
      -- - a.b.c
      -- - d.e.f
    """
    lines = sql_text.splitlines()

    start = None
    for idx, line in enumerate(lines[:200]):  # only scan top of file
        if "REQUIRED CHECK IDS" in line.upper():
            start = idx + 1
            break
    if start is None:
        return ()

    check_ids: List[str] = []
    for line in lines[start : start + 80]:
        stripped = line.strip()

        # Stop once we reach real SQL after collecting at least one ID
        if not stripped.startswith("--"):
            if check_ids:
                break
            continue

        # remove comment prefix
        content = stripped[2:].strip()

        # tolerate bullets
        content = content.lstrip("-").strip()

        if not content:
            if check_ids:
                break
            continue

        # stop on obvious end of block
        if content.upper().startswith(("WITH", "SELECT", "CREATE")):
            break

        # basic validation: allow dot-separated ids, no spaces
        if "." in content and " " not in content:
            check_ids.append(content)

    # de-dupe while preserving order
    seen = set()
    out: List[str] = []
    for cid in check_ids:
        if cid in seen:
            continue
        seen.add(cid)
        out.append(cid)
    return tuple(out)
