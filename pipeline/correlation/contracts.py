"""Correlation rule contracts.

Correlation rules are expressed as single-statement SQL queries that run against
a view named ``rule_input`` created by the correlation engine.

The engine treats each returned row as one emitted *meta-finding*.
"""

from dataclasses import dataclass
from typing import Sequence



@dataclass(frozen=True)
class CorrelationRule:
    rule_id: str
    name: str
    required_check_ids: Sequence[str]
    sql: str
    enabled: bool = True