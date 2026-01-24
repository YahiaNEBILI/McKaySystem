from dataclasses import dataclass
from typing import Sequence

@dataclass(frozen=True)
class CorrelationRule:
    rule_id: str
    name: str
    required_check_ids: Sequence[str]
    sql: str
    enabled: bool = True