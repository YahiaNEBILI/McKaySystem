from dataclasses import dataclass
from typing import Any

@dataclass(frozen=True)
class Services:
    s3: Any
    rds: Any
