"""Project version constants.

These constants are used in logs and embedded in produced datasets (Parquet) so
that exported artifacts can be traced back to a specific engine/ruleset/schema
version.
"""

ENGINE_NAME: str = "finopsanalyzer"
ENGINE_VERSION: str = "0.1.0"

RULEPACK_VERSION: str = "0.1.0"
SCHEMA_VERSION: int = 1
