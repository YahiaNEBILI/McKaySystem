"""AWS SDK configuration for the engine.

The runner and service factory import from this module to keep AWS/client tuning
in one place.

Configuration knobs you are expected to edit:
- :data:`AWS_REGIONS` controls which AWS regions the runner will iterate over.
"""

from botocore.config import Config

from infra.config import get_settings

_SETTINGS = get_settings()
_AWS_CFG = _SETTINGS.aws

SDK_CONFIG = Config(
    retries={"max_attempts": int(_AWS_CFG.max_retries), "mode": "adaptive"},
    user_agent_extra="finopsanalyzer/0.1.0",
    connect_timeout=int(_AWS_CFG.connect_timeout),
    read_timeout=int(_AWS_CFG.timeout),
)

AWS_REGIONS = list(_AWS_CFG.regions)
