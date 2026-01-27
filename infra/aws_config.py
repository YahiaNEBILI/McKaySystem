"""AWS SDK configuration for the engine.

The runner and service factory import from this module to keep AWS/client tuning
in one place.

Configuration knobs you are expected to edit:
- :data:`AWS_REGIONS` controls which AWS regions the runner will iterate over.
"""

from botocore.config import Config

SDK_CONFIG = Config(
    retries={"max_attempts": 10, "mode": "adaptive"},
    user_agent_extra="finopsanalyzer/0.1.0",
    connect_timeout=5,
    read_timeout=60,
)

AWS_REGIONS = ["eu-west-1", "eu-west-2",  "eu-west-3", "us-east-1", "us-east-2", "us-west-1", "eu-central-1"]
