from botocore.config import Config

SDK_CONFIG = Config(
    retries={"max_attempts": 10, "mode": "adaptive"},
    user_agent_extra="finopsanalyzer/0.1.0",
    connect_timeout=5,
    read_timeout=60,
)

AWS_REGIONS = ["eu-west-3", "eu-west-1"]