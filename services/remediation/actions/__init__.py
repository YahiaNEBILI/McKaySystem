"""Built-in remediation actions.

Import modules here so registration works in static contexts.
"""

from services.remediation.actions import ec2_stop as _ec2_stop
from services.remediation.actions import noop as _noop
from services.remediation.actions import snapshot_delete as _snapshot_delete

__all__ = ["_noop", "_ec2_stop", "_snapshot_delete"]
