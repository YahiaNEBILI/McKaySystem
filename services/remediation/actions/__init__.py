"""Built-in remediation actions.

Import modules here so registration works in static contexts.
"""

from services.remediation.actions import noop as _noop

__all__ = ["_noop"]
