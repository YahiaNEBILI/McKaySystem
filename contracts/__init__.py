"""Contracts and canonical schema.

The contracts package defines:
- the canonical Arrow schema used for storage
- wire-format validation and canonicalization
- helper types used by checkers and the runner
- Protocol definitions for dependency injection
- TypedDict definitions for wire formats

Main exports:
- RunContext, Scope, Severity, FindingDraft, Checker, CheckerRunner
- build_finding_record, build_ids_and_validate, ValidationError
- Protocol definitions for AWS services and storage
- TypedDict definitions for API contracts
"""

from contracts import finops_checker_pattern
from contracts import finops_contracts
from contracts import services as services_module

# Explicit re-exports to satisfy ruff F401
__all__ = [
    "Checker",
    "CheckerResult",
    "CheckerRunner",
    "FindingDraft",
    "RunContext",
    "Scope",
    "Severity",
    "Services",
    "ServicesFactory",
    "build_finding_record",
    "ValidationError",
    "build_ids_and_validate",
    "normalize_str",
]

# Re-export for convenience
Checker = finops_checker_pattern.Checker
CheckerResult = finops_checker_pattern.CheckerResult
CheckerRunner = finops_checker_pattern.CheckerRunner
FindingDraft = finops_checker_pattern.FindingDraft
RunContext = finops_checker_pattern.RunContext
Scope = finops_checker_pattern.Scope
Severity = finops_checker_pattern.Severity
build_finding_record = finops_checker_pattern.build_finding_record

Services = services_module.Services
ServicesFactory = services_module.ServicesFactory

ValidationError = finops_contracts.ValidationError
build_ids_and_validate = finops_contracts.build_ids_and_validate
normalize_str = finops_contracts.normalize_str

