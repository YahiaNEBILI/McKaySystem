"""Flask API Blueprints package.

This package contains Flask Blueprint modules for each API domain:
- health: Health check and metadata endpoints
- runs: Run management endpoints
- findings: Finding query and management endpoints
- recommendations: Recommendation endpoints
- teams: Team management endpoints
- sla_policies: SLA policy management endpoints
- lifecycle: Finding lifecycle action endpoints
- remediations: Remediation action approval/list endpoints
- groups: Finding group endpoints
- facets: Facets and audit endpoints
"""

# Import blueprints for convenient registration
from apps.flask_api.blueprints.facets import facets_bp
from apps.flask_api.blueprints.findings import findings_bp
from apps.flask_api.blueprints.groups import groups_bp
from apps.flask_api.blueprints.health import health_bp
from apps.flask_api.blueprints.lifecycle import lifecycle_bp
from apps.flask_api.blueprints.recommendations import recommendations_bp
from apps.flask_api.blueprints.remediations import remediations_bp
from apps.flask_api.blueprints.runs import runs_bp
from apps.flask_api.blueprints.sla_policies import sla_policies_bp
from apps.flask_api.blueprints.teams import teams_bp

__all__ = [
    "health_bp",
    "runs_bp",
    "findings_bp",
    "recommendations_bp",
    "teams_bp",
    "sla_policies_bp",
    "lifecycle_bp",
    "remediations_bp",
    "groups_bp",
    "facets_bp",
]
