"""Facets Blueprint.

Provides facet/distinct values endpoints for filter suggestions.
"""

from typing import Any

from flask import Blueprint, jsonify

from apps.backend.db import db_conn, fetch_all_dict_conn
from apps.flask_api.utils import _require_scope_from_query

# Create the blueprint
facets_bp = Blueprint("facets", __name__)


@facets_bp.route("/api/facets", methods=["GET"])
def api_facets() -> Any:
    """Return distinct values (with counts) for common filters.

    Query params:
        tenant_id (required): Tenant identifier
        workspace (required): Workspace identifier

    Returns:
        JSON with distinct values and counts for services, regions, severities, states
    """
    try:
        tenant_id, workspace = _require_scope_from_query()
        with db_conn() as conn:
            services = fetch_all_dict_conn(
                conn,
                """
                SELECT service AS value, COUNT(*)::bigint AS count
                FROM finding_current
                WHERE tenant_id=%s AND workspace=%s AND service IS NOT NULL
                GROUP BY service
                ORDER BY count DESC
                """,
                (tenant_id, workspace),
            )
            regions = fetch_all_dict_conn(
                conn,
                """
                SELECT region AS value, COUNT(*)::bigint AS count
                FROM finding_current
                WHERE tenant_id=%s AND workspace=%s AND region IS NOT NULL
                GROUP BY region
                ORDER BY count DESC
                """,
                (tenant_id, workspace),
            )
            severities = fetch_all_dict_conn(
                conn,
                """
                SELECT severity AS value, COUNT(*)::bigint AS count
                FROM finding_current
                WHERE tenant_id=%s AND workspace=%s AND severity IS NOT NULL
                GROUP BY severity
                ORDER BY count DESC
                """,
                (tenant_id, workspace),
            )
            states = fetch_all_dict_conn(
                conn,
                """
                SELECT effective_state AS value, COUNT(*)::bigint AS count
                FROM finding_current
                WHERE tenant_id=%s AND workspace=%s
                GROUP BY effective_state
                ORDER BY count DESC
                """,
                (tenant_id, workspace),
            )

        return jsonify(
            {
                "tenant_id": tenant_id,
                "workspace": workspace,
                "services": services,
                "regions": regions,
                "severities": severities,
                "states": states,
            }
        )
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
