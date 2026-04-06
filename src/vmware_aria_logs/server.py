"""VMware Aria Operations for Logs — MCP Server.

Exposes Log Insight API v2 and optional vROps correlation as MCP tools.
"""

from __future__ import annotations

import json
import os
from typing import Any

from mcp.server.fastmcp import FastMCP

from .analysis.events import dedupe_events
from .analysis.incidents import detect_mass_incidents, incidents_to_dicts
from .clients.loginsight import EventConstraint, LogInsightClient, LogInsightError
from .clients.vrops import VropsClient, VropsError

mcp = FastMCP(
    "vmware-aria-logs",
    instructions="VMware Aria Operations for Logs (Log Insight) — log search, incident detection, vROps correlation",
)

# ---------------------------------------------------------------------------
# Lazy client singletons — created on first tool call
# ---------------------------------------------------------------------------

_li_client: LogInsightClient | None = None
_vrops_client: VropsClient | None = None


def _get_li_client() -> LogInsightClient:
    global _li_client
    if _li_client is None:
        base_url = os.environ.get("LI_BASE_URL") or os.environ.get("LI_API_BASE_URL") or ""
        if not base_url:
            raise LogInsightError("LI_BASE_URL environment variable is required")
        _li_client = LogInsightClient(
            base_url=base_url,
            username=os.environ.get("LI_USERNAME") or os.environ.get("LI_API_USER") or "admin",
            password=os.environ.get("LI_PASSWORD") or os.environ.get("LI_API_PASSWORD") or "",
            provider=os.environ.get("LI_PROVIDER") or os.environ.get("LI_API_PROVIDER") or "Local",
            verify_tls=os.environ.get("LI_VERIFY_TLS", "false").lower() in ("true", "1", "yes"),
            timeout_sec=int(os.environ.get("LI_TIMEOUT_SEC", "30")),
        )
    return _li_client


def _get_vrops_client() -> VropsClient | None:
    global _vrops_client
    if _vrops_client is None:
        base_url = os.environ.get("VROPS_BASE_URL") or ""
        if not base_url:
            return None
        _vrops_client = VropsClient(
            base_url=base_url,
            username=os.environ.get("VROPS_USERNAME") or os.environ.get("VROPS_USER") or "admin",
            password=os.environ.get("VROPS_PASSWORD") or "",
            auth_source=os.environ.get("VROPS_AUTH_SOURCE") or "local",
            verify_tls=os.environ.get("VROPS_VERIFY_TLS", "false").lower() in ("true", "1", "yes"),
            timeout_sec=int(os.environ.get("VROPS_TIMEOUT_SEC", "30")),
        )
    return _vrops_client


# ---------------------------------------------------------------------------
# MCP Tools
# ---------------------------------------------------------------------------


@mcp.tool()
def query_events(
    lookback_minutes: int = 60,
    search_term: str = "",
    limit: int = 100,
    field_name: str = "",
    field_operator: str = "CONTAINS",
    field_value: str = "",
) -> str:
    """Search log events in VMware Aria Operations for Logs.

    Args:
        lookback_minutes: How far back to search (default 60 minutes).
        search_term: Free-text search term (optional).
        limit: Maximum number of events to return (default 100, max 10000).
        field_name: Optional field constraint name (e.g. 'hostname', 'appname').
        field_operator: Constraint operator (CONTAINS, NOT_CONTAINS, HAS, etc.).
        field_value: Constraint value.

    Returns:
        JSON array of log events with text, source, timestamp, and fields.
    """
    client = _get_li_client()
    constraints = None
    if field_name and field_value:
        constraints = [EventConstraint(field_name=field_name, operator=field_operator, value=field_value)]
    events = client.query_events(
        lookback_minutes=lookback_minutes,
        term=search_term,
        constraints=constraints,
        limit=min(limit, 10_000),
    )
    events = dedupe_events(events)
    return json.dumps(events[:limit], ensure_ascii=False, indent=2)


@mcp.tool()
def get_version() -> str:
    """Get VMware Aria Operations for Logs appliance version and API surface.

    Returns version info and probes key API endpoints to determine
    which features are available on this deployment.
    """
    client = _get_li_client()
    if not client.token:
        client.authenticate()

    version_info = client.probe_endpoint(method="GET", path="/api/v2/version")
    dashboards = client.probe_endpoint(method="GET", path="/vrlic/api/v1/content/dashboards")
    queries = client.probe_endpoint(method="GET", path="/vrlic/api/v1/query-definitions")

    result = {
        "base_url": client.base_url,
        "version": version_info.get("parsed", {}),
        "api_surface": {
            "v2_version": version_info["verdict"],
            "legacy_dashboards": dashboards["verdict"],
            "legacy_query_definitions": queries["verdict"],
        },
    }
    return json.dumps(result, ensure_ascii=False, indent=2)


@mcp.tool()
def list_dashboards() -> str:
    """List saved dashboards from Aria Operations for Logs.

    Uses the legacy vRLIC API (``/vrlic/api/v1/content/dashboards``).
    This endpoint was deprecated in Aria Operations for Logs 8.18+
    and will return an empty result on newer appliances.
    """
    client = _get_li_client()
    dashboards = client.list_dashboards()
    if not dashboards:
        return json.dumps({"message": "No dashboards found or legacy API unavailable"})
    return json.dumps(dashboards[:50], ensure_ascii=False, indent=2)


@mcp.tool()
def detect_incidents(
    lookback_minutes: int = 60,
    search_term: str = "",
    event_limit: int = 5000,
    mass_threshold: int = 5,
    max_incidents: int = 20,
) -> str:
    """Detect mass log incidents using signature clustering (Stormbreaker engine).

    Queries events, groups them by normalized signature pattern, and returns
    clusters that exceed the mass threshold — ranked by event count.

    Args:
        lookback_minutes: How far back to search (default 60 minutes).
        search_term: Free-text search term (optional, empty = all events).
        event_limit: Max events to fetch for analysis (default 5000).
        mass_threshold: Min events per signature to qualify as incident (default 5).
        max_incidents: Max incidents to return (default 20).

    Returns:
        JSON with ranked incidents including signature, event count,
        blast radius (affected sources), and sample text.
    """
    client = _get_li_client()
    events = client.query_events(
        lookback_minutes=lookback_minutes,
        term=search_term,
        limit=min(event_limit, 10_000),
    )
    events = dedupe_events(events)
    incidents = detect_mass_incidents(
        events,
        mass_threshold=mass_threshold,
        max_incidents=max_incidents,
    )
    return json.dumps({
        "total_events_analyzed": len(events),
        "incidents_found": len(incidents),
        "lookback_minutes": lookback_minutes,
        "incidents": incidents_to_dicts(incidents),
    }, ensure_ascii=False, indent=2)


@mcp.tool()
def find_vrops_resources(name: str) -> str:
    """Find resources in VMware Aria Operations (vROps) by name.

    Useful for correlating Log Insight events with vROps monitored entities.
    Requires VROPS_BASE_URL to be configured.

    Args:
        name: Resource name to search for (VM name, host name, etc.).

    Returns:
        JSON array of matching vROps resources with IDs, names, and types.
    """
    client = _get_vrops_client()
    if client is None:
        return json.dumps({"error": "vROps not configured (VROPS_BASE_URL not set)"})
    resources = client.find_resources(name)
    compact = [
        {
            "identifier": r.get("identifier", ""),
            "name": (r.get("resourceKey") or {}).get("name", ""),
            "resourceKind": (r.get("resourceKey") or {}).get("resourceKindKey", ""),
            "adapterKind": (r.get("resourceKey") or {}).get("adapterKindKey", ""),
            "health": r.get("resourceHealth", ""),
        }
        for r in resources[:20]
    ]
    return json.dumps(compact, ensure_ascii=False, indent=2)


@mcp.tool()
def get_vrops_alerts(resource_ids: str) -> str:
    """Get alerts from VMware Aria Operations for specific resources.

    Args:
        resource_ids: Comma-separated vROps resource IDs.

    Returns:
        JSON array of alerts with severity, status, and descriptions.
    """
    client = _get_vrops_client()
    if client is None:
        return json.dumps({"error": "vROps not configured (VROPS_BASE_URL not set)"})
    ids = [rid.strip() for rid in resource_ids.split(",") if rid.strip()]
    if not ids:
        return json.dumps({"error": "No resource IDs provided"})
    alerts = client.get_alerts(ids)
    compact = [
        {
            "alertId": a.get("alertId", ""),
            "alertLevel": a.get("alertLevel", ""),
            "status": a.get("status", ""),
            "alertDefinitionName": (a.get("alertDefinitionName") or a.get("name", "")),
            "startTimeUTC": a.get("startTimeUTC", 0),
            "resourceId": a.get("resourceId", ""),
        }
        for a in alerts[:50]
    ]
    return json.dumps(compact, ensure_ascii=False, indent=2)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Run the MCP server (stdio transport)."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
