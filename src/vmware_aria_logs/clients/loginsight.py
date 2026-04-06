"""Log Insight API v2 client — read-only operations."""

from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any


class LogInsightError(RuntimeError):
    """Raised when a Log Insight API call fails."""


@dataclass(frozen=True)
class EventConstraint:
    """A single field constraint for event queries."""

    field_name: str
    operator: str  # CONTAINS, NOT_CONTAINS, HAS, etc.
    value: str


@dataclass
class LogInsightClient:
    """Small client for the Log Insight API v2 read path.

    Supports session-based Bearer token auth and event querying with
    arbitrary field constraints.
    """

    base_url: str
    username: str
    password: str
    provider: str = "Local"
    verify_tls: bool = False
    timeout_sec: int = 30
    token: str = field(default="", repr=False)

    def __post_init__(self) -> None:
        self.base_url = self.base_url.rstrip("/")
        if self.verify_tls:
            self._ssl_ctx = ssl.create_default_context()
        else:
            self._ssl_ctx = ssl._create_unverified_context()

    def _request_raw(
        self,
        *,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
    ) -> tuple[int, str]:
        url = f"{self.base_url}{path}"
        data = None
        headers: dict[str, str] = {"Accept": "application/json"}
        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        request = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, context=self._ssl_ctx, timeout=self.timeout_sec) as resp:
                body = resp.read().decode("utf-8")
                return int(getattr(resp, "status", resp.getcode())), body
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            return int(exc.code), body
        except urllib.error.URLError as exc:
            raise LogInsightError(f"request failed {method} {path}: {exc}") from exc

    def _request_json(
        self,
        *,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
    ) -> Any:
        status, body = self._request_raw(method=method, path=path, payload=payload)
        if status >= 400:
            raise LogInsightError(f"HTTP {status} for {method} {path}: {body[:400]}")
        try:
            return json.loads(body)
        except json.JSONDecodeError as exc:
            raise LogInsightError(f"non-JSON response for {path}: {body[:400]}") from exc

    def authenticate(self) -> str:
        """Obtain a session token. Returns the token string."""
        response = self._request_json(
            method="POST",
            path="/api/v2/sessions",
            payload={
                "username": self.username,
                "password": self.password,
                "provider": self.provider,
            },
        )
        token = str(
            response.get("sessionId")
            or response.get("session_id")
            or response.get("id")
            or ""
        ).strip()
        if not token:
            raise LogInsightError("auth succeeded but no session id returned")
        self.token = token
        return token

    def _build_events_path(
        self,
        *,
        lookback_minutes: int,
        term: str = "",
        constraints: list[EventConstraint] | None = None,
        limit: int = 100,
    ) -> str:
        parts = [
            urllib.parse.quote("timestamp", safe=""),
            urllib.parse.quote(f"LAST {max(lookback_minutes, 1) * 60_000}", safe=""),
        ]
        if term:
            parts.extend([
                urllib.parse.quote("text", safe=""),
                urllib.parse.quote(f"CONTAINS {term}", safe=""),
            ])
        for c in constraints or []:
            parts.extend([
                urllib.parse.quote(c.field_name, safe=""),
                urllib.parse.quote(f"{c.operator} {c.value}", safe=""),
            ])
        return f"/api/v2/events/{'/'.join(parts)}?limit={int(limit)}"

    def query_events(
        self,
        *,
        lookback_minutes: int = 60,
        term: str = "",
        constraints: list[EventConstraint] | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Query events from Log Insight. Returns list of event dicts."""
        if not self.token:
            self.authenticate()
        path = self._build_events_path(
            lookback_minutes=lookback_minutes,
            term=term,
            constraints=constraints,
            limit=limit,
        )
        payload = self._request_json(method="GET", path=path)
        return _extract_events(payload)

    def get_version(self) -> dict[str, Any]:
        """Get appliance version info."""
        if not self.token:
            self.authenticate()
        return self._request_json(method="GET", path="/api/v2/version")

    def probe_endpoint(self, *, method: str, path: str) -> dict[str, Any]:
        """Probe an API endpoint and return availability info."""
        status, body = self._request_raw(method=method, path=path)
        parsed: Any = None
        if body.strip():
            try:
                parsed = json.loads(body)
            except json.JSONDecodeError:
                parsed = None
        if status == 404:
            verdict = "unavailable"
        elif status >= 400:
            verdict = "auth_or_transport_error"
        else:
            verdict = "available"
        return {
            "method": method,
            "path": path,
            "http_status": status,
            "verdict": verdict,
            "body_excerpt": body[:500] if verdict != "available" else "",
            "parsed": parsed if isinstance(parsed, (dict, list)) else None,
        }

    def list_dashboards(self) -> list[dict[str, Any]]:
        """List saved dashboards via the legacy vRLIC API.

        Note: The ``/vrlic/api/v1/content/dashboards`` endpoint was deprecated
        starting in Aria Operations for Logs 8.18.  On 8.18+ appliances this
        method will return an empty list (probe verdict "unavailable").
        """
        if not self.token:
            self.authenticate()
        result = self.probe_endpoint(method="GET", path="/vrlic/api/v1/content/dashboards")
        if result["verdict"] == "available" and isinstance(result["parsed"], list):
            return result["parsed"]
        if isinstance(result["parsed"], dict):
            items = result["parsed"].get("dashboards") or result["parsed"].get("content") or []
            if isinstance(items, list):
                return items
        return []


def _extract_events(payload: Any) -> list[dict[str, Any]]:
    """Extract event list from various API response shapes."""
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        for key in ("events", "results", "items"):
            value = payload.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
    return []
