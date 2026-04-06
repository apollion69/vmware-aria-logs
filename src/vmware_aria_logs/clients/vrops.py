"""VMware Aria Operations (vROps) Suite API client — read-only correlation."""

from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any


class VropsError(RuntimeError):
    """Raised when a vROps API call fails."""


@dataclass
class VropsClient:
    """Read-only client for VMware Aria Operations Suite API.

    Used to correlate Log Insight events with vROps resources and alerts.
    """

    base_url: str
    username: str
    password: str = field(default="", repr=False)
    auth_source: str = "local"
    verify_tls: bool = False
    timeout_sec: int = 30
    token: str = field(default="", repr=False)

    def __post_init__(self) -> None:
        self.base_url = self.base_url.rstrip("/")
        parsed = urllib.parse.urlparse(self.base_url)
        if parsed.scheme not in ("https", "http"):
            raise VropsError(
                f"base_url must use http(s) scheme, got: {parsed.scheme!r}"
            )
        if not parsed.netloc:
            raise VropsError("base_url must include a hostname")
        if self.verify_tls:
            self._ssl_ctx = ssl.create_default_context()
        else:
            self._ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            self._ssl_ctx.check_hostname = False
            self._ssl_ctx.verify_mode = ssl.CERT_NONE

    def _request_json(
        self,
        *,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
    ) -> Any:
        url = f"{self.base_url}{path}"
        data = None
        headers: dict[str, str] = {"Accept": "application/json"}
        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if self.token:
            headers["Authorization"] = f"vRealizeOpsToken {self.token}"
        request = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(
                request, context=self._ssl_ctx, timeout=self.timeout_sec
            ) as resp:
                body = resp.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise VropsError(
                f"HTTP {exc.code} for {method} {path}: {body[:400]}"
            ) from exc
        except urllib.error.URLError as exc:
            raise VropsError(f"request failed {method} {path}: {exc}") from exc
        try:
            return json.loads(body)
        except json.JSONDecodeError as exc:
            raise VropsError(f"non-JSON response for {path}: {body[:400]}") from exc

    def authenticate(self) -> str:
        """Acquire a vROps auth token."""
        response = self._request_json(
            method="POST",
            path="/suite-api/api/auth/token/acquire",
            payload={
                "username": self.username,
                "authSource": self.auth_source,
                "password": self.password,
            },
        )
        token = str(
            response.get("token")
            or response.get("authToken")
            or response.get("auth_token")
            or ""
        ).strip()
        if not token:
            raise VropsError("auth succeeded but no token returned")
        self.token = token
        return token

    def find_resources(self, name: str, *, page_size: int = 20) -> list[dict[str, Any]]:
        """Find vROps resources by name."""
        if not self.token:
            self.authenticate()
        params = urllib.parse.urlencode({"name": name, "pageSize": str(page_size)})
        payload = self._request_json(
            method="GET", path=f"/suite-api/api/resources?{params}"
        )
        return _extract_list(payload, "resourceList", "resources")

    def get_alerts(
        self, resource_ids: list[str], *, page_size: int = 100
    ) -> list[dict[str, Any]]:
        """Get alerts for specific resource IDs."""
        if not resource_ids:
            return []
        if not self.token:
            self.authenticate()
        params = [("page", "0"), ("pageSize", str(page_size))]
        params.extend(("resourceId", rid) for rid in resource_ids)
        payload = self._request_json(
            method="GET",
            path=f"/suite-api/api/alerts?{urllib.parse.urlencode(params, doseq=True)}",
        )
        return _extract_list(payload, "alerts", "alert")


def _extract_list(payload: Any, *keys: str) -> list[dict[str, Any]]:
    """Extract a list of dicts from various response shapes."""
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        for key in (*keys, "items", "results"):
            value = payload.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
    return []
