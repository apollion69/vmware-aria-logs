"""Unit tests for API clients — construction, URL building, and HTTP layer."""

import io
import json
import urllib.error

import pytest

from vmware_aria_logs.clients.loginsight import (
    EventConstraint,
    LogInsightClient,
    LogInsightError,
)
from vmware_aria_logs.clients.vrops import VropsClient, VropsError


def _make_li_client(**overrides: object) -> LogInsightClient:
    defaults = {"base_url": "https://li.test", "username": "admin", "password": "pw"}
    defaults.update(overrides)
    return LogInsightClient(**defaults)  # type: ignore[arg-type]


def _make_vrops_client(**overrides: object) -> VropsClient:
    defaults = {"base_url": "https://vrops.test", "username": "admin", "password": "pw"}
    defaults.update(overrides)
    return VropsClient(**defaults)  # type: ignore[arg-type]


def _mock_response(body: str, status: int = 200) -> object:
    """Create a fake urllib response object usable as context manager."""
    resp = io.BytesIO(body.encode("utf-8"))
    resp.status = status  # type: ignore[attr-defined]
    resp.getcode = lambda: status  # type: ignore[attr-defined]
    resp.__enter__ = lambda s: s  # type: ignore[attr-defined]
    resp.__exit__ = lambda s, *a: None  # type: ignore[attr-defined]
    return resp


# ---------------------------------------------------------------------------
# LogInsight — construction & URL building
# ---------------------------------------------------------------------------


class TestLogInsightClientConstruction:
    def test_strips_trailing_slash(self) -> None:
        client = LogInsightClient(
            base_url="https://loginsight.example.com/",
            username="admin",
            password="secret",
        )
        assert client.base_url == "https://loginsight.example.com"

    def test_defaults(self) -> None:
        client = _make_li_client()
        assert client.provider == "Local"
        assert client.verify_tls is False
        assert client.timeout_sec == 30
        assert client.token == ""

    def test_verify_tls_true(self) -> None:
        client = _make_li_client(verify_tls=True)
        assert client.verify_tls is True


class TestEventsPathBuilding:
    def test_basic_path(self) -> None:
        client = _make_li_client()
        path = client._build_events_path(lookback_minutes=60, limit=100)
        assert "/api/v2/events/" in path
        assert "limit=100" in path
        assert "LAST" in path

    def test_with_search_term(self) -> None:
        client = _make_li_client()
        path = client._build_events_path(lookback_minutes=30, term="error", limit=50)
        assert "CONTAINS" in path
        assert "limit=50" in path

    def test_with_constraints(self) -> None:
        client = _make_li_client()
        constraints = [
            EventConstraint(field_name="hostname", operator="CONTAINS", value="web")
        ]
        path = client._build_events_path(
            lookback_minutes=60, constraints=constraints, limit=100
        )
        assert "hostname" in path
        assert "CONTAINS" in path

    def test_minimum_lookback(self) -> None:
        client = _make_li_client()
        path = client._build_events_path(lookback_minutes=0, limit=10)
        assert "LAST%2060000" in path  # min 1 minute = 60000ms


# ---------------------------------------------------------------------------
# LogInsight — HTTP layer (mocked urlopen)
# ---------------------------------------------------------------------------


class TestLogInsightRequestRaw:
    def test_success_get(self, monkeypatch: pytest.MonkeyPatch) -> None:
        client = _make_li_client()
        client.token = "tok"
        monkeypatch.setattr(
            "urllib.request.urlopen",
            lambda req, **kw: _mock_response('{"ok": true}', 200),
        )
        status, body = client._request_raw(method="GET", path="/api/v2/version")
        assert status == 200
        assert '"ok"' in body

    def test_success_post_with_payload(self, monkeypatch: pytest.MonkeyPatch) -> None:
        captured: list[object] = []

        def fake_urlopen(req: object, **kw: object) -> object:
            captured.append(req)
            return _mock_response('{"sessionId": "abc"}', 200)

        client = _make_li_client()
        monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
        status, body = client._request_raw(
            method="POST", path="/api/v2/sessions", payload={"user": "x"}
        )
        assert status == 200
        assert captured[0].data is not None  # type: ignore[union-attr]

    def test_http_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def raise_http_error(req: object, **kw: object) -> object:
            raise urllib.error.HTTPError(
                "https://li.test/api/v2/version",
                403,
                "Forbidden",
                {},  # type: ignore[arg-type]
                io.BytesIO(b"forbidden"),
            )

        client = _make_li_client()
        monkeypatch.setattr("urllib.request.urlopen", raise_http_error)
        status, body = client._request_raw(method="GET", path="/api/v2/version")
        assert status == 403
        assert "forbidden" in body

    def test_url_error_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def raise_url_error(req: object, **kw: object) -> object:
            raise urllib.error.URLError("connection refused")

        client = _make_li_client()
        monkeypatch.setattr("urllib.request.urlopen", raise_url_error)
        with pytest.raises(LogInsightError, match="request failed"):
            client._request_raw(method="GET", path="/api/v2/version")


class TestLogInsightRequestJson:
    def test_success(self, monkeypatch: pytest.MonkeyPatch) -> None:
        client = _make_li_client()
        monkeypatch.setattr(
            "urllib.request.urlopen",
            lambda req, **kw: _mock_response('{"version": "8.14"}', 200),
        )
        result = client._request_json(method="GET", path="/api/v2/version")
        assert result["version"] == "8.14"

    def test_http_error_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def raise_http_error(req: object, **kw: object) -> object:
            raise urllib.error.HTTPError(
                "url",
                500,
                "ISE",
                {},
                io.BytesIO(b"server error"),  # type: ignore[arg-type]
            )

        client = _make_li_client()
        monkeypatch.setattr("urllib.request.urlopen", raise_http_error)
        with pytest.raises(LogInsightError, match="HTTP 500"):
            client._request_json(method="GET", path="/fail")

    def test_invalid_json_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        client = _make_li_client()
        monkeypatch.setattr(
            "urllib.request.urlopen",
            lambda req, **kw: _mock_response("not json", 200),
        )
        with pytest.raises(LogInsightError, match="non-JSON"):
            client._request_json(method="GET", path="/bad")


class TestLogInsightAuthenticate:
    def test_returns_session_id(self, monkeypatch: pytest.MonkeyPatch) -> None:
        client = _make_li_client()
        monkeypatch.setattr(
            "urllib.request.urlopen",
            lambda req, **kw: _mock_response('{"sessionId": "tok-123"}', 200),
        )
        token = client.authenticate()
        assert token == "tok-123"
        assert client.token == "tok-123"

    def test_session_id_alt_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        client = _make_li_client()
        monkeypatch.setattr(
            "urllib.request.urlopen",
            lambda req, **kw: _mock_response('{"session_id": "alt-tok"}', 200),
        )
        assert client.authenticate() == "alt-tok"

    def test_missing_session_id_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        client = _make_li_client()
        monkeypatch.setattr(
            "urllib.request.urlopen",
            lambda req, **kw: _mock_response('{"result": "ok"}', 200),
        )
        with pytest.raises(LogInsightError, match="no session id"):
            client.authenticate()


class TestLogInsightQueryEvents:
    def test_auto_authenticates_and_returns_events(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        call_count = {"n": 0}

        def fake_urlopen(req: object, **kw: object) -> object:
            call_count["n"] += 1
            if call_count["n"] == 1:
                return _mock_response('{"sessionId": "tok"}', 200)
            return _mock_response(
                json.dumps(
                    {"events": [{"text": "err", "source": "h1", "timestamp": "1"}]}
                ),
                200,
            )

        client = _make_li_client()
        monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
        events = client.query_events(lookback_minutes=10, limit=50)
        assert len(events) == 1
        assert events[0]["text"] == "err"
        assert client.token == "tok"

    def test_skips_auth_if_token_set(self, monkeypatch: pytest.MonkeyPatch) -> None:
        client = _make_li_client()
        client.token = "existing"
        monkeypatch.setattr(
            "urllib.request.urlopen",
            lambda req, **kw: _mock_response('{"events": []}', 200),
        )
        events = client.query_events(lookback_minutes=5)
        assert events == []


class TestLogInsightGetVersion:
    def test_returns_version_dict(self, monkeypatch: pytest.MonkeyPatch) -> None:
        client = _make_li_client()
        client.token = "tok"
        monkeypatch.setattr(
            "urllib.request.urlopen",
            lambda req, **kw: _mock_response('{"version": "8.14.0"}', 200),
        )
        result = client.get_version()
        assert result["version"] == "8.14.0"

    def test_auto_authenticates(self, monkeypatch: pytest.MonkeyPatch) -> None:
        calls = {"n": 0}

        def fake_urlopen(req: object, **kw: object) -> object:
            calls["n"] += 1
            if calls["n"] == 1:
                return _mock_response('{"sessionId": "t"}', 200)
            return _mock_response('{"version": "8.14"}', 200)

        client = _make_li_client()
        monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
        result = client.get_version()
        assert result["version"] == "8.14"


class TestLogInsightProbeEndpoint:
    def test_available(self, monkeypatch: pytest.MonkeyPatch) -> None:
        client = _make_li_client()
        monkeypatch.setattr(
            "urllib.request.urlopen",
            lambda req, **kw: _mock_response('{"version": "8.14"}', 200),
        )
        result = client.probe_endpoint(method="GET", path="/api/v2/version")
        assert result["verdict"] == "available"
        assert result["http_status"] == 200

    def test_not_found(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def raise_404(req: object, **kw: object) -> object:
            raise urllib.error.HTTPError("url", 404, "Not Found", {}, io.BytesIO(b""))  # type: ignore[arg-type]

        client = _make_li_client()
        monkeypatch.setattr("urllib.request.urlopen", raise_404)
        result = client.probe_endpoint(method="GET", path="/missing")
        assert result["verdict"] == "unavailable"
        assert result["http_status"] == 404

    def test_auth_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def raise_401(req: object, **kw: object) -> object:
            raise urllib.error.HTTPError(
                "url", 401, "Unauthorized", {}, io.BytesIO(b"denied")
            )  # type: ignore[arg-type]

        client = _make_li_client()
        monkeypatch.setattr("urllib.request.urlopen", raise_401)
        result = client.probe_endpoint(method="GET", path="/secured")
        assert result["verdict"] == "auth_or_transport_error"

    def test_non_json_body(self, monkeypatch: pytest.MonkeyPatch) -> None:
        client = _make_li_client()
        monkeypatch.setattr(
            "urllib.request.urlopen",
            lambda req, **kw: _mock_response("not json at all", 200),
        )
        result = client.probe_endpoint(method="GET", path="/text")
        assert result["verdict"] == "available"
        assert result["parsed"] is None


class TestLogInsightListDashboards:
    def test_returns_list(self, monkeypatch: pytest.MonkeyPatch) -> None:
        calls = {"n": 0}

        def fake_urlopen(req: object, **kw: object) -> object:
            calls["n"] += 1
            if calls["n"] == 1:
                return _mock_response('{"sessionId": "t"}', 200)
            return _mock_response('[{"id": "d1", "name": "dash1"}]', 200)

        client = _make_li_client()
        monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
        dashboards = client.list_dashboards()
        assert len(dashboards) == 1
        assert dashboards[0]["name"] == "dash1"

    def test_dict_wrapper(self, monkeypatch: pytest.MonkeyPatch) -> None:
        client = _make_li_client()
        client.token = "t"
        monkeypatch.setattr(
            "urllib.request.urlopen",
            lambda req, **kw: _mock_response('{"dashboards": [{"id": "d1"}]}', 200),
        )
        dashboards = client.list_dashboards()
        assert len(dashboards) == 1

    def test_unavailable_returns_empty(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def raise_404(req: object, **kw: object) -> object:
            raise urllib.error.HTTPError("url", 404, "NF", {}, io.BytesIO(b""))  # type: ignore[arg-type]

        client = _make_li_client()
        client.token = "t"
        monkeypatch.setattr("urllib.request.urlopen", raise_404)
        assert client.list_dashboards() == []


# ---------------------------------------------------------------------------
# vROps — construction
# ---------------------------------------------------------------------------


class TestVropsClientConstruction:
    def test_strips_trailing_slash(self) -> None:
        client = VropsClient(
            base_url="https://vrops.example.com/",
            username="admin",
            password="secret",
        )
        assert client.base_url == "https://vrops.example.com"

    def test_defaults(self) -> None:
        client = _make_vrops_client()
        assert client.auth_source == "local"
        assert client.verify_tls is False
        assert client.token == ""


# ---------------------------------------------------------------------------
# vROps — HTTP layer (mocked urlopen)
# ---------------------------------------------------------------------------


class TestVropsRequestJson:
    def test_success(self, monkeypatch: pytest.MonkeyPatch) -> None:
        client = _make_vrops_client()
        monkeypatch.setattr(
            "urllib.request.urlopen",
            lambda req, **kw: _mock_response('{"resources": []}', 200),
        )
        result = client._request_json(method="GET", path="/suite-api/api/resources")
        assert result == {"resources": []}

    def test_http_error_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def raise_http(req: object, **kw: object) -> object:
            raise urllib.error.HTTPError("url", 403, "Forbid", {}, io.BytesIO(b"no"))  # type: ignore[arg-type]

        client = _make_vrops_client()
        monkeypatch.setattr("urllib.request.urlopen", raise_http)
        with pytest.raises(VropsError, match="HTTP 403"):
            client._request_json(method="GET", path="/fail")

    def test_url_error_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def raise_url(req: object, **kw: object) -> object:
            raise urllib.error.URLError("refused")

        client = _make_vrops_client()
        monkeypatch.setattr("urllib.request.urlopen", raise_url)
        with pytest.raises(VropsError, match="request failed"):
            client._request_json(method="GET", path="/fail")

    def test_non_json_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        client = _make_vrops_client()
        monkeypatch.setattr(
            "urllib.request.urlopen",
            lambda req, **kw: _mock_response("not json", 200),
        )
        with pytest.raises(VropsError, match="non-JSON"):
            client._request_json(method="GET", path="/bad")


class TestVropsAuthenticate:
    def test_returns_token(self, monkeypatch: pytest.MonkeyPatch) -> None:
        client = _make_vrops_client()
        monkeypatch.setattr(
            "urllib.request.urlopen",
            lambda req, **kw: _mock_response('{"token": "vrops-tok-1"}', 200),
        )
        token = client.authenticate()
        assert token == "vrops-tok-1"
        assert client.token == "vrops-tok-1"

    def test_alt_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        client = _make_vrops_client()
        monkeypatch.setattr(
            "urllib.request.urlopen",
            lambda req, **kw: _mock_response('{"authToken": "alt"}', 200),
        )
        assert client.authenticate() == "alt"

    def test_missing_token_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        client = _make_vrops_client()
        monkeypatch.setattr(
            "urllib.request.urlopen",
            lambda req, **kw: _mock_response('{"status": "ok"}', 200),
        )
        with pytest.raises(VropsError, match="no token"):
            client.authenticate()


class TestVropsFindResources:
    def test_auto_authenticates_and_returns(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        calls = {"n": 0}

        def fake_urlopen(req: object, **kw: object) -> object:
            calls["n"] += 1
            if calls["n"] == 1:
                return _mock_response('{"token": "t"}', 200)
            return _mock_response(
                json.dumps(
                    {
                        "resourceList": [
                            {"identifier": "r1", "resourceKey": {"name": "vm1"}}
                        ]
                    }
                ),
                200,
            )

        client = _make_vrops_client()
        monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
        resources = client.find_resources("vm1")
        assert len(resources) == 1
        assert resources[0]["identifier"] == "r1"

    def test_skips_auth_if_token_set(self, monkeypatch: pytest.MonkeyPatch) -> None:
        client = _make_vrops_client()
        client.token = "existing"
        monkeypatch.setattr(
            "urllib.request.urlopen",
            lambda req, **kw: _mock_response('{"resourceList": []}', 200),
        )
        assert client.find_resources("x") == []


class TestVropsGetAlerts:
    def test_returns_alerts(self, monkeypatch: pytest.MonkeyPatch) -> None:
        client = _make_vrops_client()
        client.token = "t"
        monkeypatch.setattr(
            "urllib.request.urlopen",
            lambda req, **kw: _mock_response(
                json.dumps({"alerts": [{"alertId": "a1", "alertLevel": "CRITICAL"}]}),
                200,
            ),
        )
        alerts = client.get_alerts(["r1"])
        assert len(alerts) == 1
        assert alerts[0]["alertLevel"] == "CRITICAL"

    def test_empty_ids_returns_empty(self) -> None:
        client = _make_vrops_client()
        client.token = "t"
        assert client.get_alerts([]) == []

    def test_auto_authenticates(self, monkeypatch: pytest.MonkeyPatch) -> None:
        calls = {"n": 0}

        def fake_urlopen(req: object, **kw: object) -> object:
            calls["n"] += 1
            if calls["n"] == 1:
                return _mock_response('{"token": "t"}', 200)
            return _mock_response('{"alerts": []}', 200)

        client = _make_vrops_client()
        monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
        assert client.get_alerts(["r1"]) == []
