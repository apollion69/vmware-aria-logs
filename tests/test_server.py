"""Tests for MCP server tool functions — mocked HTTP, no real API calls."""

import json
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture(autouse=True)
def _reset_clients() -> None:
    """Reset singleton clients between tests."""
    import vmware_aria_logs.server as srv

    srv._li_client = None
    srv._vrops_client = None


@pytest.fixture()
def _env_vars(monkeypatch: pytest.MonkeyPatch) -> None:
    """Set required env vars for client construction."""
    monkeypatch.setenv("LI_BASE_URL", "https://loginsight.test")
    monkeypatch.setenv("LI_USERNAME", "admin")
    monkeypatch.setenv("LI_PASSWORD", "testpass")
    monkeypatch.setenv("LI_PROVIDER", "Local")
    monkeypatch.setenv("VROPS_BASE_URL", "https://vrops.test")
    monkeypatch.setenv("VROPS_USERNAME", "admin")
    monkeypatch.setenv("VROPS_PASSWORD", "testpass")


class TestQueryEventsTool:
    @pytest.mark.usefixtures("_env_vars")
    @patch("vmware_aria_logs.clients.loginsight.LogInsightClient.query_events")
    @patch("vmware_aria_logs.clients.loginsight.LogInsightClient.authenticate")
    def test_returns_json_events(
        self, mock_auth: MagicMock, mock_query: MagicMock
    ) -> None:
        mock_auth.return_value = "fake-token"
        mock_query.return_value = [
            {"text": "Error on host1", "source": "host1", "timestamp": "1000"},
            {"text": "Warning on host2", "source": "host2", "timestamp": "2000"},
        ]
        from vmware_aria_logs.server import query_events

        result = json.loads(
            query_events(lookback_minutes=30, search_term="error", limit=10)
        )
        assert isinstance(result, list)
        assert len(result) == 2

    @pytest.mark.usefixtures("_env_vars")
    @patch("vmware_aria_logs.clients.loginsight.LogInsightClient.query_events")
    @patch("vmware_aria_logs.clients.loginsight.LogInsightClient.authenticate")
    def test_deduplicates_events(
        self, mock_auth: MagicMock, mock_query: MagicMock
    ) -> None:
        mock_auth.return_value = "fake-token"
        mock_query.return_value = [
            {"text": "Same error", "source": "host1", "timestamp": "1000"},
            {"text": "Same error", "source": "host1", "timestamp": "1000"},
        ]
        from vmware_aria_logs.server import query_events

        result = json.loads(query_events())
        assert len(result) == 1


class TestDetectIncidentsTool:
    @pytest.mark.usefixtures("_env_vars")
    @patch("vmware_aria_logs.clients.loginsight.LogInsightClient.query_events")
    @patch("vmware_aria_logs.clients.loginsight.LogInsightClient.authenticate")
    def test_returns_incidents(
        self, mock_auth: MagicMock, mock_query: MagicMock
    ) -> None:
        mock_auth.return_value = "fake-token"
        mock_query.return_value = [
            {"text": "Repeated error", "source": f"host{i}", "timestamp": str(i)}
            for i in range(20)
        ]
        from vmware_aria_logs.server import detect_incidents

        result = json.loads(detect_incidents(lookback_minutes=60, mass_threshold=5))
        assert result["total_events_analyzed"] == 20
        assert result["incidents_found"] >= 1
        assert result["incidents"][0]["event_count"] == 20


class TestGetVersionTool:
    @pytest.mark.usefixtures("_env_vars")
    @patch("vmware_aria_logs.clients.loginsight.LogInsightClient.probe_endpoint")
    @patch("vmware_aria_logs.clients.loginsight.LogInsightClient.authenticate")
    def test_returns_version_info(
        self, mock_auth: MagicMock, mock_probe: MagicMock
    ) -> None:
        mock_auth.return_value = "fake-token"
        mock_probe.return_value = {
            "method": "GET",
            "path": "/api/v2/version",
            "http_status": 200,
            "verdict": "available",
            "body_excerpt": "",
            "parsed": {"version": "8.14.0"},
        }
        from vmware_aria_logs.server import get_version

        result = json.loads(get_version())
        assert "version" in result
        assert "api_surface" in result


class TestFindVropsResourcesTool:
    @pytest.mark.usefixtures("_env_vars")
    @patch("vmware_aria_logs.clients.vrops.VropsClient.find_resources")
    @patch("vmware_aria_logs.clients.vrops.VropsClient.authenticate")
    def test_returns_resources(
        self, mock_auth: MagicMock, mock_find: MagicMock
    ) -> None:
        mock_auth.return_value = "fake-token"
        mock_find.return_value = [
            {
                "identifier": "res-123",
                "resourceKey": {
                    "name": "vm-web01",
                    "resourceKindKey": "VirtualMachine",
                    "adapterKindKey": "VMWARE",
                },
                "resourceHealth": "GREEN",
            }
        ]
        from vmware_aria_logs.server import find_vrops_resources

        result = json.loads(find_vrops_resources(name="vm-web01"))
        assert isinstance(result, list)
        assert result[0]["name"] == "vm-web01"

    def test_returns_error_without_vrops_config(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("LI_BASE_URL", "https://li.test")
        monkeypatch.setenv("LI_USERNAME", "admin")
        monkeypatch.setenv("LI_PASSWORD", "pw")
        # No VROPS_BASE_URL set
        monkeypatch.delenv("VROPS_BASE_URL", raising=False)
        from vmware_aria_logs.server import find_vrops_resources

        result = json.loads(find_vrops_resources(name="test"))
        assert "error" in result


class TestListDashboardsTool:
    @pytest.mark.usefixtures("_env_vars")
    @patch("vmware_aria_logs.clients.loginsight.LogInsightClient.list_dashboards")
    @patch("vmware_aria_logs.clients.loginsight.LogInsightClient.authenticate")
    def test_returns_dashboards(
        self, mock_auth: MagicMock, mock_dash: MagicMock
    ) -> None:
        mock_auth.return_value = "fake-token"
        mock_dash.return_value = [
            {"name": "Errors Overview", "id": "d-1", "owner": "admin"},
            {"name": "Network Logs", "id": "d-2", "owner": "admin"},
        ]
        from vmware_aria_logs.server import list_dashboards

        result = json.loads(list_dashboards())
        assert isinstance(result, list)
        assert len(result) == 2
        assert result[0]["name"] == "Errors Overview"

    @pytest.mark.usefixtures("_env_vars")
    @patch("vmware_aria_logs.clients.loginsight.LogInsightClient.list_dashboards")
    @patch("vmware_aria_logs.clients.loginsight.LogInsightClient.authenticate")
    def test_empty_returns_message(
        self, mock_auth: MagicMock, mock_dash: MagicMock
    ) -> None:
        mock_auth.return_value = "fake-token"
        mock_dash.return_value = []
        from vmware_aria_logs.server import list_dashboards

        result = json.loads(list_dashboards())
        assert "message" in result


class TestGetVropsAlertsTool:
    @pytest.mark.usefixtures("_env_vars")
    @patch("vmware_aria_logs.clients.vrops.VropsClient.get_alerts")
    @patch("vmware_aria_logs.clients.vrops.VropsClient.authenticate")
    def test_returns_alerts(self, mock_auth: MagicMock, mock_alerts: MagicMock) -> None:
        mock_auth.return_value = "fake-token"
        mock_alerts.return_value = [
            {
                "alertId": "a-1",
                "alertLevel": "CRITICAL",
                "status": "ACTIVE",
                "alertDefinitionName": "CPU Contention",
                "startTimeUTC": 1700000000,
                "resourceId": "res-1",
            }
        ]
        from vmware_aria_logs.server import get_vrops_alerts

        result = json.loads(get_vrops_alerts(resource_ids="res-1"))
        assert isinstance(result, list)
        assert result[0]["alertLevel"] == "CRITICAL"

    def test_no_vrops_config_returns_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("LI_BASE_URL", "https://li.test")
        monkeypatch.setenv("LI_USERNAME", "admin")
        monkeypatch.setenv("LI_PASSWORD", "pw")
        monkeypatch.delenv("VROPS_BASE_URL", raising=False)
        from vmware_aria_logs.server import get_vrops_alerts

        result = json.loads(get_vrops_alerts(resource_ids="res-1"))
        assert "error" in result

    @pytest.mark.usefixtures("_env_vars")
    @patch("vmware_aria_logs.clients.vrops.VropsClient.authenticate")
    def test_empty_ids_returns_error(self, mock_auth: MagicMock) -> None:
        mock_auth.return_value = "fake-token"
        from vmware_aria_logs.server import get_vrops_alerts

        result = json.loads(get_vrops_alerts(resource_ids="  , , "))
        assert "error" in result


class TestNoConfigError:
    def test_query_events_fails_without_base_url(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("LI_BASE_URL", raising=False)
        monkeypatch.delenv("LI_API_BASE_URL", raising=False)
        from vmware_aria_logs.clients.loginsight import LogInsightError
        from vmware_aria_logs.server import query_events

        with pytest.raises(LogInsightError, match="LI_BASE_URL"):
            query_events()
