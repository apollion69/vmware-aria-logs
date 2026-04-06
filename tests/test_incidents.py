"""Unit tests for mass incident detection."""

from vmware_aria_logs.analysis.incidents import (
    MassIncident,
    detect_mass_incidents,
    incidents_to_dicts,
)


def _make_events(text: str, source: str, count: int) -> list[dict]:
    return [{"text": text, "source": source, "timestamp": str(i)} for i in range(count)]


class TestDetectMassIncidents:
    def test_groups_identical_events(self) -> None:
        events = _make_events("Error on host", "host1", 10)
        incidents = detect_mass_incidents(events, mass_threshold=5)
        assert len(incidents) == 1
        assert incidents[0].event_count == 10

    def test_respects_mass_threshold(self) -> None:
        events = _make_events("Error on host", "host1", 3)
        incidents = detect_mass_incidents(events, mass_threshold=5)
        assert len(incidents) == 0

    def test_multiple_clusters(self) -> None:
        events = _make_events("Error A", "host1", 10) + _make_events(
            "Error B", "host2", 8
        )
        incidents = detect_mass_incidents(events, mass_threshold=5)
        assert len(incidents) == 2
        assert incidents[0].event_count >= incidents[1].event_count

    def test_blast_radius_counts_unique_sources(self) -> None:
        events = [
            {"text": "Error X", "source": f"host{i}", "timestamp": str(i)}
            for i in range(10)
        ]
        incidents = detect_mass_incidents(events, mass_threshold=5)
        assert len(incidents) == 1
        assert incidents[0].blast_radius == 10

    def test_normalizes_variable_parts(self) -> None:
        events = [
            {"text": f"Error on 10.0.0.{i}", "source": "host1", "timestamp": str(i)}
            for i in range(10)
        ]
        incidents = detect_mass_incidents(events, mass_threshold=5)
        assert len(incidents) == 1  # all normalize to "Error on <IP>"

    def test_max_incidents_limit(self) -> None:
        all_events: list[dict] = []
        for i in range(30):
            all_events.extend(_make_events(f"Unique error {i}", f"host{i}", 10))
        incidents = detect_mass_incidents(
            all_events, mass_threshold=5, max_incidents=10
        )
        assert len(incidents) <= 10

    def test_empty_events(self) -> None:
        assert detect_mass_incidents([]) == []

    def test_sorted_by_count_descending(self) -> None:
        events = _make_events("Small error", "host1", 6) + _make_events(
            "Big error", "host2", 20
        )
        incidents = detect_mass_incidents(events, mass_threshold=5)
        assert incidents[0].event_count > incidents[1].event_count


class TestIncidentsToDicts:
    def test_converts_to_serializable(self) -> None:
        incidents = [
            MassIncident(
                signature="abc123",
                normalized_text="Error on <IP>",
                event_count=10,
                affected_sources=["host1", "host2"],
                sample_text="Error on 10.0.0.1",
                blast_radius=2,
            )
        ]
        result = incidents_to_dicts(incidents)
        assert len(result) == 1
        assert result[0]["signature"] == "abc123"
        assert result[0]["event_count"] == 10
        assert result[0]["blast_radius"] == 2

    def test_empty_list(self) -> None:
        assert incidents_to_dicts([]) == []
