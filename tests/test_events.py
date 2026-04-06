"""Unit tests for event processing — normalize, signature, dedupe."""

from vmware_aria_logs.analysis.events import (
    dedupe_events,
    event_signature,
    extract_source,
    extract_text,
    normalize_text,
)


class TestNormalizeText:
    def test_replaces_uuids(self) -> None:
        text = "Error on object 550e8400-e29b-41d4-a716-446655440000 failed"
        result = normalize_text(text)
        assert "<UUID>" in result
        assert "550e8400" not in result

    def test_replaces_ips(self) -> None:
        text = "Connection refused from 192.168.1.100 to 10.0.0.1"
        result = normalize_text(text)
        assert "<IP>" in result
        assert "192.168.1.100" not in result

    def test_replaces_long_hex(self) -> None:
        text = "Token abc123def456789012 expired"
        result = normalize_text(text)
        assert "<HEX>" in result

    def test_replaces_long_numbers(self) -> None:
        text = "Process 123456 exited with code 0"
        result = normalize_text(text)
        assert "<N>" in result
        assert "123456" not in result

    def test_replaces_long_paths(self) -> None:
        text = "File /var/log/vmware/vpxd/vpxd-1234.log not found"
        result = normalize_text(text)
        assert "<PATH>" in result

    def test_preserves_short_text(self) -> None:
        text = "Error occurred"
        assert normalize_text(text) == "Error occurred"


class TestEventSignature:
    def test_same_text_same_sig(self) -> None:
        e1 = {"text": "Error on host A", "source": "host1"}
        e2 = {"text": "Error on host A", "source": "host1"}
        assert event_signature(e1) == event_signature(e2)

    def test_different_source_same_sig_by_default(self) -> None:
        """Default: source-independent for mass incident detection."""
        e1 = {"text": "Error on host A", "source": "host1"}
        e2 = {"text": "Error on host A", "source": "host2"}
        assert event_signature(e1) == event_signature(e2)

    def test_different_source_different_sig_with_flag(self) -> None:
        """With include_source=True, different hosts get different sigs."""
        e1 = {"text": "Error on host A", "source": "host1"}
        e2 = {"text": "Error on host A", "source": "host2"}
        assert event_signature(e1, include_source=True) != event_signature(e2, include_source=True)

    def test_variable_parts_normalized(self) -> None:
        e1 = {"text": "Error on 10.0.0.1", "source": "host1"}
        e2 = {"text": "Error on 10.0.0.2", "source": "host1"}
        assert event_signature(e1) == event_signature(e2)


class TestExtractText:
    def test_from_text_field(self) -> None:
        assert extract_text({"text": "hello"}) == "hello"

    def test_from_message_field(self) -> None:
        assert extract_text({"message": "hello"}) == "hello"

    def test_from_fields_array(self) -> None:
        event = {"fields": [{"name": "text", "content": "hello"}]}
        assert extract_text(event) == "hello"

    def test_empty_event(self) -> None:
        assert extract_text({}) == ""


class TestExtractSource:
    def test_from_source_field(self) -> None:
        assert extract_source({"source": "host1"}) == "host1"

    def test_from_hostname_field(self) -> None:
        assert extract_source({"hostname": "host1"}) == "host1"

    def test_from_fields_array(self) -> None:
        event = {"fields": [{"name": "hostname", "content": "host1"}]}
        assert extract_source(event) == "host1"

    def test_empty_event(self) -> None:
        assert extract_source({}) == ""


class TestDedupeEvents:
    def test_removes_exact_duplicates(self) -> None:
        events = [
            {"text": "error A", "source": "h1", "timestamp": "100"},
            {"text": "error A", "source": "h1", "timestamp": "100"},
        ]
        assert len(dedupe_events(events)) == 1

    def test_keeps_different_events(self) -> None:
        events = [
            {"text": "error A", "source": "h1", "timestamp": "100"},
            {"text": "error B", "source": "h1", "timestamp": "100"},
        ]
        assert len(dedupe_events(events)) == 2

    def test_keeps_same_text_different_timestamp(self) -> None:
        events = [
            {"text": "error A", "source": "h1", "timestamp": "100"},
            {"text": "error A", "source": "h1", "timestamp": "200"},
        ]
        assert len(dedupe_events(events)) == 2

    def test_empty_list(self) -> None:
        assert dedupe_events([]) == []
