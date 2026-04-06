"""Event extraction, normalization, and deduplication."""

from __future__ import annotations

import hashlib
import re
from typing import Any

_UUID_RE = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")
_HEX_LONG_RE = re.compile(r"\b[0-9a-fA-F]{16,}\b")
_NUMBER_RE = re.compile(r"\b\d{4,}\b")
_IP_RE = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
_PATH_RE = re.compile(r"/[\w./-]{20,}")


def normalize_text(text: str) -> str:
    """Normalize log text to a signature by replacing variable parts."""
    result = _UUID_RE.sub("<UUID>", text)
    result = _HEX_LONG_RE.sub("<HEX>", result)
    result = _IP_RE.sub("<IP>", result)
    result = _PATH_RE.sub("<PATH>", result)
    result = _NUMBER_RE.sub("<N>", result)
    return result


def event_signature(event: dict[str, Any], *, include_source: bool = False) -> str:
    """Compute a stable signature hash for an event.

    Args:
        event: Event dict with text/source fields.
        include_source: If True, signature includes source hostname.
            Use False (default) for mass incident detection across hosts.
            Use True for per-host deduplication.
    """
    text = str(event.get("text") or "")
    normalized = normalize_text(text)
    if include_source:
        source = str(event.get("source") or event.get("hostname") or "")
        key = f"{source}::{normalized}"
    else:
        key = normalized
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


def extract_text(event: dict[str, Any]) -> str:
    """Extract the primary text content from an event."""
    text = event.get("text")
    if isinstance(text, str) and text:
        return text
    for field_key in ("message", "msg", "log", "raw"):
        value = event.get(field_key)
        if isinstance(value, str) and value:
            return value
    fields = event.get("fields") or []
    if isinstance(fields, list):
        for field_item in fields:
            if isinstance(field_item, dict):
                name = str(field_item.get("name") or "")
                content = str(field_item.get("content") or "")
                if name.lower() in ("text", "message", "msg") and content:
                    return content
    return ""


def extract_source(event: dict[str, Any]) -> str:
    """Extract the source hostname from an event."""
    for key in ("source", "hostname", "host", "agent"):
        value = event.get(key)
        if isinstance(value, str) and value:
            return value
    fields = event.get("fields") or []
    if isinstance(fields, list):
        for field_item in fields:
            if isinstance(field_item, dict):
                name = str(field_item.get("name") or "").lower()
                content = str(field_item.get("content") or "")
                if name in ("source", "hostname", "host") and content:
                    return content
    return ""


def dedupe_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Remove duplicate events based on text + source + timestamp."""
    seen: set[str] = set()
    result: list[dict[str, Any]] = []
    for event in events:
        text = extract_text(event)
        source = extract_source(event)
        ts = str(event.get("timestamp") or "")
        key = f"{source}:{ts}:{text[:200]}"
        digest = hashlib.md5(key.encode("utf-8")).hexdigest()
        if digest not in seen:
            seen.add(digest)
            result.append(event)
    return result
