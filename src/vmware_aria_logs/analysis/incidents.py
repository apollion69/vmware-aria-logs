"""Mass incident detection via signature clustering."""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Any

from .events import event_signature, extract_source, extract_text, normalize_text


@dataclass(frozen=True)
class MassIncident:
    """A cluster of events sharing the same normalized signature."""

    signature: str
    normalized_text: str
    event_count: int
    affected_sources: list[str]
    sample_text: str
    blast_radius: int  # number of unique sources


def detect_mass_incidents(
    events: list[dict[str, Any]],
    *,
    mass_threshold: int = 5,
    max_incidents: int = 50,
) -> list[MassIncident]:
    """Group events by signature and return those exceeding the mass threshold.

    Args:
        events: Raw event dicts from Log Insight API.
        mass_threshold: Minimum event count to qualify as a mass incident.
        max_incidents: Maximum number of incidents to return (ranked by count).

    Returns:
        List of MassIncident objects, sorted by event_count descending.
    """
    sig_events: dict[str, list[dict[str, Any]]] = defaultdict(list)
    sig_normalized: dict[str, str] = {}

    for event in events:
        sig = event_signature(event)
        sig_events[sig].append(event)
        if sig not in sig_normalized:
            text = extract_text(event)
            sig_normalized[sig] = normalize_text(text)

    incidents: list[MassIncident] = []
    for sig, group in sig_events.items():
        if len(group) < mass_threshold:
            continue
        sources = list({extract_source(e) for e in group if extract_source(e)})
        sample = extract_text(group[0])
        incidents.append(MassIncident(
            signature=sig,
            normalized_text=sig_normalized.get(sig, ""),
            event_count=len(group),
            affected_sources=sorted(sources),
            sample_text=sample[:500],
            blast_radius=len(sources),
        ))

    incidents.sort(key=lambda i: i.event_count, reverse=True)
    return incidents[:max_incidents]


def incidents_to_dicts(incidents: list[MassIncident]) -> list[dict[str, Any]]:
    """Convert incidents to serializable dicts."""
    return [
        {
            "signature": inc.signature,
            "normalized_text": inc.normalized_text,
            "event_count": inc.event_count,
            "blast_radius": inc.blast_radius,
            "affected_sources": inc.affected_sources,
            "sample_text": inc.sample_text,
        }
        for inc in incidents
    ]
