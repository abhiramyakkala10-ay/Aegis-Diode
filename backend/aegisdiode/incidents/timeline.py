"""
AegisDiode Incident Timeline Builder
======================================
Aggregates correlated alerts into chronological incident timelines.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from aegisdiode.db.models import Alert, Incident


class TimelineEntry:
    """A single entry in the incident timeline."""

    def __init__(self, timestamp: float, event_type: str, description: str,
                 severity: str = "", detector: str = "", alert_id: str = ""):
        self.timestamp = timestamp
        self.event_type = event_type
        self.description = description
        self.severity = severity
        self.detector = detector
        self.alert_id = alert_id

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "time_str": datetime.utcfromtimestamp(self.timestamp).isoformat() + "Z",
            "event_type": self.event_type,
            "description": self.description,
            "severity": self.severity,
            "detector": self.detector,
            "alert_id": self.alert_id,
        }


class TimelineBuilder:
    """Builds chronological timelines from incident data."""

    def build_timeline(self, incident: Incident | dict, alerts: list[Alert | dict]) -> list[dict]:
        """
        Build a complete timeline for an incident.

        The timeline includes:
        1. Incident creation event
        2. All contributing alerts in chronological order
        3. Status change events
        """
        entries: list[TimelineEntry] = []

        def get_val(obj, key, default=None):
            if isinstance(obj, dict):
                return obj.get(key, default)
            val = getattr(obj, key, default)
            return getattr(val, "value", val) if hasattr(val, "value") else val

        # Add alert events
        for alert in sorted(alerts, key=lambda a: get_val(a, "timestamp", 0.0) or 0.0):
            entries.append(TimelineEntry(
                timestamp=get_val(alert, "timestamp", 0.0) or 0.0,
                event_type="alert",
                description=get_val(alert, "description", ""),
                severity=str(get_val(alert, "severity", "") or ""),
                detector=str(get_val(alert, "detector_type", "") or ""),
                alert_id=str(get_val(alert, "id", "") or ""),
            ))

        # Add incident creation
        timeline_start = get_val(incident, "timeline_start", 0.0) or 0.0
        desc = get_val(incident, "description", "")
        classification = str(get_val(incident, "classification", "") or "")
        entries.append(TimelineEntry(
            timestamp=timeline_start,
            event_type="incident_created",
            description=f"Incident created: {desc}",
            severity=classification,
        ))

        # Add acknowledgment if present
        ack_at = get_val(incident, "acknowledged_at")
        if ack_at:
            if isinstance(ack_at, datetime):
                ack_timestamp = ack_at.timestamp()
            elif isinstance(ack_at, (int, float)):
                ack_timestamp = float(ack_at)
            else:
                ack_timestamp = timeline_start
            entries.append(TimelineEntry(
                timestamp=ack_timestamp,
                event_type="acknowledged",
                description="Incident acknowledged by SOC analyst",
            ))

        # Sort by timestamp
        entries.sort(key=lambda e: e.timestamp)

        return [e.to_dict() for e in entries]
