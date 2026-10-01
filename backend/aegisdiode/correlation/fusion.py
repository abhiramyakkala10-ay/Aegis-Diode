"""
AegisDiode Multi-Signal Fusion Engine
=======================================
Time-windowed correlation of alerts from multiple detectors.
Core innovation: only multi-detector incidents are surfaced, eliminating alert fatigue.
"""

from __future__ import annotations

import time
from collections import defaultdict
from typing import Optional

from aegisdiode.config import config
from aegisdiode.db.models import Alert, Incident, IncidentStatus
from aegisdiode.correlation.scoring import compute_threat_score, classify_threat


class FusionEngine:
    """
    Multi-signal fusion engine that correlates alerts from distinct detectors.

    Algorithm:
    1. Collect all alerts within a 30-second correlation window
    2. Group alerts by destination IP (target-centric view)
    3. Count distinct detector types that fired
    4. If distinct_detectors >= 2 → create an Incident
    5. Single-detector alerts are SUPPRESSED (eliminates alert fatigue)

    This is the core innovation: SOC analysts only see correlated multi-signal
    events, not individual noisy detector outputs.
    """

    def __init__(self):
        self.correlation_window = config.correlation.correlation_window
        self.min_detectors = config.correlation.min_detectors
        self.merge_window = config.correlation.merge_window

        # Pending alerts waiting for correlation
        self._pending_alerts: list[Alert] = []
        self._recent_incidents: list[Incident] = []

    def add_alert(self, alert: Alert) -> Optional[Incident]:
        """
        Add an alert to the fusion engine.
        Returns an Incident if correlation threshold is met.
        """
        self._pending_alerts.append(alert)

        # Clean old alerts outside the correlation window
        now = time.time()
        self._pending_alerts = [
            a for a in self._pending_alerts
            if now - a.timestamp <= self.correlation_window
        ]

        # Try to correlate
        return self._try_correlate()

    async def process_alert(self, alert: Alert) -> Optional[Incident]:
        """Async-compatible wrapper for alert correlation processing."""
        return self.add_alert(alert)

    def _try_correlate(self) -> Optional[Incident]:
        """
        Attempt to create an incident from correlated alerts.

        Groups alerts by target IP and checks if enough distinct
        detectors have fired within the correlation window.
        """
        if len(self._pending_alerts) < self.min_detectors:
            return None

        # Group alerts by destination IP extracted from flow_key_str
        target_groups: dict[str, list[Alert]] = defaultdict(list)
        for alert in self._pending_alerts:
            # Extract target IP from flow key string (format: src:port->dst:port/proto)
            target_ip = self._extract_target_ip(alert.flow_key_str)
            target_groups[target_ip].append(alert)

        # Check each target for multi-signal correlation
        for target_ip, alerts in target_groups.items():
            detector_types = set(a.detector_type.value for a in alerts)

            if len(detector_types) >= self.min_detectors:
                # Check if we should merge with a recent incident
                existing = self._find_mergeable_incident(target_ip)
                if existing:
                    self._merge_into_incident(existing, alerts)
                    return existing

                # Create new incident
                incident = self._create_incident(target_ip, alerts, detector_types)

                # Remove correlated alerts from pending
                correlated_ids = {a.id for a in alerts}
                self._pending_alerts = [
                    a for a in self._pending_alerts
                    if a.id not in correlated_ids
                ]

                self._recent_incidents.append(incident)
                return incident

        return None

    def _create_incident(
        self, target_ip: str, alerts: list[Alert], detector_types: set[str]
    ) -> Incident:
        """Create a new incident from correlated alerts."""
        # Compute threat score
        threat_score = compute_threat_score(alerts)
        classification = classify_threat(threat_score)

        # Collect source IPs
        source_ips = list(set(
            self._extract_source_ip(a.flow_key_str) for a in alerts
        ))
        flow_ids = list(set(a.flow_id for a in alerts))

        # Build description
        detector_list = ", ".join(sorted(detector_types))
        severity_max = max(alerts, key=lambda a: {"LOW": 0, "MEDIUM": 1, "HIGH": 2}[a.severity.value])

        description = (
            f"Multi-signal incident targeting {target_ip}: "
            f"Detectors: [{detector_list}]. "
            f"Peak severity: {severity_max.severity.value}. "
            f"{len(alerts)} contributing alerts from {len(source_ips)} source(s)."
        )

        return Incident(
            alert_ids=[a.id for a in alerts],
            detector_types=list(detector_types),
            threat_score=threat_score,
            classification=classification,
            status=IncidentStatus.OPEN,
            target_ip=target_ip,
            source_ips=source_ips,
            affected_flow_ids=flow_ids,
            timeline_start=min(a.timestamp for a in alerts),
            timeline_end=max(a.timestamp for a in alerts),
            description=description,
        )

    def _find_mergeable_incident(self, target_ip: str) -> Optional[Incident]:
        """Find a recent incident for the same target that can be merged."""
        now = time.time()
        for incident in reversed(self._recent_incidents):
            if (incident.target_ip == target_ip and
                    incident.status == IncidentStatus.OPEN and
                    now - incident.timeline_end <= self.merge_window):
                return incident
        return None

    def _merge_into_incident(self, incident: Incident, new_alerts: list[Alert]) -> None:
        """Merge new alerts into an existing incident."""
        for alert in new_alerts:
            if alert.id not in incident.alert_ids:
                incident.alert_ids.append(alert.id)
                if alert.detector_type.value not in incident.detector_types:
                    incident.detector_types.append(alert.detector_type.value)
                if alert.flow_id not in incident.affected_flow_ids:
                    incident.affected_flow_ids.append(alert.flow_id)

        incident.timeline_end = max(
            incident.timeline_end, max(a.timestamp for a in new_alerts))

        # Recalculate threat score
        # (simplified — in production, would re-fetch all contributing alerts)
        incident.threat_score = min(100, incident.threat_score + 5)
        incident.classification = classify_threat(incident.threat_score)

    @staticmethod
    def _extract_target_ip(flow_key_str: str) -> str:
        """Extract destination IP from flow key string."""
        try:
            # Format: src_ip:port->dst_ip:port/proto
            parts = flow_key_str.split("->")
            if len(parts) == 2:
                dst_part = parts[1].split(":")[0]
                return dst_part
        except (IndexError, ValueError):
            pass
        return "unknown"

    @staticmethod
    def _extract_source_ip(flow_key_str: str) -> str:
        """Extract source IP from flow key string."""
        try:
            parts = flow_key_str.split(":")
            if parts:
                return parts[0]
        except (IndexError, ValueError):
            pass
        return "unknown"
