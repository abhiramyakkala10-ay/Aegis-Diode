"""
AegisDiode JSON Report Exporter
=================================
Produces compact, self-contained JSON incident reports for air-gapped SOC analysis.
"""

from __future__ import annotations

import json
from datetime import datetime

from aegisdiode.db.models import Alert, Incident
from aegisdiode.incidents.timeline import TimelineBuilder


class IncidentExporter:
    """
    Exports incidents as self-contained JSON reports.

    Designed for air-gapped environments:
    - Reports are USB-transferable
    - No external dependencies needed to read
    - Include all evidence and baseline comparisons
    - Fully auditable — deterministic scoring included
    """

    def __init__(self):
        self.timeline_builder = TimelineBuilder()

    def export(self, incident: Incident, alerts: list[Alert]) -> dict:
        """
        Export a complete incident report as a JSON-serializable dict.

        Report includes:
        - Incident metadata (ID, score, classification, status)
        - Timeline (chronological event sequence)
        - Contributing alerts with feature evidence
        - Baseline comparisons for each alert
        - Scoring breakdown (weights, formula, result)
        """
        timeline = self.timeline_builder.build_timeline(incident, alerts)

        # Build alert evidence
        alert_evidence = []
        for alert in sorted(alerts, key=lambda a: a.timestamp):
            alert_evidence.append({
                "alert_id": alert.id,
                "detector": alert.detector_type.value,
                "severity": alert.severity.value,
                "confidence": alert.confidence,
                "z_score": alert.z_score,
                "description": alert.description,
                "features": alert.feature_values,
                "baseline_comparison": alert.baseline_values,
                "timestamp": alert.timestamp,
            })

        report = {
            "report_version": "1.0",
            "generator": "AegisDiode v0.1.0",
            "generated_at": datetime.utcnow().isoformat() + "Z",

            "incident": {
                "id": incident.id,
                "threat_score": incident.threat_score,
                "classification": incident.classification.value,
                "status": incident.status.value,
                "target_ip": incident.target_ip,
                "source_ips": incident.source_ips,
                "affected_flows": incident.affected_flow_ids,
                "description": incident.description,
            },

            "timeline": {
                "start": incident.timeline_start,
                "end": incident.timeline_end,
                "duration_seconds": round(incident.timeline_end - incident.timeline_start, 2),
                "events": timeline,
            },

            "evidence": {
                "total_alerts": len(alerts),
                "detector_types": incident.detector_types,
                "alerts": alert_evidence,
            },

            "scoring": {
                "method": "deterministic_weighted_sum",
                "formula": "Σ(detector_weight × severity_weight × confidence) × normalization",
                "detector_weights": {
                    "iat": 0.25, "size": 0.20, "entropy": 0.30, "rate": 0.25
                },
                "severity_weights": {"LOW": 1, "MEDIUM": 2, "HIGH": 3},
                "result": incident.threat_score,
                "classification_thresholds": {
                    "Low": "<30", "Medium": "30-60", "High": "60-80", "Critical": ">80"
                },
            },
        }

        return report

    def export_json(self, incident: Incident, alerts: list[Alert]) -> str:
        """Export as formatted JSON string."""
        return json.dumps(self.export(incident, alerts), indent=2)
