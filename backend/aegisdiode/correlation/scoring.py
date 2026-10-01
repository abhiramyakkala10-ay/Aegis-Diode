"""
AegisDiode Deterministic Threat Scoring
=========================================
Fully auditable, deterministic scoring — no ML black boxes.
Same inputs always produce the same score.
"""

from __future__ import annotations

from aegisdiode.config import config
from aegisdiode.db.models import Alert, Classification


def compute_threat_score(alerts: list[Alert]) -> float:
    """
    Compute deterministic threat score (0-100) from contributing alerts.

    Formula:
        score = Σ(detector_weight × severity_weight × confidence) × normalization

    Detector weights (from config):
        IAT=0.25, Size=0.20, Entropy=0.30, Rate=0.25

    Severity weights:
        LOW=1, MEDIUM=2, HIGH=3

    The score is deterministic: same alerts always produce the same score.
    This is critical for SOC audit trails — analysts can reproduce any score.
    """
    weights = config.scoring.detector_weights
    severity_weights = config.scoring.severity_weights

    if not alerts:
        return 0.0

    total_score = 0.0
    for alert in alerts:
        detector_weight = weights.get(alert.detector_type.value, 0.25)
        severity_weight = severity_weights.get(alert.severity.value, 1)
        confidence = alert.confidence

        total_score += detector_weight * severity_weight * confidence

    # Normalize to 0-100 scale
    # Maximum possible per detector: weight * 3 (HIGH) * 1.0 (max confidence) = weight * 3
    # Maximum total: Σ weights * 3 = 1.0 * 3 = 3.0
    max_possible = sum(weights.values()) * max(severity_weights.values())
    normalized = (total_score / max(max_possible, 0.01)) * 100

    return round(min(100.0, normalized), 1)


def classify_threat(score: float) -> Classification:
    """
    Classify threat level from score.

    Thresholds (from config):
        < 30 = Low
        30-60 = Medium
        60-80 = High
        > 80 = Critical
    """
    thresholds = config.scoring.classification_thresholds

    if score >= thresholds.get("Critical", 80):
        return Classification.CRITICAL
    elif score >= thresholds.get("High", 60):
        return Classification.HIGH
    elif score >= thresholds.get("Medium", 30):
        return Classification.MEDIUM
    else:
        return Classification.LOW
