"""
AegisDiode Entropy Anomaly Detector
=====================================
Detects anomalous Shannon entropy patterns in packet payloads.
"""

from __future__ import annotations

import time

from aegisdiode.config import config
from aegisdiode.db.models import (
    Alert, BaselineRecord, DetectorType, FlowFeatures, Severity,
)


def detect_entropy_anomaly(
    features: FlowFeatures,
    baseline: BaselineRecord,
    z_score: float,
    flow_key_str: str = "",
) -> Alert | None:
    """
    Entropy anomaly detector.

    Fires when:
    1. Entropy z-score exceeds threshold (deviation from baseline)
    2. Entropy > 7.5 — encrypted/compressed data (potential exfiltration)
    3. Entropy < 1.0 — padding/null traffic (potential covert channel)
    4. Rapid entropy change rate (sudden encryption onset)
    """
    entropy = features.entropy.value
    high_threshold = config.detector.high_entropy_threshold
    low_threshold = config.detector.low_entropy_threshold

    # Check for encrypted/compressed data (exfiltration)
    if entropy > high_threshold:
        return Alert(
            flow_id=features.flow_id,
            flow_key_str=flow_key_str,
            detector_type=DetectorType.ENTROPY,
            severity=Severity.HIGH,
            confidence=min(1.0, (entropy - high_threshold) / 0.5),
            z_score=z_score,
            description=f"High entropy detected: {entropy:.3f} bits (>{high_threshold}) — "
                        f"encrypted/compressed data, potential exfiltration",
            feature_values={
                "entropy": entropy,
                "entropy_change_rate": features.entropy.change_rate,
            },
            baseline_values={
                "entropy_median": baseline.entropy_median,
                "entropy_mad": baseline.entropy_mad,
            },
            timestamp=time.time(),
        )

    # Check for covert channel (very low entropy)
    if entropy < low_threshold and features.packet_count > 5:
        return Alert(
            flow_id=features.flow_id,
            flow_key_str=flow_key_str,
            detector_type=DetectorType.ENTROPY,
            severity=Severity.MEDIUM,
            confidence=min(1.0, (low_threshold - entropy) / low_threshold),
            z_score=z_score,
            description=f"Low entropy detected: {entropy:.3f} bits (<{low_threshold}) — "
                        f"padding/null data, potential covert channel",
            feature_values={
                "entropy": entropy,
                "entropy_change_rate": features.entropy.change_rate,
            },
            baseline_values={
                "entropy_median": baseline.entropy_median,
                "entropy_mad": baseline.entropy_mad,
            },
            timestamp=time.time(),
        )

    # Check for entropy z-score anomaly
    if z_score > config.detector.entropy_z_threshold:
        if z_score > config.detector.entropy_z_threshold + 2:
            severity = Severity.HIGH
        elif z_score > config.detector.entropy_z_threshold + 1:
            severity = Severity.MEDIUM
        else:
            severity = Severity.LOW

        return Alert(
            flow_id=features.flow_id,
            flow_key_str=flow_key_str,
            detector_type=DetectorType.ENTROPY,
            severity=severity,
            confidence=min(1.0, (z_score - config.detector.entropy_z_threshold) / 5.0),
            z_score=z_score,
            description=f"Entropy anomaly: z-score={z_score:.2f} (value={entropy:.3f}, "
                        f"baseline={baseline.entropy_median:.3f})",
            feature_values={
                "entropy": entropy,
                "entropy_change_rate": features.entropy.change_rate,
            },
            baseline_values={
                "entropy_median": baseline.entropy_median,
                "entropy_mad": baseline.entropy_mad,
            },
            timestamp=time.time(),
        )

    return None


class EntropyDetector:
    """Class wrapper for Entropy anomaly evaluation."""

    def evaluate(self, features: FlowFeatures, baseline: BaselineRecord, flow_key_str: str = "") -> Alert | None:
        mad = baseline.entropy_mad if baseline.entropy_mad > 0 else 0.001
        z_score = abs(0.6745 * (features.entropy.value - baseline.entropy_median) / mad)
        return detect_entropy_anomaly(features, baseline, z_score, flow_key_str=flow_key_str)
