"""
AegisDiode IAT Anomaly Detector
=================================
Detects anomalous inter-arrival time patterns including beaconing.
"""

from __future__ import annotations

import time

from aegisdiode.config import config
from aegisdiode.db.models import (
    Alert, BaselineRecord, DetectorType, FlowFeatures, Severity,
)


def detect_iat_anomaly(
    features: FlowFeatures,
    baseline: BaselineRecord,
    z_score: float,
    flow_key_str: str = "",
) -> Alert | None:
    """
    IAT anomaly detector.

    Fires when:
    1. IAT z-score exceeds threshold (deviation from baseline)
    2. IAT coefficient of variation is suspiciously low (beaconing)

    Beaconing detection:
    C2 callbacks typically have very regular timing (CV < 0.05).
    Normal traffic has high variability in packet timing.
    """
    threshold = config.detector.iat_z_threshold
    beaconing_cv = config.detector.beaconing_cv_threshold

    # Check for beaconing (regular intervals)
    if features.iat.cv > 0 and features.iat.cv < beaconing_cv and features.packet_count > 10:
        return Alert(
            flow_id=features.flow_id,
            flow_key_str=flow_key_str,
            detector_type=DetectorType.IAT,
            severity=Severity.HIGH,
            confidence=min(1.0, (beaconing_cv - features.iat.cv) / beaconing_cv),
            z_score=z_score,
            description=f"C2 Beaconing suspected: IAT CV={features.iat.cv:.4f} (threshold: {beaconing_cv}). "
                        f"Mean interval: {features.iat.mean:.3f}s",
            feature_values={
                "iat_mean": features.iat.mean,
                "iat_std": features.iat.std,
                "iat_cv": features.iat.cv,
            },
            baseline_values={
                "iat_median": baseline.iat_median,
                "iat_mad": baseline.iat_mad,
            },
            timestamp=time.time(),
        )

    # Check for general IAT anomaly
    if z_score > threshold:
        if z_score > threshold + 2:
            severity = Severity.HIGH
        elif z_score > threshold + 1:
            severity = Severity.MEDIUM
        else:
            severity = Severity.LOW

        confidence = min(1.0, (z_score - threshold) / 5.0)

        return Alert(
            flow_id=features.flow_id,
            flow_key_str=flow_key_str,
            detector_type=DetectorType.IAT,
            severity=severity,
            confidence=confidence,
            z_score=z_score,
            description=f"IAT anomaly: z-score={z_score:.2f} (mean={features.iat.mean:.4f}s, "
                        f"baseline={baseline.iat_median:.4f}s)",
            feature_values={
                "iat_mean": features.iat.mean,
                "iat_std": features.iat.std,
                "iat_cv": features.iat.cv,
            },
            baseline_values={
                "iat_median": baseline.iat_median,
                "iat_mad": baseline.iat_mad,
            },
            timestamp=time.time(),
        )

    return None


class IatDetector:
    """Class wrapper for IAT anomaly evaluation."""

    def evaluate(self, features: FlowFeatures, baseline: BaselineRecord, flow_key_str: str = "") -> Alert | None:
        mad = baseline.iat_mad if baseline.iat_mad > 0 else 0.001
        z_score = abs(0.6745 * (features.iat.mean - baseline.iat_median) / mad)
        return detect_iat_anomaly(features, baseline, z_score, flow_key_str=flow_key_str)
