"""
AegisDiode Rate Anomaly Detector
==================================
Detects anomalous flow creation rates (port scans, DoS).
"""

from __future__ import annotations

import time

from aegisdiode.config import config
from aegisdiode.db.models import (
    Alert, BaselineRecord, DetectorType, FlowFeatures, Severity,
)


def detect_rate_anomaly(
    features: FlowFeatures,
    baseline: BaselineRecord,
    z_score: float,
    current_rate: float = 0.0,
    flow_key_str: str = "",
) -> Alert | None:
    """
    Flow-rate anomaly detector.

    Fires when:
    1. Bytes-per-second z-score exceeds threshold
    2. Flow creation rate spikes (many new flows in short time)

    Detects:
    - Port scans: Many flows, few packets each
    - DoS floods: Many flows AND many packets
    - Volumetric attacks: Extreme bytes-per-second
    """
    threshold = config.detector.rate_z_threshold

    if z_score > threshold:
        # Determine if this is a scan vs flood
        is_scan = features.packet_count < 5  # Few packets per flow = scan
        is_flood = features.size.bytes_per_sec > baseline.rate_median * 10

        if is_flood:
            severity = Severity.HIGH
            desc_type = "Volumetric flood"
        elif is_scan:
            severity = Severity.MEDIUM
            desc_type = "Port scan pattern"
        else:
            severity = Severity.LOW
            desc_type = "Rate anomaly"

        if z_score > threshold + 2:
            severity = Severity.HIGH

        confidence = min(1.0, (z_score - threshold) / 5.0)

        return Alert(
            flow_id=features.flow_id,
            flow_key_str=flow_key_str,
            detector_type=DetectorType.RATE,
            severity=severity,
            confidence=confidence,
            z_score=z_score,
            description=f"{desc_type}: rate z-score={z_score:.2f}, "
                        f"bytes/sec={features.size.bytes_per_sec:.0f} "
                        f"(baseline={baseline.rate_median:.0f})",
            feature_values={
                "bytes_per_sec": features.size.bytes_per_sec,
                "packet_count": features.packet_count,
                "current_rate": current_rate,
            },
            baseline_values={
                "rate_median": baseline.rate_median,
                "rate_mad": baseline.rate_mad,
            },
            timestamp=time.time(),
        )

    return None


class RateDetector:
    """Class wrapper for Rate anomaly evaluation."""

    def evaluate(self, features: FlowFeatures, baseline: BaselineRecord, flow_key_str: str = "") -> Alert | None:
        mad = baseline.rate_mad if baseline.rate_mad > 0 else 0.001
        z_score = abs(0.6745 * (features.size.bytes_per_sec - baseline.rate_median) / mad)
        return detect_rate_anomaly(features, baseline, z_score, flow_key_str=flow_key_str)
