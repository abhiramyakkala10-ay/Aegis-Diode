"""
AegisDiode Size Anomaly Detector
==================================
Detects anomalous packet size distributions using KL divergence.
"""

from __future__ import annotations

import time
import numpy as np

from aegisdiode.config import config
from aegisdiode.db.models import (
    Alert, BaselineRecord, DetectorType, FlowFeatures, Severity,
)


def _kl_divergence(p: list[float], q: list[float]) -> float:
    """
    Compute Kullback-Leibler divergence between two probability distributions.
    D_KL(P || Q) = Σ P(x) * log(P(x) / Q(x))

    Uses smoothing to avoid log(0) issues.
    """
    epsilon = 1e-10
    p_arr = np.array(p, dtype=np.float64) + epsilon
    q_arr = np.array(q, dtype=np.float64) + epsilon

    # Normalize
    p_arr = p_arr / p_arr.sum()
    q_arr = q_arr / q_arr.sum()

    return float(np.sum(p_arr * np.log(p_arr / q_arr)))


def detect_size_anomaly(
    features: FlowFeatures,
    baseline: BaselineRecord,
    z_score: float,
    baseline_histogram: list[float] | None = None,
    flow_key_str: str = "",
) -> Alert | None:
    """
    Size anomaly detector.

    Fires when:
    1. Size z-score exceeds threshold
    2. KL divergence between observed and baseline size histograms is high
    3. Uniform packet sizes (structured exfiltration pattern)
    """
    threshold = config.detector.size_kl_threshold

    # Check for uniform packet sizes (potential data exfiltration)
    if features.size.std < 1.0 and features.packet_count > 10 and features.size.mean > 500:
        return Alert(
            flow_id=features.flow_id,
            flow_key_str=flow_key_str,
            detector_type=DetectorType.SIZE,
            severity=Severity.MEDIUM,
            confidence=0.8,
            z_score=z_score,
            description=f"Uniform packet sizes detected: mean={features.size.mean:.0f}B, "
                        f"std={features.size.std:.2f}B — potential structured data exfiltration",
            feature_values={
                "size_mean": features.size.mean,
                "size_std": features.size.std,
                "bytes_per_sec": features.size.bytes_per_sec,
            },
            baseline_values={
                "size_median": baseline.size_median,
                "size_mad": baseline.size_mad,
            },
            timestamp=time.time(),
        )

    # Check KL divergence against baseline histogram
    if baseline_histogram and features.size.histogram:
        kl_div = _kl_divergence(features.size.histogram, baseline_histogram)
        if kl_div > threshold:
            severity = Severity.HIGH if kl_div > threshold * 2 else Severity.MEDIUM

            return Alert(
                flow_id=features.flow_id,
                flow_key_str=flow_key_str,
                detector_type=DetectorType.SIZE,
                severity=severity,
                confidence=min(1.0, kl_div / (threshold * 3)),
                z_score=z_score,
                description=f"Size distribution anomaly: KL divergence={kl_div:.3f} "
                            f"(threshold: {threshold})",
                feature_values={
                    "size_mean": features.size.mean,
                    "kl_divergence": round(kl_div, 4),
                    "histogram": features.size.histogram,
                },
                baseline_values={
                    "size_median": baseline.size_median,
                    "baseline_histogram": baseline_histogram,
                },
                timestamp=time.time(),
            )

    # Fall back to z-score check
    if z_score > config.detector.iat_z_threshold:
        severity = Severity.MEDIUM if z_score > 4 else Severity.LOW

        return Alert(
            flow_id=features.flow_id,
            flow_key_str=flow_key_str,
            detector_type=DetectorType.SIZE,
            severity=severity,
            confidence=min(1.0, (z_score - config.detector.iat_z_threshold) / 5.0),
            z_score=z_score,
            description=f"Size anomaly: z-score={z_score:.2f} (mean={features.size.mean:.0f}B, "
                        f"baseline={baseline.size_median:.0f}B)",
            feature_values={"size_mean": features.size.mean, "size_std": features.size.std},
            baseline_values={"size_median": baseline.size_median, "size_mad": baseline.size_mad},
            timestamp=time.time(),
        )

    return None


class SizeDetector:
    """Class wrapper for Size anomaly evaluation."""

    def evaluate(self, features: FlowFeatures, baseline: BaselineRecord, flow_key_str: str = "") -> Alert | None:
        mad = baseline.size_mad if baseline.size_mad > 0 else 0.001
        z_score = abs(0.6745 * (features.size.mean - baseline.size_median) / mad)
        return detect_size_anomaly(features, baseline, z_score, flow_key_str=flow_key_str)
