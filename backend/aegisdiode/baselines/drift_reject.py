"""
AegisDiode Drift-Rejection Filter
===================================
Prevents gradual baseline poisoning attacks by rejecting
suspicious baseline updates.
"""

from __future__ import annotations

import time

from aegisdiode.config import config
from aegisdiode.db.models import BaselineRecord


class DriftRejectionFilter:
    """
    Prevents gradual baseline poisoning by detecting and rejecting
    suspicious baseline shifts.

    Attack scenario:
    An attacker slowly drifts traffic patterns over hours/days to shift
    the baseline, making future attack traffic appear "normal."

    Defense:
    Before accepting any baseline update, we check if the proposed new
    median has drifted beyond DRIFT_THRESHOLD MADs from the current baseline.
    If so, the update is REJECTED and logged as a security event.

    Algorithm:
    1. Compute candidate new median from latest window
    2. Calculate drift = |new_median - current_median| / current_MAD
    3. If drift > DRIFT_THRESHOLD (default: 3.0), REJECT the update
    4. Log drift-rejection event as a system alert
    """

    def __init__(self):
        self.drift_threshold = config.baseline.drift_threshold

    def check_drift(
        self,
        current: BaselineRecord,
        proposed_median: float,
        current_median: float,
        current_mad: float,
        feature_name: str,
    ) -> tuple[bool, float]:
        """
        Check if a proposed baseline update should be rejected due to drift.

        Returns:
            (accepted: bool, drift_magnitude: float)
        """
        if current.observation_count < config.baseline.min_observations:
            # Not enough data to detect drift yet — accept all updates
            return True, 0.0

        if current_mad <= 0:
            current_mad = 0.001

        drift = abs(proposed_median - current_median) / current_mad

        if drift > self.drift_threshold:
            # REJECT: Suspicious drift detected
            current.drift_rejected_count += 1
            current.last_drift_event = time.time()
            return False, round(drift, 4)

        return True, round(drift, 4)

    def apply_update(
        self,
        current: BaselineRecord,
        proposed_iat_median: float,
        proposed_size_median: float,
        proposed_entropy_median: float,
        proposed_rate_median: float,
        proposed_iat_mad: float,
        proposed_size_mad: float,
        proposed_entropy_mad: float,
        proposed_rate_mad: float,
    ) -> tuple[BaselineRecord, list[dict]]:
        """
        Apply drift-rejection filter to all feature baselines.

        Returns:
            (updated_record, list_of_rejection_events)
        """
        rejections = []

        # Check each feature for drift
        iat_ok, iat_drift = self.check_drift(
            current, proposed_iat_median,
            current.iat_median, current.iat_mad, "iat")
        if iat_ok:
            current.iat_median = proposed_iat_median
            current.iat_mad = proposed_iat_mad
        else:
            rejections.append({
                "feature": "iat", "drift": iat_drift,
                "proposed": proposed_iat_median, "current": current.iat_median,
            })

        size_ok, size_drift = self.check_drift(
            current, proposed_size_median,
            current.size_median, current.size_mad, "size")
        if size_ok:
            current.size_median = proposed_size_median
            current.size_mad = proposed_size_mad
        else:
            rejections.append({
                "feature": "size", "drift": size_drift,
                "proposed": proposed_size_median, "current": current.size_median,
            })

        entropy_ok, entropy_drift = self.check_drift(
            current, proposed_entropy_median,
            current.entropy_median, current.entropy_mad, "entropy")
        if entropy_ok:
            current.entropy_median = proposed_entropy_median
            current.entropy_mad = proposed_entropy_mad
        else:
            rejections.append({
                "feature": "entropy", "drift": entropy_drift,
                "proposed": proposed_entropy_median, "current": current.entropy_median,
            })

        rate_ok, rate_drift = self.check_drift(
            current, proposed_rate_median,
            current.rate_median, current.rate_mad, "rate")
        if rate_ok:
            current.rate_median = proposed_rate_median
            current.rate_mad = proposed_rate_mad
        else:
            rejections.append({
                "feature": "rate", "drift": rate_drift,
                "proposed": proposed_rate_median, "current": current.rate_median,
            })

        current.last_updated = time.time()
        return current, rejections


# Alias for convenience
DriftRejector = DriftRejectionFilter
