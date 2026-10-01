"""
AegisDiode Rolling Statistics
==============================
Rolling statistical baselines using EWMA and robust dispersion measures.
"""

from __future__ import annotations

import time
from collections import deque

import numpy as np

from aegisdiode.config import config
from aegisdiode.db.models import BaselineRecord, FlowFeatures


class RollingBaseline:
    """
    Maintains per-feature rolling baselines using:
    - Exponentially Weighted Moving Average (EWMA) for central tendency
    - Median Absolute Deviation (MAD) for robust dispersion

    The MAD-based approach is more resistant to outliers than standard deviation,
    which is critical in adversarial environments where attackers may inject
    outlier traffic to inflate baselines.
    """

    def __init__(self, pattern_key: str):
        self.pattern_key = pattern_key
        self.window_size = config.baseline.window_size
        self.alpha = config.baseline.ewma_alpha
        self.min_observations = config.baseline.min_observations

        # Rolling windows for each feature
        self._iat_window: deque[float] = deque(maxlen=self.window_size)
        self._size_window: deque[float] = deque(maxlen=self.window_size)
        self._entropy_window: deque[float] = deque(maxlen=self.window_size)
        self._rate_window: deque[float] = deque(maxlen=self.window_size)

        # Current baseline record
        self.record = BaselineRecord(pattern_key=pattern_key)

    @property
    def is_ready(self) -> bool:
        """Whether enough observations have been collected for anomaly detection."""
        return self.record.observation_count >= self.min_observations

    def update(self, features: FlowFeatures) -> BaselineRecord:
        """
        Update baselines with new feature observations.
        Returns the updated BaselineRecord.
        """
        # Add to rolling windows
        self._iat_window.append(features.iat.mean)
        self._size_window.append(features.size.mean)
        self._entropy_window.append(features.entropy.value)
        self._rate_window.append(features.size.bytes_per_sec)

        self.record.observation_count += 1
        self.record.last_updated = time.time()

        # Recompute medians and MADs
        if len(self._iat_window) >= self.min_observations:
            self.record.iat_median, self.record.iat_mad = self._compute_median_mad(
                self._iat_window)
            self.record.size_median, self.record.size_mad = self._compute_median_mad(
                self._size_window)
            self.record.entropy_median, self.record.entropy_mad = self._compute_median_mad(
                self._entropy_window)
            self.record.rate_median, self.record.rate_mad = self._compute_median_mad(
                self._rate_window)

        return self.record

    def compute_z_score(self, observed: float, median: float, mad: float) -> float:
        """
        Compute modified z-score using median and MAD.
        Z = 0.6745 * (observed - median) / MAD

        The 0.6745 factor normalizes MAD to be consistent with standard deviation
        for normally distributed data.
        """
        if mad <= 0:
            mad = 0.001  # Prevent division by zero
        return abs(0.6745 * (observed - median) / mad)

    def get_z_scores(self, features: FlowFeatures) -> dict[str, float]:
        """Compute z-scores for all features against current baseline."""
        if not self.is_ready:
            return {"iat": 0.0, "size": 0.0, "entropy": 0.0, "rate": 0.0}

        return {
            "iat": self.compute_z_score(
                features.iat.mean, self.record.iat_median, self.record.iat_mad),
            "size": self.compute_z_score(
                features.size.mean, self.record.size_median, self.record.size_mad),
            "entropy": self.compute_z_score(
                features.entropy.value, self.record.entropy_median, self.record.entropy_mad),
            "rate": self.compute_z_score(
                features.size.bytes_per_sec, self.record.rate_median, self.record.rate_mad),
        }

    @staticmethod
    def _compute_median_mad(window: deque) -> tuple[float, float]:
        """Compute median and Median Absolute Deviation."""
        arr = np.array(list(window))
        median = float(np.median(arr))
        mad = float(np.median(np.abs(arr - median)))
        # Ensure MAD is never zero (prevents infinite z-scores)
        mad = max(mad, 0.001)
        return round(median, 6), round(mad, 6)

    def load_from_record(self, record: BaselineRecord) -> None:
        """Load baseline state from a persisted record."""
        self.record = record


class BaselineManager:
    """Manages rolling baselines across all flow key patterns with DB persistence."""

    def __init__(self):
        self._baselines: dict[str, RollingBaseline] = {}

    def get_or_create(self, pattern_key: str) -> RollingBaseline:
        if pattern_key not in self._baselines:
            self._baselines[pattern_key] = RollingBaseline(pattern_key)
        return self._baselines[pattern_key]

    async def get_baseline(self, pattern_key: str) -> BaselineRecord | None:
        from aegisdiode.db.repository import repository
        b_dict = await repository.get_baseline(pattern_key)
        if b_dict:
            rec = BaselineRecord(
                id=b_dict.get("id", ""),
                pattern_key=pattern_key,
                observation_count=b_dict.get("observation_count", 0),
                last_updated=b_dict.get("last_updated", 0.0),
                iat_median=b_dict.get("iat_median", 0.0),
                iat_mad=b_dict.get("iat_mad", 1.0),
                size_median=b_dict.get("size_median", 0.0),
                size_mad=b_dict.get("size_mad", 1.0),
                entropy_median=b_dict.get("entropy_median", 0.0),
                entropy_mad=b_dict.get("entropy_mad", 1.0),
                rate_median=b_dict.get("rate_median", 0.0),
                rate_mad=b_dict.get("rate_mad", 1.0),
                drift_rejected_count=b_dict.get("drift_rejected_count", 0),
                last_drift_event=b_dict.get("last_drift_event"),
            )
            rb = self.get_or_create(pattern_key)
            rb.load_from_record(rec)
            return rec
        else:
            rb = self.get_or_create(pattern_key)
            return rb.record if rb.is_ready else None

    async def update_baseline(self, pattern_key: str, features: FlowFeatures) -> tuple[BaselineRecord, list[dict]]:
        from aegisdiode.db.repository import repository
        from aegisdiode.baselines.drift_reject import DriftRejectionFilter

        rb = self.get_or_create(pattern_key)
        old_record = rb.record.model_copy()

        # Compute proposed new values
        proposed_record = rb.update(features)

        # Apply drift rejection filter
        drift_filter = DriftRejectionFilter()
        final_record, rejections = drift_filter.apply_update(
            current=old_record,
            proposed_iat_median=proposed_record.iat_median,
            proposed_size_median=proposed_record.size_median,
            proposed_entropy_median=proposed_record.entropy_median,
            proposed_rate_median=proposed_record.rate_median,
            proposed_iat_mad=proposed_record.iat_mad,
            proposed_size_mad=proposed_record.size_mad,
            proposed_entropy_mad=proposed_record.entropy_mad,
            proposed_rate_mad=proposed_record.rate_mad,
        )

        rb.record = final_record
        await repository.upsert_baseline(final_record)
        return final_record, rejections
