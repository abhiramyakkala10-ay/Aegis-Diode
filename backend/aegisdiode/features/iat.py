"""
AegisDiode IAT Feature Extraction
===================================
Inter-Arrival Time analysis for observation flows.
"""

from __future__ import annotations

import numpy as np

from aegisdiode.db.models import IATFeatures, PacketMeta


def compute_iat_features(packets: list[PacketMeta]) -> IATFeatures:
    """
    Compute Inter-Arrival Time features from a list of packets.

    IAT (Inter-Arrival Time) measures the time gap between consecutive packets.
    In unidirectional traffic, IAT patterns reveal:
    - Regular intervals → C2 beaconing
    - Very small IATs → flood/DoS
    - Highly variable IATs → normal browsing
    - Zero IATs → burst traffic
    """
    if len(packets) < 2:
        return IATFeatures()

    timestamps = np.array([p.timestamp for p in packets])
    timestamps.sort()

    # Compute inter-arrival times
    iats = np.diff(timestamps)

    if len(iats) == 0:
        return IATFeatures()

    # Filter out negative or zero IATs (clock issues)
    iats = iats[iats >= 0]

    if len(iats) == 0:
        return IATFeatures()

    mean_val = float(np.mean(iats))
    std_val = float(np.std(iats))
    min_val = float(np.min(iats))
    max_val = float(np.max(iats))
    median_val = float(np.median(iats))

    # Coefficient of variation (CV) — key for beaconing detection
    # Low CV (< 0.05) = suspiciously regular intervals
    cv = float(std_val / mean_val) if mean_val > 0 else 0.0

    return IATFeatures(
        mean=round(mean_val, 6),
        std=round(std_val, 6),
        min=round(min_val, 6),
        max=round(max_val, 6),
        median=round(median_val, 6),
        cv=round(cv, 6),
    )
