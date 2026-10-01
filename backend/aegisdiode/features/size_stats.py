"""
AegisDiode Packet Size Statistics
===================================
Size distribution analysis for observation flows.
"""

from __future__ import annotations

import numpy as np

from aegisdiode.db.models import SizeFeatures, PacketMeta
from aegisdiode.config import config


def compute_size_features(packets: list[PacketMeta]) -> SizeFeatures:
    """
    Compute packet size statistics from a list of packets.

    Size patterns reveal:
    - Uniform large packets → data exfiltration (structured payloads)
    - Very small packets → control traffic / beaconing
    - Bimodal distribution → mixed request/response traffic
    - Sudden size changes → protocol switching / tunneling
    """
    if not packets:
        return SizeFeatures()

    sizes = np.array([p.size for p in packets], dtype=np.float64)

    if len(sizes) == 0:
        return SizeFeatures()

    mean_val = float(np.mean(sizes))
    std_val = float(np.std(sizes))
    min_val = float(np.min(sizes))
    max_val = float(np.max(sizes))

    # Bytes per second
    if len(packets) >= 2:
        duration = packets[-1].timestamp - packets[0].timestamp
        bytes_per_sec = float(np.sum(sizes)) / max(duration, 0.001)
    else:
        bytes_per_sec = 0.0

    # Size distribution histogram (8 bins, 0-1500 bytes)
    bins = config.feature.size_histogram_bins
    hist, _ = np.histogram(sizes, bins=bins, range=(0, 1500))
    total = hist.sum()
    histogram = (hist / max(total, 1)).tolist()  # Normalize to probabilities

    return SizeFeatures(
        mean=round(mean_val, 2),
        std=round(std_val, 2),
        min=round(min_val, 2),
        max=round(max_val, 2),
        bytes_per_sec=round(bytes_per_sec, 2),
        histogram=[round(h, 4) for h in histogram],
    )
