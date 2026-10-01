"""
AegisDiode Shannon Entropy Computation
========================================
Byte-level entropy analysis for packet payloads.
"""

from __future__ import annotations

import math
from collections import Counter

import numpy as np

from aegisdiode.db.models import EntropyFeatures, PacketMeta


def compute_shannon_entropy(data: bytes) -> float:
    """
    Compute Shannon entropy of a byte sequence.

    Returns value between 0.0 and 8.0 bits:
    - 0.0 = all identical bytes (completely predictable)
    - 8.0 = perfectly uniform distribution (maximum randomness)

    Significance in threat detection:
    - > 7.5 = encrypted/compressed data (potential exfiltration)
    - < 1.0 = padding/null bytes (potential covert channel)
    - 4.0-6.0 = typical plaintext/protocol data
    """
    if not data:
        return 0.0

    # Count byte occurrences
    byte_counts = Counter(data)
    total = len(data)

    # Shannon entropy formula: H = -Σ p(x) * log2(p(x))
    entropy = 0.0
    for count in byte_counts.values():
        if count > 0:
            probability = count / total
            entropy -= probability * math.log2(probability)

    return round(entropy, 4)


def compute_entropy_features(
    packets: list[PacketMeta],
    prev_entropy: float | None = None,
) -> EntropyFeatures:
    """
    Compute entropy features from packet payloads in a flow window.

    Concatenates all payload bytes and computes overall entropy,
    plus entropy change rate if previous entropy is available.
    """
    if not packets:
        return EntropyFeatures()

    # Concatenate all payload bytes
    all_payload = b""
    for pkt in packets:
        if pkt.payload_bytes:
            all_payload += pkt.payload_bytes

    if not all_payload:
        # No payload data — compute from packet sizes as proxy
        size_bytes = bytes([min(p.size, 255) for p in packets])
        entropy_value = compute_shannon_entropy(size_bytes)
    else:
        # Sample if payload is very large
        sample = all_payload[:1024]
        entropy_value = compute_shannon_entropy(sample)

    # Entropy change rate
    change_rate = 0.0
    if prev_entropy is not None:
        change_rate = entropy_value - prev_entropy

    return EntropyFeatures(
        value=entropy_value,
        change_rate=round(change_rate, 4),
    )
