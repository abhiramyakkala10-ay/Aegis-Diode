"""
AegisDiode Feature Extraction Package
======================================
Statistical feature extraction from observation flows.
"""

from __future__ import annotations

from aegisdiode.db.models import FlowFeatures, IATFeatures, SizeFeatures, EntropyFeatures, PacketMeta
from aegisdiode.features.iat import compute_iat_features
from aegisdiode.features.size_stats import compute_size_features
from aegisdiode.features.entropy import compute_entropy_features

import time


class FeatureExtractor:
    """Orchestrates feature extraction for a flow's packet window."""

    def extract(self, flow_id: str, packets: list[PacketMeta]) -> FlowFeatures:
        """
        Extract complete feature vector from a list of packets.

        Args:
            flow_id: The observation flow ID
            packets: List of PacketMeta objects in the extraction window
        """
        if len(packets) < 2:
            return FlowFeatures(flow_id=flow_id, timestamp=time.time(), packet_count=len(packets))

        iat = compute_iat_features(packets)
        size = compute_size_features(packets)
        entropy = compute_entropy_features(packets)

        return FlowFeatures(
            flow_id=flow_id,
            timestamp=time.time(),
            packet_count=len(packets),
            iat=iat,
            size=size,
            entropy=entropy,
        )

    def extract_features(self, flow) -> FlowFeatures | None:
        """Convenience method extracting features directly from an ObservationFlow."""
        if not flow.packets or len(flow.packets) < 2:
            return None
        return self.extract(flow.id, flow.packets)
