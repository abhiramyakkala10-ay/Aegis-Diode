"""
AegisDiode Flow Tracker
========================
Core flow management implementing Zero Gap Initialization.
Creates observation flows on the FIRST packet seen (no SYN required).
"""

from __future__ import annotations

import time
from typing import Optional, Callable, Awaitable

from aegisdiode.db.models import FlowKey, FlowState, ObservationFlow, PacketMeta


class FlowTracker:
    """
    Tracks unidirectional observation flows keyed by 5-tuple.

    Key innovation: Zero Gap Initialization
    - Creates a new flow on the FIRST packet seen (no TCP SYN required)
    - This is critical for unidirectional networks where SYN/ACK handshakes
      are physically impossible due to the data diode
    """

    def __init__(self):
        self._flows: dict[FlowKey, ObservationFlow] = {}
        self._on_new_flow: Optional[Callable[[ObservationFlow], Awaitable[None]]] = None
        self._on_flow_update: Optional[Callable[[ObservationFlow], Awaitable[None]]] = None
        self._total_packets = 0

    def set_callbacks(
        self,
        on_new_flow: Callable[[ObservationFlow], Awaitable[None]] | None = None,
        on_flow_update: Callable[[ObservationFlow], Awaitable[None]] | None = None,
    ):
        """Set event callbacks for flow lifecycle events."""
        self._on_new_flow = on_new_flow
        self._on_flow_update = on_flow_update

    async def process_packet(self, packet: PacketMeta) -> ObservationFlow:
        """
        Process a single packet and assign it to an observation flow.

        Zero Gap Initialization: If no flow exists for this 5-tuple,
        a new flow is created immediately on the first packet.
        """
        self._total_packets += 1
        flow_key = FlowKey(
            src_ip=packet.src_ip,
            dst_ip=packet.dst_ip,
            src_port=packet.src_port,
            dst_port=packet.dst_port,
            protocol=packet.protocol,
        )

        if flow_key in self._flows:
            flow = self._flows[flow_key]
            # Check if flow has expired and needs re-creation
            if flow.state == FlowState.EXPIRED:
                flow = self._create_flow(flow_key, packet)
            else:
                self._update_flow(flow, packet)
                if self._on_flow_update:
                    await self._on_flow_update(flow)
        else:
            # Zero Gap Initialization — create flow on first packet
            flow = self._create_flow(flow_key, packet)

        return flow

    def _create_flow(self, flow_key: FlowKey, packet: PacketMeta) -> ObservationFlow:
        """Create a new observation flow from the first packet."""
        flow = ObservationFlow(
            flow_key=flow_key,
            state=FlowState.ACTIVE,
            first_seen=packet.timestamp,
            last_seen=packet.timestamp,
            packet_count=1,
            byte_count=packet.size,
            packets=[packet],
        )
        self._flows[flow_key] = flow
        return flow

    def _update_flow(self, flow: ObservationFlow, packet: PacketMeta) -> None:
        """Update an existing flow with a new packet."""
        flow.last_seen = packet.timestamp
        flow.packet_count += 1
        flow.byte_count += packet.size
        flow.state = FlowState.ACTIVE
        flow.packets.append(packet)

    def get_flow(self, flow_key: FlowKey) -> Optional[ObservationFlow]:
        """Get a flow by its 5-tuple key."""
        return self._flows.get(flow_key)

    def get_all_flows(self) -> list[ObservationFlow]:
        """Get all tracked flows."""
        return list(self._flows.values())

    def get_active_flows(self) -> list[ObservationFlow]:
        """Get all active (non-expired) flows."""
        return [f for f in self._flows.values() if f.state != FlowState.EXPIRED]

    def expire_flow(self, flow_key: FlowKey) -> Optional[ObservationFlow]:
        """Mark a flow as expired and return it for final processing."""
        flow = self._flows.get(flow_key)
        if flow:
            flow.state = FlowState.EXPIRED
        return flow

    def remove_flow(self, flow_key: FlowKey) -> Optional[ObservationFlow]:
        """Remove a flow from tracking entirely."""
        return self._flows.pop(flow_key, None)

    @property
    def active_count(self) -> int:
        return sum(1 for f in self._flows.values() if f.state == FlowState.ACTIVE)

    @property
    def total_count(self) -> int:
        return len(self._flows)

    @property
    def total_packets(self) -> int:
        return self._total_packets
