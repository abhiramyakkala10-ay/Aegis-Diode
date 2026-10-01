"""
AegisDiode Packet Reader
=========================
Reads packets from PCAP files or synthetic generators and yields PacketMeta objects.
Designed for demo mode — production would use Go + AF_PACKET.
"""

from __future__ import annotations

import asyncio
import time
from typing import AsyncGenerator

from aegisdiode.db.models import PacketMeta


class PcapReader:
    """Reads packets from a PCAP file and yields PacketMeta objects."""

    def __init__(self, pcap_path: str, realtime: bool = True):
        """
        Args:
            pcap_path: Path to .pcap file
            realtime: If True, replay packets at original inter-arrival times
        """
        self.pcap_path = pcap_path
        self.realtime = realtime

    async def read_packets(self) -> AsyncGenerator[PacketMeta, None]:
        """Async generator yielding packets from the PCAP file."""
        # Import scapy lazily to avoid startup overhead
        from scapy.all import rdpcap, IP, TCP, UDP

        packets = rdpcap(self.pcap_path)
        prev_time = None

        for pkt in packets:
            if IP not in pkt:
                continue

            ip = pkt[IP]
            src_port = 0
            dst_port = 0
            protocol = ip.proto

            if TCP in pkt:
                src_port = pkt[TCP].sport
                dst_port = pkt[TCP].dport
            elif UDP in pkt:
                src_port = pkt[UDP].sport
                dst_port = pkt[UDP].dport

            # Extract payload bytes for entropy computation
            payload = bytes(pkt.payload.payload.payload) if pkt.payload and pkt.payload.payload else b""

            meta = PacketMeta(
                timestamp=float(pkt.time),
                src_ip=ip.src,
                dst_ip=ip.dst,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                size=len(pkt),
                payload_bytes=payload[:256],  # Cap at 256 bytes for entropy
            )

            # Simulate real-time replay
            if self.realtime and prev_time is not None:
                delay = float(pkt.time) - prev_time
                if 0 < delay < 5.0:  # Cap delays at 5 seconds
                    await asyncio.sleep(delay)

            prev_time = float(pkt.time)
            yield meta


class SyntheticPacketSource:
    """Wraps a traffic generator as an async packet source."""

    def __init__(self):
        self._queue: asyncio.Queue[PacketMeta] = asyncio.Queue(maxsize=10000)
        self._running = False

    async def push(self, packet: PacketMeta) -> None:
        """Push a packet into the source queue."""
        await self._queue.put(packet)

    async def read_packets(self) -> AsyncGenerator[PacketMeta, None]:
        """Async generator that yields packets from the internal queue."""
        self._running = True
        while self._running:
            try:
                packet = await asyncio.wait_for(self._queue.get(), timeout=1.0)
                yield packet
            except asyncio.TimeoutError:
                continue

    def stop(self) -> None:
        """Stop the packet source."""
        self._running = False
