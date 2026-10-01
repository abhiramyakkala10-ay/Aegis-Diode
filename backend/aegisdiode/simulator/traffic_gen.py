"""
AegisDiode Traffic Generator
==============================
Generates realistic synthetic unidirectional network traffic for demo purposes.
"""

from __future__ import annotations

import asyncio
import random
import time
from typing import Optional

from aegisdiode.capture.packet_reader import SyntheticPacketSource
from aegisdiode.db.models import PacketMeta
from aegisdiode.simulator.attack_patterns import ATTACK_GENERATORS


# Realistic IP ranges for simulation
INTERNAL_IPS = [f"192.168.1.{i}" for i in range(10, 50)]
EXTERNAL_IPS = [f"10.0.0.{i}" for i in range(1, 30)]
COMMON_PORTS = [80, 443, 8080, 8443, 53, 22, 3389, 25, 110, 993]


class TrafficGenerator:
    """
    Generates synthetic unidirectional network traffic.

    Produces a mix of:
    - Normal HTTP/HTTPS browsing traffic
    - DNS queries
    - Background service traffic
    - Configurable attack pattern injection
    """

    def __init__(self, packet_source: SyntheticPacketSource):
        self.source = packet_source
        self._running = False
        self._task: Optional[asyncio.Task] = None
        self._packets_generated = 0
        self._attacks_injected = 0

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def stats(self) -> dict:
        return {
            "running": self._running,
            "packets_generated": self._packets_generated,
            "attacks_injected": self._attacks_injected,
        }

    async def start(self, packets_per_sec: float = 50.0) -> None:
        """Start generating background traffic."""
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._generate_loop(packets_per_sec))

    async def stop(self) -> None:
        """Stop traffic generation."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    async def inject_attack(self, attack_type: str) -> dict:
        """
        Inject a specific attack pattern into the traffic stream.

        Args:
            attack_type: One of: port_scan, data_exfil, dos_flood, beaconing, slow_poison

        Returns:
            dict with attack details
        """
        generator = ATTACK_GENERATORS.get(attack_type)
        if not generator:
            return {"error": f"Unknown attack type: {attack_type}",
                    "available": list(ATTACK_GENERATORS.keys())}

        base_time = time.time()
        packets = generator(base_time=base_time)

        # Feed packets into the pipeline
        injected = 0
        for pkt in packets:
            await self.source.push(pkt)
            injected += 1
            # Small delay to avoid overwhelming the queue
            if injected % 50 == 0:
                await asyncio.sleep(0.01)

        self._attacks_injected += 1
        self._packets_generated += injected

        return {
            "attack_type": attack_type,
            "packets_injected": injected,
            "timestamp": base_time,
        }

    async def _generate_loop(self, pps: float) -> None:
        """Main traffic generation loop."""
        interval = 1.0 / max(pps, 1)

        while self._running:
            try:
                packet = self._generate_normal_packet()
                await self.source.push(packet)
                self._packets_generated += 1

                # Add some burstiness
                if random.random() < 0.1:
                    # Burst: send 5-10 packets quickly
                    burst_size = random.randint(5, 10)
                    for _ in range(burst_size):
                        pkt = self._generate_normal_packet()
                        await self.source.push(pkt)
                        self._packets_generated += 1
                    await asyncio.sleep(interval * 2)
                else:
                    await asyncio.sleep(interval * random.uniform(0.5, 1.5))

            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"[TrafficGen] Error: {e}")
                await asyncio.sleep(0.1)

    def _generate_normal_packet(self) -> PacketMeta:
        """Generate a single normal traffic packet."""
        traffic_type = random.choices(
            ["http", "https", "dns", "ssh", "other"],
            weights=[30, 40, 15, 5, 10],
        )[0]

        src_ip = random.choice(INTERNAL_IPS)
        dst_ip = random.choice(EXTERNAL_IPS)
        protocol = 6  # TCP

        if traffic_type == "http":
            dst_port = 80
            size = random.choice([
                random.randint(64, 200),   # Request
                random.randint(200, 1400),  # Response
            ])
            payload = bytes([random.randint(32, 126) for _ in range(min(size, 128))])

        elif traffic_type == "https":
            dst_port = 443
            size = random.randint(100, 1400)
            # HTTPS has higher entropy due to TLS
            payload = bytes([random.randint(0, 255) for _ in range(min(size, 128))])

        elif traffic_type == "dns":
            dst_port = 53
            protocol = 17  # UDP
            size = random.randint(40, 512)
            payload = bytes([random.randint(0, 255) for _ in range(min(size, 64))])

        elif traffic_type == "ssh":
            dst_port = 22
            size = random.randint(64, 500)
            payload = bytes([random.randint(0, 255) for _ in range(min(size, 64))])

        else:
            dst_port = random.choice(COMMON_PORTS)
            size = random.randint(64, 1000)
            payload = bytes([random.randint(32, 126) for _ in range(min(size, 64))])

        return PacketMeta(
            timestamp=time.time(),
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=random.randint(1024, 65535),
            dst_port=dst_port,
            protocol=protocol,
            size=size,
            payload_bytes=payload,
        )
