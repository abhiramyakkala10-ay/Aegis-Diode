"""
AegisDiode Attack Patterns
============================
Templates for common attack patterns injected during demo simulation.
"""

from __future__ import annotations

import os
import random
import time

from aegisdiode.db.models import PacketMeta


def _random_payload(size: int, entropy_level: str = "medium") -> bytes:
    """Generate payload bytes with controlled entropy levels."""
    if entropy_level == "high":
        return os.urandom(size)  # ~8.0 bits entropy
    elif entropy_level == "low":
        return bytes([0x00] * size)  # ~0.0 bits entropy
    else:
        # Medium entropy — mix of printable ASCII
        return bytes([random.randint(32, 126) for _ in range(size)])


def generate_port_scan(
    src_ip: str = "10.0.0.50",
    dst_ip: str = "192.168.1.100",
    start_port: int = 1,
    end_port: int = 100,
    base_time: float | None = None,
) -> list[PacketMeta]:
    """
    Port scan pattern: rapid sequential flows to incrementing ports.
    Characteristics:
    - Many flows, 1-2 packets each
    - Very small IAT between flows
    - Small packet sizes (SYN-like)
    """
    packets = []
    t = base_time or time.time()

    for port in range(start_port, end_port + 1):
        # SYN packet to target port
        packets.append(PacketMeta(
            timestamp=t,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=random.randint(40000, 65000),
            dst_port=port,
            protocol=6,  # TCP
            size=54,  # SYN packet size
            payload_bytes=b"",
        ))
        t += random.uniform(0.001, 0.01)  # Very fast scanning

    return packets


def generate_data_exfiltration(
    src_ip: str = "192.168.1.10",
    dst_ip: str = "10.0.0.200",
    duration: float = 30.0,
    base_time: float | None = None,
) -> list[PacketMeta]:
    """
    Data exfiltration pattern: sustained flow with high entropy, uniform large packets.
    Characteristics:
    - High entropy (>7.5) — encrypted/compressed
    - Uniform packet sizes (~1400 bytes)
    - Steady transmission rate
    """
    packets = []
    t = base_time or time.time()
    port = random.randint(443, 8443)

    while t < (base_time or time.time()) + duration:
        packets.append(PacketMeta(
            timestamp=t,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=random.randint(40000, 65000),
            dst_port=port,
            protocol=6,  # TCP
            size=1400,  # Uniform large packets
            payload_bytes=_random_payload(256, "high"),  # Encrypted data
        ))
        t += random.uniform(0.01, 0.05)  # Steady rate

    return packets


def generate_dos_flood(
    src_ip: str = "10.0.0.99",
    dst_ip: str = "192.168.1.1",
    dst_port: int = 80,
    duration: float = 10.0,
    base_time: float | None = None,
) -> list[PacketMeta]:
    """
    DoS flood pattern: massive packet rate to single target.
    Characteristics:
    - Extremely small IAT
    - High bytes/sec
    - Same destination port
    """
    packets = []
    t = base_time or time.time()

    while t < (base_time or time.time()) + duration:
        packets.append(PacketMeta(
            timestamp=t,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=random.randint(1024, 65000),
            dst_port=dst_port,
            protocol=6,
            size=random.randint(64, 1500),
            payload_bytes=_random_payload(64, "medium"),
        ))
        t += random.uniform(0.0001, 0.001)  # Extremely fast

    return packets


def generate_beaconing(
    src_ip: str = "192.168.1.50",
    dst_ip: str = "10.0.0.77",
    dst_port: int = 443,
    interval: float = 30.0,
    jitter: float = 0.5,
    count: int = 20,
    base_time: float | None = None,
) -> list[PacketMeta]:
    """
    C2 beaconing pattern: periodic small packets at fixed intervals.
    Characteristics:
    - Very low IAT coefficient of variation (CV < 0.05)
    - Regular interval ± small jitter
    - Small packets (check-in payloads)
    """
    packets = []
    t = base_time or time.time()

    for _ in range(count):
        packets.append(PacketMeta(
            timestamp=t,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=random.randint(40000, 65000),
            dst_port=dst_port,
            protocol=6,
            size=random.randint(80, 150),  # Small beacon payloads
            payload_bytes=_random_payload(32, "medium"),
        ))
        t += interval + random.uniform(-jitter, jitter)

    return packets


def generate_baseline_poisoning(
    src_ip: str = "192.168.1.30",
    dst_ip: str = "10.0.0.10",
    dst_port: int = 80,
    duration: float = 120.0,
    base_time: float | None = None,
) -> list[PacketMeta]:
    """
    Gradual baseline poisoning: slowly drifts traffic patterns.
    Characteristics:
    - Starts with normal-looking traffic
    - Gradually increases packet sizes / changes entropy
    - Designed to shift baselines without triggering immediate alerts
    """
    packets = []
    t = base_time or time.time()
    end_time = t + duration

    step = 0
    total_steps = int(duration / 0.5)

    while t < end_time:
        # Gradually increase size from 200 to 1400 bytes
        progress = step / max(total_steps, 1)
        current_size = int(200 + (1200 * progress))
        current_size = min(current_size, 1500)

        # Gradually increase entropy
        if progress < 0.5:
            entropy_level = "medium"
        else:
            entropy_level = "high"

        packets.append(PacketMeta(
            timestamp=t,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=random.randint(40000, 65000),
            dst_port=dst_port,
            protocol=6,
            size=current_size,
            payload_bytes=_random_payload(min(current_size, 256), entropy_level),
        ))
        t += random.uniform(0.3, 0.7)
        step += 1

    return packets


# Map of attack names to generator functions
ATTACK_GENERATORS = {
    "port_scan": generate_port_scan,
    "data_exfil": generate_data_exfiltration,
    "dos_flood": generate_dos_flood,
    "beaconing": generate_beaconing,
    "slow_poison": generate_baseline_poisoning,
}
