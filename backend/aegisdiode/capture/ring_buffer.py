"""
AegisDiode Ring Buffer
=======================
Fixed-size circular buffer simulating AF_PACKET's ring buffer behavior.
Stores packet metadata with O(1) push/pop and tracks drop count.
"""

from __future__ import annotations

import asyncio
from collections import deque
from typing import Optional

from aegisdiode.db.models import PacketMeta
from aegisdiode.config import config


class RingBuffer:
    """
    Thread-safe circular buffer simulating AF_PACKET ring buffer.

    In production, this would be a kernel-level AF_PACKET TPACKET_V3 ring buffer
    with TX=0 (receive-only). This Python simulation maintains identical semantics:
    - Fixed capacity
    - O(1) push/pop
    - Drops oldest packets when full (with drop counter)
    - No transmit capability (receive-only by design)
    """

    def __init__(self, capacity: int | None = None):
        self.capacity = capacity or config.capture.ring_buffer_size
        self._buffer: deque[PacketMeta] = deque(maxlen=self.capacity)
        self._lock = asyncio.Lock()
        self._event = asyncio.Event()
        self._drop_count = 0
        self._total_received = 0

    async def push(self, packet: PacketMeta) -> None:
        """
        Push a packet into the ring buffer.
        If buffer is full, oldest packet is dropped automatically.
        """
        async with self._lock:
            if len(self._buffer) >= self.capacity:
                self._drop_count += 1
            self._buffer.append(packet)
            self._total_received += 1
            self._event.set()

    async def pop(self) -> Optional[PacketMeta]:
        """Pop the oldest packet from the buffer. Returns None if empty."""
        async with self._lock:
            if self._buffer:
                return self._buffer.popleft()
            return None

    async def pop_batch(self, max_count: int = 100) -> list[PacketMeta]:
        """Pop up to max_count packets from the buffer."""
        async with self._lock:
            batch = []
            for _ in range(min(max_count, len(self._buffer))):
                batch.append(self._buffer.popleft())
            return batch

    async def wait_for_packets(self, timeout: float = 1.0) -> bool:
        """Wait until packets are available or timeout."""
        self._event.clear()
        try:
            await asyncio.wait_for(self._event.wait(), timeout=timeout)
            return True
        except asyncio.TimeoutError:
            return False

    @property
    def size(self) -> int:
        return len(self._buffer)

    @property
    def drop_count(self) -> int:
        return self._drop_count

    @property
    def total_received(self) -> int:
        return self._total_received

    @property
    def utilization(self) -> float:
        """Buffer utilization as a percentage."""
        return (len(self._buffer) / self.capacity) * 100 if self.capacity > 0 else 0
