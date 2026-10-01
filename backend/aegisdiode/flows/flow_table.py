"""
AegisDiode Flow Table
======================
Active/idle timer management for observation flows.
Implements the 60s active / 15s idle timeout policy.
"""

from __future__ import annotations

import asyncio
import time
from typing import Callable, Awaitable, Optional

from aegisdiode.config import config
from aegisdiode.db.models import FlowKey, FlowState, ObservationFlow
from aegisdiode.flows.flow_tracker import FlowTracker


class FlowTable:
    """
    Manages flow lifecycle with active/idle timers.

    Timer policy:
    - Active timeout (60s): Flow transitions from ACTIVE → IDLE if no packets
      are seen within this window
    - Idle timeout (15s): Flow transitions from IDLE → EXPIRED after this
      grace period with no activity
    - Sweep interval (5s): Background task checks for timer expirations
    """

    def __init__(self, flow_tracker: FlowTracker):
        self.tracker = flow_tracker
        self.active_timeout = config.flow.active_timeout
        self.idle_timeout = config.flow.idle_timeout
        self.sweep_interval = config.flow.sweep_interval
        self._sweep_task: Optional[asyncio.Task] = None
        self._on_flow_expired: Optional[Callable[[ObservationFlow], Awaitable[None]]] = None
        self._running = False

    def set_on_expired(self, callback: Callable[[ObservationFlow], Awaitable[None]]):
        """Set callback for when a flow expires (triggers final feature extraction)."""
        self._on_flow_expired = callback

    async def touch_flow(self, flow: ObservationFlow) -> None:
        """Update flow activity timestamp (handled inside flow tracker)."""
        pass

    async def start(self) -> None:
        """Start the background flow sweeper."""
        self._running = True
        self._sweep_task = asyncio.create_task(self._sweep_loop())

    async def stop(self) -> None:
        """Stop the background flow sweeper."""
        self._running = False
        if self._sweep_task:
            self._sweep_task.cancel()
            try:
                await self._sweep_task
            except asyncio.CancelledError:
                pass

    async def _sweep_loop(self) -> None:
        """Periodically check for expired flows."""
        while self._running:
            try:
                await asyncio.sleep(self.sweep_interval)
                await self._sweep_expired_flows()
            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"[FlowTable] Sweep error: {e}")

    async def _sweep_expired_flows(self) -> None:
        """Check all flows for timeout expirations."""
        now = time.time()
        expired_keys: list[FlowKey] = []

        for flow in self.tracker.get_all_flows():
            if flow.state == FlowState.EXPIRED:
                continue

            time_since_last = now - flow.last_seen

            if flow.state == FlowState.ACTIVE:
                if time_since_last > self.active_timeout:
                    flow.state = FlowState.IDLE
                    # Start idle grace period

            if flow.state == FlowState.IDLE:
                if time_since_last > (self.active_timeout + self.idle_timeout):
                    expired_keys.append(flow.flow_key)

        # Process expired flows
        for key in expired_keys:
            flow = self.tracker.expire_flow(key)
            if flow and self._on_flow_expired:
                await self._on_flow_expired(flow)

    def get_flow_timers(self) -> list[dict]:
        """Get timer status for all active flows (for dashboard display)."""
        now = time.time()
        timers = []
        for flow in self.tracker.get_active_flows():
            elapsed = now - flow.last_seen
            remaining_active = max(0, self.active_timeout - elapsed)
            timers.append({
                "flow_id": flow.id,
                "flow_key": flow.flow_key.to_string(),
                "state": flow.state.value,
                "elapsed": round(elapsed, 1),
                "remaining": round(remaining_active, 1),
                "packets": flow.packet_count,
            })
        return timers
