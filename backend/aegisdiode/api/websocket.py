"""
AegisDiode WebSocket Manager
==============================
Manages active WebSocket connections and broadcasts real-time telemetry:
flow updates, single-detector alerts, correlated incidents, and system metrics.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import List, Set

from fastapi import WebSocket, WebSocketDisconnect

logger = logging.getLogger(__name__)


class ConnectionManager:
    """Manages WebSocket client connections and broadcasts messages."""

    def __init__(self):
        self.active_connections: Set[WebSocket] = set()

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.add(websocket)
        logger.info(f"WebSocket client connected. Total clients: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        self.active_connections.discard(websocket)
        logger.info(f"WebSocket client disconnected. Remaining clients: {len(self.active_connections)}")

    async def broadcast(self, message: dict):
        """Send JSON message to all connected clients."""
        if not self.active_connections:
            return

        payload = json.dumps(message)
        dead_sockets = set()

        for connection in list(self.active_connections):
            try:
                await connection.send_text(payload)
            except Exception as e:
                logger.warning(f"Error sending to WebSocket client: {e}")
                dead_sockets.add(connection)

        for dead in dead_sockets:
            self.disconnect(dead)


ws_manager = ConnectionManager()
