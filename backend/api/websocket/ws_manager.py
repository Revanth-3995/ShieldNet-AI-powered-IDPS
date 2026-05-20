"""
ShieldNet WebSocket Manager.
Handles real-time dashboard updates via persistent connections.
"""
from __future__ import annotations

from typing import Any
from fastapi import WebSocket

from backend.core.logging import get_logger

logger = get_logger("shieldnet.ws")


class ConnectionManager:
    """Manages active WebSocket connections to the dashboard."""

    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.debug(f"New WS connection. Total: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            logger.debug(f"WS disconnected. Total: {len(self.active_connections)}")

    async def broadcast(self, message: Any):
        """Send message to all connected dashboard clients."""
        if not self.active_connections:
            return

        import json
        if not isinstance(message, str):
            payload = json.dumps(message, default=str)
        else:
            payload = message

        dead_links = []
        for connection in self.active_connections:
            try:
                await connection.send_text(payload)
            except Exception:
                dead_links.append(connection)

        for dead in dead_links:
            self.disconnect(dead)


# Global singleton
ws_manager = ConnectionManager()
