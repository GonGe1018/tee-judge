"""WebSocket connection managers for Judge Client and Browser notifications."""

from __future__ import annotations

import logging
from fastapi import WebSocket

logger = logging.getLogger("tee-judge")


class ConnectionManager:
    """Manages WebSocket connections per user. One connection per user per role."""

    def __init__(self, name: str):
        self._name = name
        self._connections: dict[int, WebSocket] = {}

    async def connect(self, user_id: int, websocket: WebSocket):
        old = self._connections.get(user_id)
        if old:
            try:
                await old.close(code=1000, reason="New connection")
            except Exception:
                pass
        self._connections[user_id] = websocket
        logger.info(f"[{self._name}] WS connected: user #{user_id}")

    def disconnect(self, user_id: int):
        self._connections.pop(user_id, None)
        logger.info(f"[{self._name}] WS disconnected: user #{user_id}")

    async def notify(self, user_id: int, data: dict) -> bool:
        """Send notification to a specific user."""
        ws = self._connections.get(user_id)
        if ws:
            try:
                await ws.send_json(data)
                return True
            except Exception:
                self.disconnect(user_id)
                return False
        return False

    def is_connected(self, user_id: int) -> bool:
        return user_id in self._connections

    @property
    def active_count(self) -> int:
        return len(self._connections)


# Judge Client connections
judge_manager = ConnectionManager("judge")

# Browser connections
browser_manager = ConnectionManager("browser")
