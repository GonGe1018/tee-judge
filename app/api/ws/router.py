"""WebSocket endpoints for Judge Client and Browser notifications."""

import os
import json
import logging
import asyncio
from urllib.parse import urlparse

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.core.auth import decode_token
from app.core.ws import judge_manager, browser_manager

logger = logging.getLogger("tee-judge")

router = APIRouter(tags=["websocket"])

# Allowed origins for WebSocket (comma-separated, or * for dev)
_ws_origins = os.environ.get("TEE_JUDGE_CORS_ORIGINS", "")
ALLOWED_WS_ORIGINS: set[str] = set()
if _ws_origins and _ws_origins != "*":
    ALLOWED_WS_ORIGINS = {
        o.strip().rstrip("/") for o in _ws_origins.split(",") if o.strip()
    }


def _check_origin(websocket: WebSocket) -> bool:
    """Verify WebSocket Origin header against allowed origins."""
    if not ALLOWED_WS_ORIGINS:
        return True  # No restriction configured (dev mode)
    origin = (websocket.headers.get("origin") or "").rstrip("/")
    if not origin:
        return True  # Non-browser clients (Judge Client CLI) don't send Origin
    return origin in ALLOWED_WS_ORIGINS


async def _auth_websocket(websocket: WebSocket) -> dict | None:
    """Authenticate WebSocket via first message with Origin check."""
    # Check Origin before accepting
    if not _check_origin(websocket):
        await websocket.close(code=4003)
        logger.warning(f"WS rejected: invalid origin {websocket.headers.get('origin')}")
        return None

    await websocket.accept()
    try:
        raw = await asyncio.wait_for(websocket.receive_text(), timeout=5.0)
        auth_msg = json.loads(raw)
        token = auth_msg.get("token", "")
        if token.startswith("Bearer "):
            token = token[7:]
        return decode_token(token)
    except asyncio.TimeoutError:
        await websocket.close(code=4001, reason="Auth timeout")
        return None
    except (ValueError, KeyError) as e:
        await websocket.close(code=4002, reason=f"Auth failed: {e}")
        return None


@router.websocket("/ws/judge")
async def judge_websocket(websocket: WebSocket):
    """Judge Client connects here for task notifications."""
    user = await _auth_websocket(websocket)
    if not user:
        return

    user_id = user["user_id"]
    await judge_manager.connect(user_id, websocket)

    try:
        await websocket.send_json(
            {
                "type": "connected",
                "user_id": user_id,
                "message": "Judge Client connected. Waiting for tasks...",
            }
        )

        while True:
            try:
                msg = await asyncio.wait_for(websocket.receive_text(), timeout=30.0)
                if not msg:
                    continue
                try:
                    data = json.loads(msg)
                except json.JSONDecodeError:
                    continue
                if data.get("type") == "ping":
                    await websocket.send_json({"type": "pong"})
            except asyncio.TimeoutError:
                try:
                    await websocket.send_json({"type": "ping"})
                except Exception:
                    break

    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.error(f"Judge WS error for user #{user_id}: {e}")
    finally:
        judge_manager.disconnect(user_id)


@router.websocket("/ws/browser")
async def browser_websocket(websocket: WebSocket):
    """Browser connects here for result notifications."""
    user = await _auth_websocket(websocket)
    if not user:
        return

    user_id = user["user_id"]
    await browser_manager.connect(user_id, websocket)

    try:
        await websocket.send_json(
            {
                "type": "connected",
                "user_id": user_id,
            }
        )

        while True:
            try:
                msg = await asyncio.wait_for(websocket.receive_text(), timeout=30.0)
                if not msg:
                    continue
                try:
                    data = json.loads(msg)
                except json.JSONDecodeError:
                    continue
                if data.get("type") == "ping":
                    await websocket.send_json({"type": "pong"})
            except asyncio.TimeoutError:
                try:
                    await websocket.send_json({"type": "ping"})
                except Exception:
                    break

    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.error(f"Browser WS error for user #{user_id}: {e}")
    finally:
        browser_manager.disconnect(user_id)
