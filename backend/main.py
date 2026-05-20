"""
ShieldNet — Unified AI-Powered Cybersecurity Platform
FastAPI Backend — Central Entry Point
"""
from __future__ import annotations

import asyncio
from datetime import datetime

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from backend.core.config import settings
from backend.core.logging import get_logger
from backend.db.database import create_all
from backend.api.router import api_router
from backend.services.response.alert_bus import (
    alert_bus, TOPIC_IDPS_DETECTION, TOPIC_STEG_DETECTION, TOPIC_IP_BLOCKED
)
from backend.api.websocket.ws_manager import ws_manager
from backend.services.response.intelligence import init_intelligence

logger = get_logger("shieldnet.main")

# Initialize Database
create_all()

# Initialize Intelligence Handlers
init_intelligence()

app = FastAPI(
    title=settings.app.NAME,

    version=settings.app.VERSION,
    debug=settings.app.DEBUG
)

# ---------------------------------------------------------------------------
# CORS & Preflight Handling
# ---------------------------------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
)

# Catch-all OPTIONS handler to prevent 400/405 during browser preflight
@app.options("/{rest_of_path:path}")
async def preflight_handler(rest_of_path: str):
    return {}

# Include API Router
app.include_router(api_router)


# ---------------------------------------------------------------------------
# Alert Bus Callbacks
# ---------------------------------------------------------------------------


async def on_ip_blocked(event: dict):
    ip = event.get("ip")
    await ws_manager.broadcast({
        "event_type": "ip_blocked",
        "ip": ip,
        "blocked_by": event.get("blocked_by"),
        "timestamp": datetime.utcnow().isoformat(),
    })


# Wire up remaining Alert Bus handlers
alert_bus.subscribe(TOPIC_IP_BLOCKED, on_ip_blocked)


# ---------------------------------------------------------------------------
# Lifespan Events
# ---------------------------------------------------------------------------
@app.on_event("startup")
async def startup():
    asyncio.create_task(alert_bus.start())
    logger.info(f"{settings.app.NAME} started on {settings.app.API_BASE_URL}")


@app.on_event("shutdown")
async def shutdown():
    alert_bus.stop()
    logger.info(f"{settings.app.NAME} shutting down")


# ---------------------------------------------------------------------------
# WebSocket Entry Point
# ---------------------------------------------------------------------------
@app.websocket("/ws/live")
async def websocket_endpoint(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        while True:
            # Keep-alive or handle incoming messages if needed
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)


@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "service": settings.app.NAME,
        "version": settings.app.VERSION,
        "timestamp": datetime.utcnow().isoformat()
    }
