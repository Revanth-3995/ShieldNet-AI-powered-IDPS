"""
ShieldNet — Unified AI-Powered Cybersecurity Platform
FastAPI Backend — Central Entry Point
"""
from __future__ import annotations

import asyncio
import os
from contextlib import asynccontextmanager
from datetime import datetime

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from backend.core.config import settings
from backend.core.logging import get_logger
from backend.db.database import create_all, SessionLocal
from backend.db import models
from backend.api.router import api_router
from backend.services.response.alert_bus import (
    alert_bus, TOPIC_IDPS_DETECTION, TOPIC_STEG_DETECTION, TOPIC_IP_BLOCKED
)
from backend.api.websocket.ws_manager import ws_manager
from backend.services.response.intelligence import init_intelligence
from backend.services.honeypot.service import honeypot_server
from backend.services.steg.cnn.cnn_classifier import _load_model as load_cnn_model

logger = get_logger("shieldnet.main")


async def _blocked_ip_poll_loop() -> None:
    """Poll blocked_ips table every 5 seconds and log active blocks for proxy enforcement."""
    while True:
        try:
            async with asyncio.timeout(4.5):
                db = SessionLocal()
                try:
                    active = db.query(models.BlockedIP).filter(
                        models.BlockedIP.unblocked_at.is_(None)
                    ).all()
                    if active:
                        logger.debug(f"[Poll] {len(active)} IPs currently blocked: "
                                     f"{[b.ip_address for b in active[:5]]}")
                finally:
                    db.close()
        except Exception as e:
            logger.warning(f"[blocked_ip_poll] error: {e}")
        await asyncio.sleep(5)


async def on_ip_blocked(event: dict):
    ip = event.get("ip")
    await ws_manager.broadcast({
        "event_type": "ip_blocked",
        "ip": ip,
        "blocked_by": event.get("blocked_by"),
        "timestamp": datetime.utcnow().isoformat(),
    })


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    create_all()
    init_intelligence()
    alert_bus.subscribe(TOPIC_IP_BLOCKED, on_ip_blocked)

    load_cnn_model()

    tasks = [
        asyncio.create_task(honeypot_server.start(), name="honeypot"),
        asyncio.create_task(alert_bus.start(), name="alert_bus"),
        asyncio.create_task(_blocked_ip_poll_loop(), name="blocked_ip_poll"),
    ]
    
    if os.environ.get("DEMO_MODE", "false").lower() == "true":
        from backend.utils.testing.demo_seed import seed_demo_data
        seed_demo_data()

    logger.info(f"{settings.app.NAME} v{settings.app.VERSION} started.")
    yield

    # Shutdown
    for t in tasks:
        t.cancel()
        try:
            await t
        except (asyncio.CancelledError, Exception):
            pass
    await honeypot_server.stop()
    alert_bus.stop()
    logger.info(f"{settings.app.NAME} shut down.")


app = FastAPI(
    title=settings.app.NAME,
    version=settings.app.VERSION,
    debug=settings.app.DEBUG,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
)


@app.options("/{rest_of_path:path}")
async def preflight_handler(rest_of_path: str):
    return {}


app.include_router(api_router)


@app.websocket("/ws/live")
async def websocket_endpoint(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
