"""
ShieldNet — Cross-Pipeline Intelligence
Handles escalation and intelligence exchange between pipelines.
"""
from __future__ import annotations

from datetime import datetime
from sqlalchemy.orm import Session
from backend.core.logging import get_logger
from backend.db import models
from backend.db.database import SessionLocal
from backend.services.response.alert_bus import alert_bus, TOPIC_IDPS_DETECTION, TOPIC_STEG_DETECTION
from backend.api.websocket.ws_manager import ws_manager

logger = get_logger("shieldnet.intelligence")

async def handle_idps_detection(event: dict):
    """When IDPS detects an attack, lower the threshold for Steganalysis."""
    ip = event.get("source_ip")
    if not ip:
        return

    logger.info(f"Escalating watch for {ip} due to IDPS detection")
    
    with SessionLocal() as db:
        existing = db.query(models.WatchEndpoint).filter(models.WatchEndpoint.src_ip == ip).first()
        if existing:
            existing.sensitivity_multiplier = max(existing.sensitivity_multiplier, 1.5)
            existing.reason = f"IDPS Escalation: {event.get('attack_type')}"
        else:
            db.add(models.WatchEndpoint(
                src_ip=ip,
                reason=f"IDPS Escalation: {event.get('attack_type')}",
                sensitivity_multiplier=1.5,
                triggered_by="idps"
            ))
        db.commit()

    await ws_manager.broadcast({
        "event_type": "cross_pipeline_escalation",
        "direction": "A->B",
        "ip": ip,
        "message": f"IDPS flagged {ip} — lowering steg detection thresholds",
        "timestamp": datetime.utcnow().isoformat(),
    })

async def handle_steg_detection(event: dict):
    """When Steganalysis detects something, inform IDPS."""
    ip = event.get("source_ip")
    if not ip:
        return
        
    logger.info(f"Steg detection for {ip} — monitoring elevated")
    
    await ws_manager.broadcast({
        "event_type": "cross_pipeline_escalation",
        "direction": "B->A",
        "ip": ip,
        "message": f"Steg covert channel from {ip} — elevating IDPS monitoring",
        "timestamp": datetime.utcnow().isoformat(),
    })

def init_intelligence():
    """Register intelligence handlers to the alert bus."""
    alert_bus.subscribe(TOPIC_IDPS_DETECTION, handle_idps_detection)
    alert_bus.subscribe(TOPIC_STEG_DETECTION, handle_steg_detection)
    logger.info("Cross-pipeline intelligence initialized")
