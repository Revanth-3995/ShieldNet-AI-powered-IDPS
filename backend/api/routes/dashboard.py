from datetime import datetime
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import func

from backend.db.database import get_db, health_check
from backend.db import models
from backend.core.config import settings
from backend.schemas.base import (
    IncidentResponse, BlockRequest, BlockedIPResponse, WatchEndpointCreate
)
from backend.services.response.alert_bus import alert_bus, TOPIC_IP_BLOCKED, TOPIC_WATCH_ENDPOINT
from backend.api.websocket.ws_manager import ws_manager
from backend.services.response.blocker import block_ip, unblock_ip

from backend.db.repositories.incidents_repository import IncidentsRepository
from backend.db.repositories.honeypot_repository import HoneypotRepository
from backend.db.repositories.response_repository import ResponseRepository
from backend.db.repositories.correlation_repository import CorrelationRepository

router = APIRouter(tags=["Dashboard"])


@router.get("/system/health")
async def system_health(db: Session = Depends(get_db)):
    from backend.services.steg.cnn.cnn_classifier import _MODEL_LOADED
    try:
        from sqlalchemy import text
        db.execute(text("SELECT 1"))
        db_ok = True
    except Exception:
        db_ok = False
    return {
        "status": "ok" if db_ok else "degraded",
        "database": "connected" if db_ok else "error",
        "ml_model_xgboost": "loaded",
        "ml_model_cnn": "loaded" if _MODEL_LOADED else "fallback_statistical",
        "honeypot": "running",
        "websocket": "running",
        "proxy": "check_mitmproxy",
        "timestamp": datetime.utcnow().isoformat(),
    }

@router.get("/health")
def health():
    return {
        "status": "ok",
        "service": settings.app.NAME,
        "version": settings.app.VERSION,
        "timestamp": datetime.utcnow().isoformat(),
        "database": health_check(),
    }


@router.get("/incidents", response_model=list[IncidentResponse])
def get_incidents(skip: int = 0, limit: int = 100, pipeline: Optional[str] = None, severity: Optional[str] = None, db: Session = Depends(get_db)):
    return IncidentsRepository.get_incidents(db, skip, limit, pipeline, severity)


@router.get("/incidents/{incident_id}", response_model=IncidentResponse)
def get_incident(incident_id: int, db: Session = Depends(get_db)):
    inc = IncidentsRepository.get_incident_by_id(db, incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    return inc


@router.get("/timeline/{ip}")
def get_timeline(ip: str, db: Session = Depends(get_db)):
    incidents = IncidentsRepository.get_timeline_for_ip(db, ip)
    idps_count = sum(1 for i in incidents if i.pipeline_primary == "idps")
    steg_count = sum(1 for i in incidents if i.pipeline_primary == "steg")
    has_mixed = idps_count >= 1 and steg_count >= 1

    if has_mixed and len(incidents) >= 3:
        pattern = "apt_operation"
    elif steg_count >= 2:
        pattern = "covert_exfiltration"
    elif idps_count >= 2:
        pattern = "network_attack"
    elif len(incidents) >= 3:
        pattern = "suspicious"
    else:
        pattern = "normal"

    return {
        "ip": ip,
        "attack_pattern": pattern,
        "total_events": len(incidents),
        "events": [
            {
                "timestamp": i.detected_at.isoformat(),
                "attack_type": i.attack_type,
                "pipeline": i.pipeline_primary,
                "pipeline_badge": "IDPS" if i.pipeline_primary == "idps" else f"{(i.media_type or 'steg').upper()}-STEG",
                "confidence": i.confidence,
                "severity": i.severity,
                "explanation": i.explanation,
                "correlation_group_id": i.correlation_group_id,
            }
            for i in incidents
        ]
    }


@router.post("/block/{ip}")
async def manual_block(ip: str, body: BlockRequest, db: Session = Depends(get_db)):
    block_ip(db, ip, "manual", body.reason)
    await alert_bus.publish(TOPIC_IP_BLOCKED, {"ip": ip, "blocked_by": "manual"})
    return {"status": "blocked", "ip": ip}


@router.delete("/block/{ip}")
def manual_unblock(ip: str, db: Session = Depends(get_db)):
    unblock_ip(db, ip)
    return {"status": "unblocked", "ip": ip}


@router.get("/blocked-ips", response_model=list[BlockedIPResponse])
def get_blocked_ips(db: Session = Depends(get_db)):
    return ResponseRepository.get_blocked_ips(db)


@router.get("/stats")
def get_stats(db: Session = Depends(get_db)):
    inc_stats = IncidentsRepository.get_stats(db)
    blocked_count = ResponseRepository.get_total_blocked_count(db)
    honeypot_count = HoneypotRepository.get_total_count(db)
    correlation_count = CorrelationRepository.get_total_count(db)

    return {
        "total_network_attacks": inc_stats["total_network_attacks"],
        "total_steg_detections": inc_stats["total_steg_detections"],
        "total_blocked_ips": blocked_count,
        "total_honeypot_interactions": honeypot_count,
        "total_correlated_incidents": correlation_count,
        "attack_type_breakdown": inc_stats["attack_type_breakdown"],
    }


@router.get("/correlations")
def get_correlations(db: Session = Depends(get_db)):
    groups = CorrelationRepository.get_correlations(db)
    return [
        {
            "group_id": g.group_id,
            "first_seen": g.first_seen.isoformat(),
            "last_seen": g.last_seen.isoformat(),
            "involved_ips": g.involved_ips,
            "event_count": g.event_count,
            "max_severity": g.max_severity,
        }
        for g in groups
    ]


@router.post("/watch-endpoint")
async def watch_endpoint(payload: WatchEndpointCreate, db: Session = Depends(get_db)):
    existing = ResponseRepository.get_watch_endpoint_by_ip(db, payload.src_ip)
    if existing:
        existing.sensitivity_multiplier = payload.sensitivity_multiplier
        existing.reason = payload.reason
    else:
        ResponseRepository.add_watch_endpoint(db, {
            "src_ip": payload.src_ip,
            "reason": payload.reason,
            "sensitivity_multiplier": payload.sensitivity_multiplier,
            "triggered_by": payload.triggered_by,
        })
    db.commit()
    await alert_bus.publish(TOPIC_WATCH_ENDPOINT, {
        "src_ip": payload.src_ip,
        "sensitivity_multiplier": payload.sensitivity_multiplier,
        "reason": payload.reason,
    })
    return {"status": "ok", "ip": payload.src_ip, "sensitivity": payload.sensitivity_multiplier}


@router.get("/watch-endpoint")
def get_watch_endpoints(db: Session = Depends(get_db)):
    endpoints = ResponseRepository.get_watch_endpoints(db)
    return [
        {
            "src_ip": e.src_ip,
            "reason": e.reason,
            "sensitivity_multiplier": e.sensitivity_multiplier,
            "triggered_by": e.triggered_by,
        }
        for e in endpoints
    ]


@router.post("/reset")
async def reset_all_data(db: Session = Depends(get_db)):
    """Wipe every table and return the dashboard to a clean state."""
    IncidentsRepository.reset_data(db)
    HoneypotRepository.reset_data(db)
    ResponseRepository.reset_data(db)
    CorrelationRepository.reset_data(db)
    db.commit()
    await ws_manager.broadcast({
        "event_type": "system_reset",
        "message": "All data cleared",
        "timestamp": datetime.utcnow().isoformat(),
    })
    return {"status": "reset", "message": "All data has been cleared"}


@router.get("/metrics")
def get_metrics():
    return {
        "alert_bus_queue_size": getattr(alert_bus, "_queue", None).qsize() if hasattr(alert_bus, "_queue") else 0,
        "active_ws_connections": len(ws_manager.active_connections),
    }
