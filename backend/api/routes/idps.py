import json
from uuid import uuid4
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from backend.db.database import get_db
from backend.db import models
from backend.schemas.base import IDPSEventCreate, IncidentResponse
from backend.services.response.alert_bus import alert_bus, TOPIC_IDPS_DETECTION
from backend.api.websocket.ws_manager import ws_manager
from backend.services.correlation import assign_correlation
from backend.services.response.blocker import block_ip
from backend.utils.helpers import compute_severity

from backend.db.repositories.incidents_repository import IncidentsRepository

router = APIRouter(prefix="/idps", tags=["IDPS"])


@router.post("/event", response_model=IncidentResponse)
async def create_idps_event(payload: IDPSEventCreate, db: Session = Depends(get_db)):
    severity = compute_severity(payload.confidence)
    explanation = payload.explanation or (
        f"Rule triggered: {payload.rule_triggered}. "
        f"Attack type: {payload.attack_type} from {payload.source_ip} "
        f"(confidence: {payload.confidence:.2f})"
        if payload.rule_triggered
        else f"{payload.attack_type} detected from {payload.source_ip} with {payload.confidence:.0%} confidence."
    )

    incident_data = {
        "incident_uid": str(uuid4()),
        "timestamp": datetime.utcnow(),
        "source_ip": payload.source_ip,
        "pipeline": "A",
        "pipeline_primary": "idps",
        "attack_type": payload.attack_type,
        "confidence": payload.confidence,
        "severity": severity,
        "explanation": explanation,
        "detected_at": datetime.utcnow(),
    }
    incident = IncidentsRepository.create_incident(db, incident_data)

    flow_data = {
        "incident_id": incident.id,
        "src_ip": payload.source_ip,
        "dst_ip": payload.dst_ip or "0.0.0.0",
        "src_port": payload.src_port,
        "dst_port": payload.dst_port,
        "protocol": payload.protocol or "TCP",
        "packet_count": payload.packet_count or 1,
        "feature_vector": json.dumps(payload.feature_vector) if payload.feature_vector else None,
        "prediction": payload.attack_type,
        "confidence": payload.confidence,
    }
    IncidentsRepository.add_network_flow(db, flow_data)

    assign_correlation(db, incident)

    if severity in ("high", "critical"):
        block_ip(db, payload.source_ip, "idps", f"Auto-block: {payload.attack_type}")
        incident.blocked = True

    db.commit()
    db.refresh(incident)

    await ws_manager.broadcast({
        "event_type": "new_incident",
        "pipeline_badge": "IDPS",
        "incident": {
            "id": incident.id,
            "uid": incident.incident_uid,
            "source_ip": incident.source_ip,
            "attack_type": incident.attack_type,
            "confidence": incident.confidence,
            "severity": incident.severity,
            "explanation": incident.explanation,
            "correlation_group_id": incident.correlation_group_id,
            "timestamp": incident.detected_at.isoformat(),
        }
    })

    await alert_bus.publish(TOPIC_IDPS_DETECTION, {
        "source_ip": payload.source_ip,
        "attack_type": payload.attack_type,
        "confidence": payload.confidence,
        "severity": severity,
    })

    return incident
