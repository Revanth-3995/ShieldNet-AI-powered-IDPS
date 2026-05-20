from datetime import datetime
from typing import Optional
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from backend.db.database import get_db
from backend.db import models
from backend.schemas.base import HoneypotLogResponse
from backend.api.websocket.ws_manager import ws_manager

from backend.db.repositories.honeypot_repository import HoneypotRepository

router = APIRouter(prefix="/honeypot", tags=["Honeypot"])


@router.get("/logs", response_model=list[HoneypotLogResponse])
def get_honeypot_logs(limit: int = 100, db: Session = Depends(get_db)):
    return HoneypotRepository.get_logs(db, limit)


@router.post("/log")
async def create_honeypot_log(
    src_ip: str, port: int, service: str,
    payload: Optional[str] = None,
    credentials: Optional[str] = None,
    session_duration: Optional[float] = None,
    mitre_ttp: Optional[str] = None,
    db: Session = Depends(get_db)
):
    log_data = {
        "src_ip": src_ip,
        "port": port,
        "service": service,
        "payload": payload,
        "credentials_attempted": credentials,
        "session_duration": session_duration,
        "mitre_ttp": mitre_ttp,
    }
    HoneypotRepository.create_log(db, log_data)
    await ws_manager.broadcast({
        "event_type": "honeypot_interaction",
        "service": service,
        "port": port,
        "src_ip": src_ip,
        "credentials": credentials,
        "mitre_ttp": mitre_ttp,
        "timestamp": datetime.utcnow().isoformat(),
    })
    return {"status": "logged"}
