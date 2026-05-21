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


from pydantic import BaseModel

class HoneypotLogCreate(BaseModel):
    src_ip: str
    port: int
    service: str
    payload: Optional[str] = None
    credentials_attempted: Optional[str] = None
    session_duration: Optional[float] = None
    mitre_ttp: Optional[str] = None

@router.post("/log")
async def create_honeypot_log(
    log: HoneypotLogCreate,
    db: Session = Depends(get_db)
):
    log_data = {
        "src_ip": log.src_ip,
        "port": log.port,
        "service": log.service,
        "payload": log.payload,
        "credentials_attempted": log.credentials_attempted,
        "session_duration": log.session_duration,
        "mitre_ttp": log.mitre_ttp,
    }
    HoneypotRepository.create_log(db, log_data)
    await ws_manager.broadcast({
        "event_type": "honeypot_interaction",
        "service": log.service,
        "port": log.port,
        "src_ip": log.src_ip,
        "credentials": log.credentials_attempted,
        "mitre_ttp": log.mitre_ttp,
        "timestamp": datetime.utcnow().isoformat(),
    })
    return {"status": "logged"}
