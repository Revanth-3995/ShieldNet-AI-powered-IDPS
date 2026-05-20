import json
from uuid import uuid4
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, File, UploadFile, BackgroundTasks
from sqlalchemy.orm import Session
from typing import Optional
import os
import shutil
import tempfile

from backend.db.database import get_db, SessionLocal
from backend.db import models
from backend.schemas.base import StegEventCreate, IncidentResponse
from backend.services.response.alert_bus import alert_bus, TOPIC_STEG_DETECTION
from backend.api.websocket.ws_manager import ws_manager
from backend.services.correlation import assign_correlation
from backend.services.response.blocker import block_ip
from backend.utils.helpers import compute_severity
from backend.db.repositories.incidents_repository import IncidentsRepository
from backend.services.video.processing.pipeline import VideoAnalysisPipeline
from backend.services.video.integration.analyzer_client import InternalAnalyzerClient
from backend.core.logging import get_logger

logger = get_logger("shieldnet.api.steg")

router = APIRouter(prefix="/steg", tags=["Steganalysis"])


@router.post("/event", response_model=IncidentResponse)
async def create_steg_event(payload: StegEventCreate, db: Session = Depends(get_db)):
    severity = compute_severity(payload.confidence)
    media_label = payload.media_type.upper()
    explanation = (
        f"{media_label} steganographic covert channel detected. "
        f"Algorithm: {payload.algorithm_detected or 'Unknown'}. "
        f"Confidence: {payload.confidence:.0%}. "
        f"Estimated hidden payload: {payload.payload_estimate or '?'} bytes."
    )

    incident_data = {
        "incident_uid": str(uuid4()),
        "timestamp": datetime.utcnow(),
        "source_ip": payload.source_ip,
        "pipeline": "B",
        "pipeline_primary": "steg",
        "attack_type": f"{payload.media_type}_steg_detected",
        "media_type": payload.media_type,
        "confidence": payload.confidence,
        "severity": severity,
        "explanation": explanation,
        "detected_at": datetime.utcnow(),
    }
    incident = IncidentsRepository.create_incident(db, incident_data)

    forensic_json = json.dumps(payload.forensic_data) if payload.forensic_data else None
    scan_data = {
        "incident_id": incident.id,
        "filename": payload.filename,
        "file_size": payload.file_size,
        "source_ip": payload.source_ip,
        "media_type": payload.media_type,
        "confidence": payload.confidence,
        "algorithm_detected": payload.algorithm_detected,
        "payload_estimate": payload.payload_estimate,
        "frame_count": payload.frame_count,
        "forensic_json": forensic_json,
    }
    scan = IncidentsRepository.add_steg_scan(db, scan_data)

    if payload.frame_results:
        for fr in payload.frame_results:
            IncidentsRepository.add_video_frame_result(db, {
                "steg_scan_id": scan.id,
                "frame_number": fr.get("frame_number", 0),
                "timestamp_ms": fr.get("timestamp_ms"),
                "confidence": fr.get("confidence", 0.0),
                "chi_square": fr.get("chi_square"),
                "rs_score": fr.get("rs_score"),
                "dct_score": fr.get("dct_score"),
                "anomaly_type": fr.get("anomaly_type"),
            })

    if payload.audio_results:
        for ar in payload.audio_results:
            IncidentsRepository.add_audio_scan_result(db, {
                "steg_scan_id": scan.id,
                "channel": ar.get("channel"),
                "rs_score": ar.get("rs_score"),
                "echo_score": ar.get("echo_score"),
                "confidence": ar.get("confidence", 0.0),
                "sample_range_flagged": ar.get("sample_range_flagged"),
            })

    assign_correlation(db, incident)

    if severity in ("high", "critical"):
        block_ip(db, payload.source_ip, "steg", "Auto-block: steg covert channel")
        incident.blocked = True

    db.commit()
    db.refresh(incident)

    await ws_manager.broadcast({
        "event_type": "new_incident",
        "pipeline_badge": f"{media_label}-STEG",
        "incident": {
            "id": incident.id,
            "uid": incident.incident_uid,
            "source_ip": incident.source_ip,
            "attack_type": incident.attack_type,
            "media_type": incident.media_type,
            "confidence": incident.confidence,
            "severity": incident.severity,
            "explanation": incident.explanation,
            "correlation_group_id": incident.correlation_group_id,
            "timestamp": incident.detected_at.isoformat(),
        }
    })

    await alert_bus.publish(TOPIC_STEG_DETECTION, {
        "source_ip": payload.source_ip,
        "media_type": payload.media_type,
        "confidence": payload.confidence,
        "severity": severity,
    })
    return incident


@router.post("/upload/video")
async def upload_video(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    source_ip: str = "127.0.0.1",
    db: Session = Depends(get_db)
):
    if not file.content_type.startswith("video/"):
        raise HTTPException(status_code=400, detail="Only video files are supported")

    # Save to a temporary file
    with tempfile.NamedTemporaryFile(suffix=os.path.splitext(file.filename)[1], delete=False) as tmp:
        shutil.copyfileobj(file.file, tmp)
        tmp_path = tmp.name

    logger.info(f"Received video upload: {file.filename} ({tmp_path})")

    # Start async processing
    background_tasks.add_task(
        process_video_task,
        tmp_path,
        file.filename,
        source_ip
    )

    return {
        "status": "processing",
        "filename": file.filename,
        "message": "Video analysis started in background"
    }


async def process_video_task(video_path: str, filename: str, source_ip: str):
    """Background task for full video analysis with real-time updates."""
    analysis_id = str(uuid4())
    try:
        # Progress callback for the pipeline
        async def on_progress(data: dict):
            await ws_manager.broadcast({
                "event_type": "video_progress",
                "analysis_id": analysis_id,
                "filename": filename,
                "progress": data["progress"],
                "frames_processed": data["frames_processed"],
                "current_confidence": data["current_confidence"]
            })

        client = InternalAnalyzerClient()
        pipeline = VideoAnalysisPipeline(analyzer=client)
        result = await pipeline.process_video(video_path, on_progress=on_progress)
        
        with SessionLocal() as db:
            # Prepare payload for reporting
            from backend.schemas.base import StegEventCreate
            payload = StegEventCreate(
                source_ip=source_ip,
                media_type="video",
                confidence=result["confidence"],
                filename=filename,
                file_size=os.path.getsize(video_path),
                algorithm_detected=result.get("algorithm_detected"),
                payload_estimate=0, # Placeholder
                frame_count=result.get("frame_count"),
                forensic_data={
                    "max_frame_confidence": result.get("max_frame_confidence"),
                    "suspicious_frame_density": result.get("suspicious_frame_density"),
                    "processing_duration": result.get("processing_duration"),
                },
                frame_results=[{
                    "frame_number": fr.get("frame_idx"),
                    "timestamp_ms": fr.get("timestamp_ms"),
                    "confidence": fr.get("confidence"),
                    "anomaly_type": fr.get("algorithm_detected")
                } for fr in result.get("frame_results", [])],
                audio_results=[]
            )
            
            await _handle_steg_report(payload, db)

    except Exception as e:
        logger.error(f"Background video analysis failed: {e}")
    finally:
        if os.path.exists(video_path):
            os.unlink(video_path)


async def _handle_steg_report(payload: StegEventCreate, db: Session):
    severity = compute_severity(payload.confidence)
    media_label = payload.media_type.upper()
    explanation = (
        f"{media_label} steganographic covert channel detected via Async Pipeline. "
        f"Algorithm: {payload.algorithm_detected or 'Unknown'}. "
        f"Confidence: {payload.confidence:.0%}. "
    )

    incident_data = {
        "incident_uid": str(uuid4()),
        "timestamp": datetime.utcnow(),
        "source_ip": payload.source_ip,
        "pipeline": "B",
        "pipeline_primary": "steg",
        "attack_type": f"{payload.media_type}_steg_detected",
        "media_type": payload.media_type,
        "confidence": payload.confidence,
        "severity": severity,
        "explanation": explanation,
        "detected_at": datetime.utcnow(),
    }
    incident = IncidentsRepository.create_incident(db, incident_data)

    forensic_json = json.dumps(payload.forensic_data) if payload.forensic_data else None
    scan_data = {
        "incident_id": incident.id,
        "filename": payload.filename,
        "file_size": payload.file_size,
        "source_ip": payload.source_ip,
        "media_type": payload.media_type,
        "confidence": payload.confidence,
        "algorithm_detected": payload.algorithm_detected,
        "payload_estimate": payload.payload_estimate,
        "frame_count": payload.frame_count,
        "forensic_json": forensic_json,
    }
    scan = IncidentsRepository.add_steg_scan(db, scan_data)

    for fr in payload.frame_results:
        IncidentsRepository.add_video_frame_result(db, {
            "steg_scan_id": scan.id,
            "frame_number": fr.get("frame_number", 0),
            "timestamp_ms": fr.get("timestamp_ms"),
            "confidence": fr.get("confidence", 0.0),
            "anomaly_type": fr.get("anomaly_type"),
        })

    assign_correlation(db, incident)
    if severity in ("high", "critical"):
        block_ip(db, payload.source_ip, "steg", "Auto-block: steg covert channel")
        incident.blocked = True

    db.commit()
    
    await ws_manager.broadcast({
        "event_type": "new_incident",
        "pipeline_badge": f"{media_label}-STEG",
        "incident": {
            "id": incident.id,
            "uid": incident.incident_uid,
            "source_ip": incident.source_ip,
            "attack_type": incident.attack_type,
            "media_type": incident.media_type,
            "confidence": incident.confidence,
            "severity": incident.severity,
            "explanation": incident.explanation,
            "correlation_group_id": incident.correlation_group_id,
            "timestamp": incident.detected_at.isoformat(),
        }
    })
    
    await alert_bus.publish(TOPIC_STEG_DETECTION, {
        "source_ip": payload.source_ip,
        "media_type": payload.media_type,
        "confidence": payload.confidence,
        "severity": severity,
    })


@router.get("/forensics/{incident_id}")
def get_forensics(incident_id: int, db: Session = Depends(get_db)):
    inc = IncidentsRepository.get_incident_by_id(db, incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    scan = IncidentsRepository.get_steg_scan_by_incident(db, incident_id)
    if not scan:
        raise HTTPException(status_code=404, detail="No forensic data for this incident")

    frames = IncidentsRepository.get_video_frames_by_scan(db, scan.id)
    audio = IncidentsRepository.get_audio_results_by_scan(db, scan.id)

    return {
        "incident_id": incident_id,
        "incident_uid": inc.incident_uid,
        "source_ip": inc.source_ip,
        "media_type": scan.media_type,
        "filename": scan.filename,
        "file_size": scan.file_size,
        "confidence": scan.confidence,
        "algorithm_detected": scan.algorithm_detected,
        "payload_estimate_bytes": scan.payload_estimate,
        "frame_count": scan.frame_count,
        "forensic_data": json.loads(scan.forensic_json) if scan.forensic_json else {},
        "quarantine_path": scan.quarantine_path,
        "frame_results": [{"frame_number": f.frame_number, "timestamp_ms": f.timestamp_ms, "confidence": f.confidence, "chi_square": f.chi_square, "rs_score": f.rs_score, "dct_score": f.dct_score, "anomaly_type": f.anomaly_type} for f in frames],
        "audio_results": [{"channel": a.channel, "rs_score": a.rs_score, "echo_score": a.echo_score, "confidence": a.confidence, "sample_range_flagged": a.sample_range_flagged} for a in audio],
    }
