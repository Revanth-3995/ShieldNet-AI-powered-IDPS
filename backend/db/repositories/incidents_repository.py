import json
from datetime import datetime
from typing import List, Optional
from sqlalchemy.orm import Session
from sqlalchemy import func
from backend.db import models

class IncidentsRepository:
    @staticmethod
    def create_incident(db: Session, incident_data: dict) -> models.Incident:
        incident = models.Incident(**incident_data)
        db.add(incident)
        db.flush()
        return incident

    @staticmethod
    def get_incident_by_id(db: Session, incident_id: int) -> Optional[models.Incident]:
        return db.query(models.Incident).filter(models.Incident.id == incident_id).first()

    @staticmethod
    def get_incidents(
        db: Session, 
        skip: int = 0, 
        limit: int = 100, 
        pipeline: Optional[str] = None, 
        severity: Optional[str] = None
    ) -> List[models.Incident]:
        q = db.query(models.Incident)
        if pipeline:
            q = q.filter(models.Incident.pipeline_primary == pipeline)
        if severity:
            q = q.filter(models.Incident.severity == severity)
        return q.order_by(models.Incident.detected_at.desc()).offset(skip).limit(limit).all()

    @staticmethod
    def get_timeline_for_ip(db: Session, ip: str) -> List[models.Incident]:
        return db.query(models.Incident).filter(models.Incident.source_ip == ip).order_by(models.Incident.detected_at.asc()).all()

    @staticmethod
    def add_network_flow(db: Session, flow_data: dict) -> models.NetworkFlow:
        flow = models.NetworkFlow(**flow_data)
        db.add(flow)
        return flow

    @staticmethod
    def add_steg_scan(db: Session, scan_data: dict) -> models.StegScan:
        scan = models.StegScan(**scan_data)
        db.add(scan)
        db.flush()
        return scan

    @staticmethod
    def add_video_frame_result(db: Session, frame_data: dict) -> models.VideoFrameResult:
        frame = models.VideoFrameResult(**frame_data)
        db.add(frame)
        return frame

    @staticmethod
    def add_audio_scan_result(db: Session, audio_data: dict) -> models.AudioScanResult:
        audio = models.AudioScanResult(**audio_data)
        db.add(audio)
        return audio

    @staticmethod
    def get_steg_scan_by_incident(db: Session, incident_id: int) -> Optional[models.StegScan]:
        return db.query(models.StegScan).filter(models.StegScan.incident_id == incident_id).first()

    @staticmethod
    def get_video_frames_by_scan(db: Session, scan_id: int) -> List[models.VideoFrameResult]:
        return db.query(models.VideoFrameResult).filter(models.VideoFrameResult.steg_scan_id == scan_id).order_by(models.VideoFrameResult.frame_number).all()

    @staticmethod
    def get_audio_results_by_scan(db: Session, scan_id: int) -> List[models.AudioScanResult]:
        return db.query(models.AudioScanResult).filter(models.AudioScanResult.steg_scan_id == scan_id).all()

    @staticmethod
    def get_stats(db: Session) -> dict:
        total_network = db.query(models.Incident).filter(models.Incident.pipeline_primary == "idps").count()
        total_steg = db.query(models.Incident).filter(models.Incident.pipeline_primary == "steg").count()
        attack_counts = db.query(models.Incident.attack_type, func.count(models.Incident.id)).filter(models.Incident.pipeline_primary == "idps").group_by(models.Incident.attack_type).all()
        return {
            "total_network_attacks": total_network,
            "total_steg_detections": total_steg,
            "attack_type_breakdown": {k: v for k, v in attack_counts},
        }

    @staticmethod
    def reset_data(db: Session):
        db.query(models.VideoFrameResult).delete()
        db.query(models.AudioScanResult).delete()
        db.query(models.StegScan).delete()
        db.query(models.NetworkFlow).delete()
        db.query(models.Incident).delete()
