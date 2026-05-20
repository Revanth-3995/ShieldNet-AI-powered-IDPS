from datetime import datetime
from typing import Optional, Any
from pydantic import BaseModel, ConfigDict


class IDPSEventCreate(BaseModel):
    source_ip: str
    attack_type: str
    confidence: float
    protocol: Optional[str] = "TCP"
    dst_port: Optional[int] = None
    src_port: Optional[int] = None
    dst_ip: Optional[str] = None
    packet_count: Optional[int] = 1
    feature_vector: Optional[dict[str, Any]] = None
    explanation: Optional[str] = None
    rule_triggered: Optional[str] = None


class VideoFrameAnalysis(BaseModel):
    frame_idx: int
    timestamp_ms: float
    confidence: float
    is_suspicious: bool
    algorithm_detected: Optional[str] = None
    motion_score: Optional[float] = None
    uniqueness_score: Optional[float] = None
    importance_score: Optional[float] = None
    forensic_data: Optional[dict[str, Any]] = None

class VideoAnalysisReport(BaseModel):
    video_id: Optional[str] = None
    confidence: float
    is_suspicious: bool
    max_frame_confidence: float
    mean_frame_confidence: float
    suspicious_frame_density: float
    frame_count: int
    algorithm_detected: Optional[str] = None
    processing_duration: float
    frame_results: list[VideoFrameAnalysis]
    extraction_stats: Optional[dict[str, Any]] = None

class StegEventCreate(BaseModel):
    source_ip: str
    media_type: str
    confidence: float
    filename: Optional[str] = None
    file_size: Optional[int] = None
    algorithm_detected: Optional[str] = None
    payload_estimate: Optional[int] = None
    frame_count: Optional[int] = None
    forensic_data: Optional[dict[str, Any]] = None
    frame_results: Optional[list[VideoFrameAnalysis]] = None
    audio_results: Optional[list[dict[str, Any]]] = None


class WatchEndpointCreate(BaseModel):
    src_ip: str
    reason: Optional[str] = None
    sensitivity_multiplier: float = 1.4
    triggered_by: Optional[str] = None


class BlockRequest(BaseModel):
    reason: Optional[str] = "Manual block"


class IncidentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    incident_uid: str
    timestamp: datetime
    source_ip: str
    pipeline: str
    pipeline_primary: str
    attack_type: str
    media_type: Optional[str] = None
    confidence: float
    severity: str
    explanation: Optional[str] = None
    correlation_group_id: Optional[str] = None
    blocked: bool
    detected_at: datetime


class HoneypotLogResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    timestamp: datetime
    src_ip: str
    port: int
    service: str
    payload: Optional[str] = None
    credentials_attempted: Optional[str] = None
    session_duration: Optional[float] = None
    mitre_ttp: Optional[str] = None


class BlockedIPResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    ip_address: str
    blocked_by: str
    reason: Optional[str] = None
    blocked_at: datetime
    both_pipelines: bool
