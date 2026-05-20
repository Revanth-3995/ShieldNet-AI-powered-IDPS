from datetime import datetime
from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, Boolean, Text, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship
from backend.db.database import Base


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    incident_uid: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)
    source_ip: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    pipeline: Mapped[str] = mapped_column(String(20), nullable=False)
    pipeline_primary: Mapped[str] = mapped_column(String(10), nullable=False)
    attack_type: Mapped[str] = mapped_column(String(100), nullable=False)
    media_type: Mapped[str] = mapped_column(String(20), nullable=True)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    explanation: Mapped[str] = mapped_column(Text, nullable=True)
    correlation_group_id: Mapped[str] = mapped_column(String(64), nullable=True, index=True)
    blocked: Mapped[bool] = mapped_column(Boolean, default=False)
    detected_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)

    network_flows: Mapped[list["NetworkFlow"]] = relationship(back_populates="incident", cascade="all, delete-orphan")
    steg_scans: Mapped[list["StegScan"]] = relationship(back_populates="incident", cascade="all, delete-orphan")


class NetworkFlow(Base):
    __tablename__ = "network_flows"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id"), nullable=False, index=True)
    src_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    dst_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    src_port: Mapped[int] = mapped_column(Integer, nullable=True)
    dst_port: Mapped[int] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str] = mapped_column(String(20), nullable=False)
    packet_count: Mapped[int] = mapped_column(Integer, nullable=False)
    feature_vector: Mapped[str] = mapped_column(Text, nullable=True)
    prediction: Mapped[str] = mapped_column(String(50), nullable=True)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)

    incident: Mapped["Incident"] = relationship(back_populates="network_flows")


class StegScan(Base):
    __tablename__ = "steg_scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id"), nullable=False, index=True)
    filename: Mapped[str] = mapped_column(String(256), nullable=True)
    file_size: Mapped[int] = mapped_column(Integer, nullable=True)
    source_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    media_type: Mapped[str] = mapped_column(String(10), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    algorithm_detected: Mapped[str] = mapped_column(String(100), nullable=True)
    payload_estimate: Mapped[int] = mapped_column(Integer, nullable=True)
    frame_count: Mapped[int] = mapped_column(Integer, nullable=True)
    forensic_json: Mapped[str] = mapped_column(Text, nullable=True)
    quarantine_path: Mapped[str] = mapped_column(String(512), nullable=True)

    incident: Mapped["Incident"] = relationship(back_populates="steg_scans")
    video_frame_results: Mapped[list["VideoFrameResult"]] = relationship(back_populates="steg_scan", cascade="all, delete-orphan")
    audio_scan_results: Mapped[list["AudioScanResult"]] = relationship(back_populates="steg_scan", cascade="all, delete-orphan")


class VideoFrameResult(Base):
    __tablename__ = "video_frame_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    steg_scan_id: Mapped[int] = mapped_column(ForeignKey("steg_scans.id"), nullable=False, index=True)
    frame_number: Mapped[int] = mapped_column(Integer, nullable=False)
    timestamp_ms: Mapped[float] = mapped_column(Float, nullable=True)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    chi_square: Mapped[float] = mapped_column(Float, nullable=True)
    rs_score: Mapped[float] = mapped_column(Float, nullable=True)
    dct_score: Mapped[float] = mapped_column(Float, nullable=True)
    anomaly_type: Mapped[str] = mapped_column(String(100), nullable=True)

    steg_scan: Mapped["StegScan"] = relationship(back_populates="video_frame_results")


class AudioScanResult(Base):
    __tablename__ = "audio_scan_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    steg_scan_id: Mapped[int] = mapped_column(ForeignKey("steg_scans.id"), nullable=False, index=True)
    channel: Mapped[str] = mapped_column(String(20), nullable=True)
    rs_score: Mapped[float] = mapped_column(Float, nullable=True)
    echo_score: Mapped[float] = mapped_column(Float, nullable=True)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    sample_range_flagged: Mapped[str] = mapped_column(String(100), nullable=True)

    steg_scan: Mapped["StegScan"] = relationship(back_populates="audio_scan_results")


class HoneypotLog(Base):
    __tablename__ = "honeypot_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)
    src_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    service: Mapped[str] = mapped_column(String(20), nullable=False)
    payload: Mapped[str] = mapped_column(Text, nullable=True)
    credentials_attempted: Mapped[str] = mapped_column(String(256), nullable=True)
    session_duration: Mapped[float] = mapped_column(Float, nullable=True)
    mitre_ttp: Mapped[str] = mapped_column(String(200), nullable=True)


class BlockedIP(Base):
    __tablename__ = "blocked_ips"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False, unique=True, index=True)
    blocked_by: Mapped[str] = mapped_column(String(20), nullable=False)
    reason: Mapped[str] = mapped_column(String(256), nullable=True)
    blocked_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)
    unblocked_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    both_pipelines: Mapped[bool] = mapped_column(Boolean, default=True)


class WatchEndpoint(Base):
    __tablename__ = "watch_endpoints"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    src_ip: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    reason: Mapped[str] = mapped_column(String(256), nullable=True)
    sensitivity_multiplier: Mapped[float] = mapped_column(Float, default=1.0)
    triggered_by: Mapped[str] = mapped_column(String(20), nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)


class CorrelationGroup(Base):
    __tablename__ = "correlation_groups"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    group_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    involved_ips: Mapped[str] = mapped_column(Text, nullable=True)
    event_count: Mapped[int] = mapped_column(Integer, default=0)
    max_severity: Mapped[str] = mapped_column(String(20), nullable=True)
