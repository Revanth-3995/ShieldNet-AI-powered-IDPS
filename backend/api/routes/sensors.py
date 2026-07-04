"""
ShieldNet — Sensor Status API
Tracks which real-network sensors are alive and reporting.
"""
from __future__ import annotations

from datetime import datetime, timedelta
from fastapi import APIRouter
from pydantic import BaseModel
from typing import Optional

router = APIRouter(prefix="/sensors", tags=["Sensors"])

# In-memory sensor registry (resets on server restart)
_sensors: dict[str, dict] = {
    "pcap": {
        "name": "Live PCAP Capture",
        "description": "Scapy-based packet sniffer detecting port scans, SYN floods, DoS",
        "how_to_run": "python -m backend.sensors.pcap_sensor",
        "requires": "Npcap (Windows) — https://npcap.com",
        "last_heartbeat": None,
        "packets_seen": 0,
        "alerts_sent": 0,
        "active": False,
    },
    "mitmproxy": {
        "name": "mitmproxy HTTP Inspector",
        "description": "HTTP proxy detecting SQLi, XSS, path traversal, credential probes",
        "how_to_run": "python -m backend.sensors.mitmproxy_addon",
        "requires": "Configure browser proxy → 127.0.0.1:8888",
        "last_heartbeat": None,
        "requests_seen": 0,
        "alerts_sent": 0,
        "active": False,
    },
    "suricata": {
        "name": "Suricata IDS",
        "description": "Forwards Suricata EVE JSON alerts to ShieldNet in real-time",
        "how_to_run": "python -m backend.sensors.suricata_sensor",
        "requires": "Suricata installed — https://suricata.io/download/",
        "last_heartbeat": None,
        "alerts_forwarded": 0,
        "active": False,
    },
}

STALE_THRESHOLD_SECONDS = 30  # sensor considered offline if no heartbeat in this time


class HeartbeatPayload(BaseModel):
    sensor: str
    packets_seen: Optional[int] = None
    alerts_sent: Optional[int] = None
    requests_seen: Optional[int] = None
    alerts_forwarded: Optional[int] = None
    last_alert_at: Optional[str] = None


def _is_active(sensor_name: str) -> bool:
    """Check if sensor sent a heartbeat recently."""
    s = _sensors.get(sensor_name)
    if not s or not s.get("last_heartbeat"):
        return False
    last = s["last_heartbeat"]
    if isinstance(last, str):
        try:
            last = datetime.fromisoformat(last)
        except Exception:
            return False
    return (datetime.utcnow() - last) < timedelta(seconds=STALE_THRESHOLD_SECONDS)


@router.post("/heartbeat")
async def sensor_heartbeat(payload: HeartbeatPayload):
    """Called by sensor processes to report they are alive."""
    name = payload.sensor
    if name not in _sensors:
        _sensors[name] = {"name": name, "description": "Custom sensor"}

    _sensors[name]["last_heartbeat"] = datetime.utcnow().isoformat()
    _sensors[name]["active"] = True

    # Update stats
    if payload.packets_seen is not None:
        _sensors[name]["packets_seen"] = payload.packets_seen
    if payload.alerts_sent is not None:
        _sensors[name]["alerts_sent"] = payload.alerts_sent
    if payload.requests_seen is not None:
        _sensors[name]["requests_seen"] = payload.requests_seen
    if payload.alerts_forwarded is not None:
        _sensors[name]["alerts_forwarded"] = payload.alerts_forwarded
    if payload.last_alert_at is not None:
        _sensors[name]["last_alert_at"] = payload.last_alert_at

    return {"status": "ok", "sensor": name}


@router.get("/status")
async def get_sensor_status():
    """Return live status of all known sensors."""
    result = {}
    for name, info in _sensors.items():
        active = _is_active(name)
        # Update active flag based on recency
        _sensors[name]["active"] = active
        result[name] = {
            **info,
            "active": active,
            "last_heartbeat": info.get("last_heartbeat"),
        }
    return result
