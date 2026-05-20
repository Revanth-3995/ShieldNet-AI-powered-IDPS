"""
ShieldNet — Pipeline B: mitmproxy Addon
"""
from __future__ import annotations

import json
import tempfile
from datetime import datetime
from pathlib import Path

import requests as req
from mitmproxy import http

from backend.core.config import settings
from backend.core.logging import get_logger

# Import from the new service structure
from backend.services.steg.algorithms import analyze_image, estimate_payload
from backend.services.steg.video_analyzer import analyze_video

logger = get_logger("shieldnet.steg.proxy")

QUARANTINE_DIR = settings.storage.QUARANTINE_DIR
QUARANTINE_DIR.mkdir(exist_ok=True, parents=True)

THRESHOLD_SUSPICIOUS = settings.detection.STEG_SUSPICIOUS_THRESHOLD
THRESHOLD_LIKELY = settings.detection.STEG_LIKELY_THRESHOLD

IMAGE_MIMES = {"image/jpeg", "image/png", "image/gif", "image/webp", "image/bmp"}
VIDEO_MIMES = {"video/mp4", "video/avi", "video/mkv", "video/mov", "video/webm"}
ALL_MEDIA_MIMES = IMAGE_MIMES | VIDEO_MIMES


def quarantine_file(content: bytes, filename: str, confidence: float) -> str:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_name = f"{ts}_{confidence:.2f}_{filename}"[:200]
    path = QUARANTINE_DIR / safe_name
    path.write_bytes(content)
    return str(path)


async def analyze_and_report(content: bytes, filename: str, content_type: str, source_ip: str, sensitivity_multiplier: float = 1.0):
    media_type = "image" if content_type in IMAGE_MIMES else "video"
    result = {}
    
    if media_type == "image":
        try:
            import numpy as np
            from PIL import Image
            from io import BytesIO
            img = Image.open(BytesIO(content)).convert("RGB")
            img_array = np.array(img)
            result = analyze_image(img_array)
            result["payload_estimate"] = estimate_payload(img_array, result.get("confidence", 0))
        except Exception as exc:
            logger.error(f"Image analysis failed: {exc}")
            result = {"confidence": 0.0}
    else:
        from backend.services.video.processing.pipeline import VideoAnalysisPipeline
        from backend.services.video.integration.analyzer_client import InternalAnalyzerClient
        
        with tempfile.NamedTemporaryFile(suffix=".mp4", delete=False) as tmp:
            tmp.write(content)
            tmp_path = tmp.name
        try:
            client = InternalAnalyzerClient()
            pipeline = VideoAnalysisPipeline(analyzer=client)
            result = await pipeline.process_video(tmp_path)
        except Exception as exc:
            logger.error(f"Video analysis failed: {exc}")
            result = {"confidence": 0.0}
        finally:
            import os
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

    raw_confidence = result.get("confidence", 0.0)
    effective_threshold = THRESHOLD_SUSPICIOUS / max(sensitivity_multiplier, 0.1)
    if raw_confidence < effective_threshold:
        return None

    if raw_confidence >= THRESHOLD_LIKELY:
        quarantine_file(content, filename, raw_confidence)

    event_data = {
        "source_ip": source_ip,
        "media_type": media_type,
        "confidence": raw_confidence,
        "filename": filename,
        "file_size": len(content),
        "algorithm_detected": result.get("algorithm_detected"),
        "payload_estimate": result.get("payload_estimate"),
        "frame_count": result.get("frame_count"),
        "forensic_data": {
            "algorithms": {k: v for k, v in result.items() if k not in {"confidence", "frame_results", "audio_results"}},
            "analysis_timestamp": datetime.utcnow().isoformat(),
        },
        "frame_results": result.get("frame_results", []),
        "audio_results": result.get("audio_results", []),
    }
    
    # We use sync requests here for now as in original code
    try:
        req.post(f"{settings.app.API_BASE_URL}/api/steg/event", json=event_data, timeout=10)
    except Exception as exc:
        logger.error(f"Failed to report steg event: {exc}")
    
    return raw_confidence


class ShieldNetProxyAddon:
    def __init__(self):
        self._blocked_ips: set = set()
        self._watched_ips: dict = {}

    def _refresh_state(self):
        try:
            blocked = req.get(f"{settings.app.API_BASE_URL}/api/blocked-ips", timeout=2).json()
            self._blocked_ips = {b["ip_address"] for b in blocked}
            watched_resp = req.get(f"{settings.app.API_BASE_URL}/api/watch-endpoint", timeout=2)
            if watched_resp.status_code == 200:
                self._watched_ips = {item["src_ip"]: item.get("sensitivity_multiplier", 1.0) for item in watched_resp.json()}
        except Exception as exc:
            logger.debug(f"State refresh failed: {exc}")

    async def request(self, flow: http.HTTPFlow):
        client_ip = flow.client_conn.peername[0] if flow.client_conn.peername else "unknown"
        self._refresh_state()
        if client_ip in self._blocked_ips:
            flow.response = http.Response.make(403, b"Blocked by ShieldNet")
            return

        content_type = flow.request.headers.get("Content-Type", "").split(";")[0].strip().lower()
        sensitivity = self._watched_ips.get(client_ip, 1.0)
        if content_type in ALL_MEDIA_MIMES:
            filename = flow.request.path.split("/")[-1] or "upload"
            confidence = await analyze_and_report(flow.request.content, filename, content_type, client_ip, sensitivity)
            if confidence and confidence >= THRESHOLD_LIKELY:
                flow.response = http.Response.make(
                    403,
                    json.dumps({
                        "error": "ShieldNet: Steganographic content detected", 
                        "confidence": confidence, 
                        "action": "blocked"
                    }).encode(),
                    {"Content-Type": "application/json"},
                )


addons = [ShieldNetProxyAddon()]
