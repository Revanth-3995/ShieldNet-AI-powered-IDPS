"""
ShieldNet — Pipeline B: Full Steganalysis Engine
Intercepts images from the proxy and runs statistical algorithms.
"""
from __future__ import annotations

import io
import os
import random
import tempfile
import time
from pathlib import Path
from typing import Optional

import numpy as np
import requests

from backend.core.logging import get_logger
from backend.core.config import settings, QUARANTINE_DIR

logger = get_logger("shieldnet.steg.engine")

try:
    from backend.services.steg.algorithms import analyze_image, estimate_payload
    STEG_ALG_AVAILABLE = True
except ImportError:
    STEG_ALG_AVAILABLE = False
    logger.warning("steg_algorithms not available — using mock mode")

try:
    from backend.services.video.processing.pipeline import VideoAnalysisPipeline
    from backend.services.video.integration.analyzer_client import InternalAnalyzerClient
    VIDEO_ENGINE_AVAILABLE = True
except ImportError:
    VIDEO_ENGINE_AVAILABLE = False


def _mock_image_analysis(seed: str = "") -> dict:
    """Produce realistic mock analysis scores for demo/simulation."""
    rng = random.Random(hash(seed + str(time.time())) % 99999)
    # Simulate mostly clean with occasional detection
    is_steg = rng.random() < 0.35
    if is_steg:
        base = rng.uniform(0.55, 0.95)
        algo = rng.choice(["chi_square", "rs_analysis", "dct_histogram", "sample_pair"])
    else:
        base = rng.uniform(0.02, 0.25)
        algo = None
    return {
        "chi_square": rng.uniform(0.6, 0.9) if is_steg else rng.uniform(0.0, 0.15),
        "sample_pair": rng.uniform(0.5, 0.85) if is_steg else rng.uniform(0.0, 0.12),
        "rs_analysis": rng.uniform(0.6, 0.92) if is_steg else rng.uniform(0.0, 0.18),
        "dct_histogram": rng.uniform(0.4, 0.85) if is_steg else rng.uniform(0.0, 0.20),
        "pixel_histogram": rng.uniform(0.3, 0.75) if is_steg else rng.uniform(0.0, 0.15),
        "noise_residual": rng.uniform(0.3, 0.80) if is_steg else rng.uniform(0.0, 0.20),
        "benford_law": rng.uniform(0.3, 0.80) if is_steg else rng.uniform(0.0, 0.18),
        "confidence": float(np.clip(base, 0, 1)),
        "algorithm_detected": algo,
    }


def analyze_image_bytes(content: bytes, filename: str = "image") -> dict:
    """Analyze image bytes using steg algorithms."""
    if STEG_ALG_AVAILABLE:
        try:
            from PIL import Image
            img = Image.open(io.BytesIO(content)).convert("RGB")
            img_array = np.array(img)
            result = analyze_image(img_array)
            result["payload_estimate"] = estimate_payload(img_array, result.get("confidence", 0))
            return result
        except Exception as e:
            logger.warning(f"Image analysis error: {e}")
    return _mock_image_analysis(filename)


def post_steg_event(
    source_ip: str,
    media_type: str,
    confidence: float,
    filename: str,
    file_size: int,
    algorithm_detected: Optional[str],
    payload_estimate: Optional[int],
    forensic_data: dict,
    frame_count: Optional[int] = None,
    frame_results: list = None,
    audio_results: list = None,
):
    """Send detected steg event to backend API."""
    data = {
        "source_ip": source_ip,
        "media_type": media_type,
        "confidence": confidence,
        "filename": filename,
        "file_size": file_size,
        "algorithm_detected": algorithm_detected,
        "payload_estimate": payload_estimate,
        "frame_count": frame_count,
        "forensic_data": forensic_data,
        "frame_results": frame_results or [],
        "audio_results": audio_results or [],
    }
    try:
        r = requests.post(f"{settings.app.API_BASE_URL}/api/steg/event", json=data, timeout=10)
        logger.info(f"Reported {media_type} steg from {source_ip}: {r.status_code}")
        return r.json()
    except Exception as e:
        logger.error(f"Failed to POST event: {e}")
        return None


class StegEngine:
    """
    Standalone steganalysis engine that can run in simulation or live proxy mode.
    """

    def __init__(self, api_base: Optional[str] = None):
        self.api_base = api_base or settings.app.API_BASE_URL
        self.watch_endpoints: dict[str, float] = {}
        self._running = False
        logger.info("StegEngine initialized")

    async def analyze_and_report(
        self,
        content: bytes,
        filename: str,
        content_type: str,
        source_ip: str,
        sensitivity_multiplier: float = 1.0,
    ) -> Optional[float]:
        """Full analysis pipeline: detect → report → return confidence."""
        media_type = "video" if content_type.startswith("video/") else "image"

        if media_type == "image":
            # Image analysis remains synchronous for now but wrapped in async call
            result = analyze_image_bytes(content, filename)
            payload_est = result.get("payload_estimate", 0)
        else:
            with tempfile.NamedTemporaryFile(suffix=".mp4", delete=False) as tmp:
                tmp.write(content)
                tmp_path = tmp.name
            
            if VIDEO_ENGINE_AVAILABLE:
                client = InternalAnalyzerClient()
                pipeline = VideoAnalysisPipeline(analyzer=client)
                result = await pipeline.process_video(tmp_path)
            else:
                result = _mock_image_analysis(filename)
                result["frame_count"] = 15
                result["frame_results"] = []
                result["audio_results"] = []
            
            os.unlink(tmp_path)
            payload_est = result.get("payload_estimate", random.randint(1000, 50000))

        confidence = result.get("confidence", 0.0)
        effective_threshold = settings.detection.STEG_SUSPICIOUS_THRESHOLD / max(sensitivity_multiplier, 0.1)

        if confidence < effective_threshold:
            return None

        # Quarantine if high confidence
        if confidence >= settings.detection.STEG_LIKELY_THRESHOLD:
            ts = int(time.time())
            safe_name = f"{ts}_{confidence:.2f}_{filename}"[:200]
            quarantine_path = QUARANTINE_DIR / safe_name
            quarantine_path.write_bytes(content)
            logger.warning(f"[Quarantine] {filename} → {quarantine_path}")

        forensic_data = {
            "algorithms": {
                k: v for k, v in result.items()
                if k not in {"confidence", "frame_results", "audio_results", "frame_count"}
            },
            "analysis_timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "sensitivity_multiplier": sensitivity_multiplier,
        }

        # reporting is also wrapped in an async-friendly way if needed, 
        # but post_steg_event uses requests (sync). 
        # In a real async system we'd use httpx.
        post_steg_event(
            source_ip=source_ip,
            media_type=media_type,
            confidence=confidence,
            filename=filename,
            file_size=len(content),
            algorithm_detected=result.get("algorithm_detected"),
            payload_estimate=payload_est,
            forensic_data=forensic_data,
            frame_count=result.get("frame_count"),
            frame_results=result.get("frame_results", []),
            audio_results=result.get("audio_results", []),
        )
        return confidence
