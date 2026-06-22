"""
ShieldNet — Pipeline B: Async Backend Client
=============================================
Sends steganography detection events to the ShieldNet FastAPI backend.

Public API
----------
send_steg_event(event: dict) -> bool
    Async POST to POST /api/steg/event with retry on failure.
    Returns True on success, False if all retries exhausted.

build_event_payload(...) -> dict
    Convenience factory to build a validated event payload.

Configuration
-------------
Reads API_BASE_URL from backend.core.config.settings.app.API_BASE_URL
(default: http://127.0.0.1:8000).
Override via the API_BASE_URL environment variable.

Retry Policy
------------
- 3 attempts total
- Exponential backoff: 1s, 2s, 4s
- Timeout per request: 10 seconds
- All failures logged to pipeline_b/logs/pipeline_b.log
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger("shieldnet.pipeline_b.backend_client")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
_DEFAULT_API_BASE = "http://127.0.0.1:8000"

def _get_api_base() -> str:
    """Read API base URL from env → backend config → default."""
    env_url = os.environ.get("API_BASE_URL", "")
    if env_url:
        return env_url.rstrip("/")
    try:
        from backend.core.config import settings
        return settings.app.API_BASE_URL.rstrip("/")
    except Exception:
        return _DEFAULT_API_BASE


_STEG_EVENT_ENDPOINT = "/api/steg/event"
_MAX_RETRIES = 3
_RETRY_BACKOFF_BASE = 1.0  # seconds
_REQUEST_TIMEOUT = 10.0    # seconds


# ---------------------------------------------------------------------------
# Payload builder
# ---------------------------------------------------------------------------

def build_event_payload(
    filename: str,
    prediction: str,
    confidence: float,
    severity: str,
    source_ip: str,
    *,
    file_size: Optional[int] = None,
    mime_type: Optional[str] = None,
    algorithm_detected: Optional[str] = None,
    payload_estimate: Optional[int] = None,
    scores: Optional[dict] = None,
    forensic_data: Optional[dict] = None,
) -> dict:
    """
    Build a validated event payload matching the StegEventCreate schema
    accepted by POST /api/steg/event.

    Parameters
    ----------
    filename       : str — name of the analyzed file
    prediction     : "clean" | "steg"
    confidence     : float [0, 1]
    severity       : "clean" | "suspicious" | "likely" | "critical"
    source_ip      : str — originating client IP address
    file_size      : int | None — file size in bytes
    mime_type      : str | None — MIME type of the file
    algorithm_detected : str | None — top triggered algorithm
    payload_estimate   : int | None — estimated hidden bytes
    scores         : dict | None — per-algorithm numeric scores
    forensic_data  : dict | None — additional forensic context

    Returns
    -------
    dict — payload ready to be serialized and POSTed to the backend
    """
    _forensic = forensic_data or {}
    if scores:
        _forensic["algorithm_scores"] = scores
    _forensic["analysis_timestamp"] = datetime.now(timezone.utc).isoformat()
    _forensic["pipeline"] = "B"
    _forensic["severity_pipeline_b"] = severity

    return {
        "source_ip":          source_ip,
        "media_type":         "image",
        "confidence":         round(float(confidence), 4),
        "filename":           filename,
        "file_size":          file_size,
        "algorithm_detected": algorithm_detected,
        "payload_estimate":   payload_estimate or 0,
        "frame_count":        None,
        "forensic_data":      _forensic,
        "frame_results":      [],
        "audio_results":      [],
    }


# ---------------------------------------------------------------------------
# Core async sender
# ---------------------------------------------------------------------------

async def send_steg_event(event: dict) -> bool:
    """
    POST a steg detection event to the backend with retry.

    Parameters
    ----------
    event : dict
        Payload built by build_event_payload() or equivalent.

    Returns
    -------
    bool — True if the backend responded with 2xx, False otherwise.
    """
    try:
        import httpx
    except ImportError:
        logger.error(
            "[BackendClient] httpx is not installed. "
            "Cannot send backend event. Run: pip install httpx"
        )
        return False

    api_base = _get_api_base()
    url = f"{api_base}{_STEG_EVENT_ENDPOINT}"

    for attempt in range(1, _MAX_RETRIES + 1):
        try:
            async with httpx.AsyncClient(timeout=_REQUEST_TIMEOUT) as client:
                response = await client.post(
                    url,
                    json=event,
                    headers={"Content-Type": "application/json"},
                )

            if response.status_code < 300:
                logger.info(
                    f"[BackendClient] Event sent successfully "
                    f"(attempt {attempt}/{_MAX_RETRIES}): "
                    f"HTTP {response.status_code} ← {url}"
                )
                return True
            else:
                logger.warning(
                    f"[BackendClient] Backend returned HTTP {response.status_code} "
                    f"(attempt {attempt}/{_MAX_RETRIES}): {response.text[:200]}"
                )

        except httpx.ConnectError:
            logger.warning(
                f"[BackendClient] Connection refused to {url} "
                f"(attempt {attempt}/{_MAX_RETRIES}). "
                "Is the backend running?"
            )
        except httpx.TimeoutException:
            logger.warning(
                f"[BackendClient] Request timed out after {_REQUEST_TIMEOUT}s "
                f"(attempt {attempt}/{_MAX_RETRIES})"
            )
        except Exception as exc:
            logger.error(
                f"[BackendClient] Unexpected error on attempt {attempt}/{_MAX_RETRIES}: "
                f"{type(exc).__name__}: {exc}"
            )

        if attempt < _MAX_RETRIES:
            backoff = _RETRY_BACKOFF_BASE * (2 ** (attempt - 1))
            logger.info(f"[BackendClient] Retrying in {backoff:.1f}s …")
            await asyncio.sleep(backoff)

    logger.error(
        f"[BackendClient] All {_MAX_RETRIES} attempts failed for event: "
        f"filename={event.get('filename', '?')}, "
        f"confidence={event.get('confidence', 0):.3f}. "
        "Event NOT delivered to backend."
    )
    return False


def send_steg_event_sync(event: dict) -> bool:
    """
    Synchronous wrapper around send_steg_event() for use in
    non-async contexts (e.g., mitmproxy's threaded addon callbacks).

    Creates a new event loop if none is running.
    """
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            # We're already in an async context (e.g., mitmproxy async addon)
            # Schedule as a coroutine and return immediately — caller should await
            import concurrent.futures
            future = asyncio.run_coroutine_threadsafe(send_steg_event(event), loop)
            try:
                return future.result(timeout=35)  # 3 retries × 10s + backoff
            except concurrent.futures.TimeoutError:
                logger.error("[BackendClient] Sync wrapper timed out waiting for async result.")
                return False
        else:
            return loop.run_until_complete(send_steg_event(event))
    except RuntimeError:
        # No event loop exists — create one
        return asyncio.run(send_steg_event(event))
