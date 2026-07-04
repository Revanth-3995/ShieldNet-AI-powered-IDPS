"""
ShieldNet — Pipeline B: mitmproxy Addon
========================================
Intercepts HTTP/HTTPS requests, extracts uploaded images, runs steganalysis,
and automatically quarantines/alerts on detected steganographic content.

Usage
-----
    # Transparent proxy (HTTP):
    mitmdump -s pipeline_b/mitmproxy_addon.py --listen-port 8080

    # With SSL interception (HTTPS):
    mitmdump -s pipeline_b/mitmproxy_addon.py --listen-port 8080 --ssl-insecure

    # With verbose logging:
    mitmdump -s pipeline_b/mitmproxy_addon.py --listen-port 8080 -v

Architecture
------------
    Attacker
        ↓ uploads image
    mitmproxy (this addon)
        ↓ intercepts request
    Extract image bytes
        ↓ save to pipeline_b/uploads/
    predict_image(filepath)
        ↓ EfficientNet + statistical analysis
    evaluate_result(confidence)
        ↓ 4-tier decision
    Decision Engine
        ├── clean/suspicious → allow (log only)
        ├── likely           → block request (HTTP 403) + backend event + forensic report
        └── critical         → quarantine + block + backend event + forensic report

Supported content types
-----------------------
    image/jpeg, image/png, image/webp, image/bmp, image/gif
    multipart/form-data (file fields)
"""
from __future__ import annotations

import email.parser
import email.policy
import json
import logging
import os
import re
import tempfile
import uuid
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
from typing import Optional

import sys
from mitmproxy import http
from mitmproxy.net.http import http1

logger = logging.getLogger("shieldnet.pipeline_b.proxy")

# Add project root to sys.path to resolve 'pipeline_b.X' imports
_BASE = Path(__file__).resolve().parent
_PROJECT_ROOT = _BASE.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

# ---------------------------------------------------------------------------
# Directory layout
# ---------------------------------------------------------------------------
_BASE = Path(__file__).resolve().parent
UPLOADS_DIR = _BASE / "uploads"
UPLOADS_DIR.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------------------------
# Supported image MIME types
# ---------------------------------------------------------------------------
IMAGE_MIMES = frozenset({
    "image/jpeg",
    "image/png",
    "image/webp",
    "image/bmp",
    "image/gif",
})

_EXT_FROM_MIME = {
    "image/jpeg": ".jpg",
    "image/png":  ".png",
    "image/webp": ".webp",
    "image/bmp":  ".bmp",
    "image/gif":  ".gif",
}

# ---------------------------------------------------------------------------
# Logging setup — write to pipeline_b/logs/pipeline_b.log
# ---------------------------------------------------------------------------
_LOGS_DIR = _BASE / "logs"
_LOGS_DIR.mkdir(parents=True, exist_ok=True)

_file_handler = logging.FileHandler(_LOGS_DIR / "pipeline_b.log", encoding="utf-8")
_file_handler.setFormatter(logging.Formatter(
    "%(asctime)s [%(levelname)s] %(name)s — %(message)s"
))
logging.getLogger("shieldnet.pipeline_b").addHandler(_file_handler)
logging.getLogger("shieldnet.pipeline_b").setLevel(logging.INFO)


# ---------------------------------------------------------------------------
# Multipart parser
# ---------------------------------------------------------------------------

def _extract_multipart_images(content: bytes, content_type: str) -> list[tuple[str, bytes]]:
    """
    Extract image file data from a multipart/form-data request body.

    Returns
    -------
    list of (filename, image_bytes) tuples.
    """
    results = []
    boundary_match = re.search(r"boundary=([^\s;]+)", content_type)
    if not boundary_match:
        return results

    boundary = boundary_match.group(1).strip('"')

    # Split on boundary
    delimiter = f"--{boundary}".encode()
    end_delimiter = f"--{boundary}--".encode()

    parts = content.split(delimiter)
    for part in parts:
        if not part or part == b"--\r\n" or part.startswith(b"--"):
            continue

        # Separate headers from body
        sep = b"\r\n\r\n"
        if sep not in part:
            sep = b"\n\n"
        if sep not in part:
            continue

        header_bytes, body = part.split(sep, 1)

        # Strip trailing CRLF from body
        if body.endswith(b"\r\n"):
            body = body[:-2]
        if body.endswith(b"\n"):
            body = body[:-1]

        # Parse Content-Disposition
        header_str = header_bytes.decode("utf-8", errors="replace")
        filename_match = re.search(r'filename="?([^";\r\n]+)"?', header_str, re.IGNORECASE)
        ct_match = re.search(r"Content-Type:\s*([^\r\n]+)", header_str, re.IGNORECASE)

        if not filename_match and not ct_match:
            logger.info(f"[Addon Debug] Skipping part, no filename/content-type. Header: {header_str}")
            continue  # Not a file field

        fname = filename_match.group(1).strip() if filename_match else "upload"
        part_ct = ct_match.group(1).strip().lower() if ct_match else ""

        logger.info(f"[Addon Debug] Found part: fname={fname}, part_ct={part_ct}")

        # Accept if content-type is image or filename extension looks like an image
        ext = Path(fname).suffix.lower()
        is_image_ct = any(part_ct.startswith(m) for m in IMAGE_MIMES)
        is_image_ext = ext in {".jpg", ".jpeg", ".png", ".webp", ".bmp", ".gif"}

        if is_image_ct or is_image_ext:
            results.append((fname, body))

    return results


# ---------------------------------------------------------------------------
# Core analysis pipeline (wraps pipeline_b modules)
# ---------------------------------------------------------------------------

def _analyze_image_bytes(
    image_bytes: bytes,
    filename: str,
    source_ip: str,
    content_type: str,
) -> Optional[dict]:
    """
    Run the full Pipeline B analysis on raw image bytes.

    1. Save bytes to pipeline_b/uploads/ temporarily
    2. Call predict_image(filepath)
    3. Call evaluate_result(confidence)
    4. Quarantine if critical
    5. Send backend event if suspicious+
    6. Generate forensic report

    Returns the full analysis context dict, or None on fatal error.
    """
    # --- Save to uploads/ ---
    ext = _EXT_FROM_MIME.get(content_type.split(";")[0].strip(), Path(filename).suffix or ".jpg")
    safe_name = re.sub(r"[^\w.\-]", "_", filename)[:100]
    uid = uuid.uuid4().hex[:8]
    upload_path = UPLOADS_DIR / f"{uid}_{safe_name}"

    try:
        upload_path.write_bytes(image_bytes)
        logger.info(f"[Addon] Image saved: {upload_path} ({len(image_bytes)} bytes)")
    except OSError as exc:
        logger.error(f"[Addon] Could not save uploaded image: {exc}")
        return None

    try:
        # --- Prediction ---
        from pipeline_b.detector import predict_image, evaluate_result
        prediction_result = predict_image(str(upload_path))
        confidence = prediction_result["confidence"]
        decision = evaluate_result(confidence)

        severity = decision["severity"]
        action   = decision["action"]

        logger.info(
            f"[Addon] {filename} | {source_ip} | "
            f"confidence={confidence:.3f} | severity={severity} | action={action}"
        )

        # --- Quarantine (critical only) ---
        quarantine_path = None
        if severity == "critical":
            from pipeline_b.quarantine_manager import quarantine_file, build_detection_record
            detection_record = build_detection_record(
                filename=filename,
                confidence=confidence,
                severity=severity,
                prediction=prediction_result["prediction"],
                source_ip=source_ip,
            )
            quarantine_path = quarantine_file(str(upload_path), detection_record)
            logger.warning(f"[Addon] QUARANTINED: {filename} → {quarantine_path}")

        # --- Backend event (suspicious+) ---
        if severity in ("suspicious", "likely", "critical"):
            from pipeline_b.backend_client import build_event_payload, send_steg_event_sync
            event = build_event_payload(
                filename=filename,
                prediction=prediction_result["prediction"],
                confidence=confidence,
                severity=severity,
                source_ip=source_ip,
                file_size=prediction_result.get("file_size"),
                mime_type=prediction_result.get("mime_type"),
                algorithm_detected=prediction_result.get("algorithm_detected"),
                payload_estimate=prediction_result.get("payload_estimate", 0),
                scores=prediction_result.get("scores"),
            )
            success = send_steg_event_sync(event)
            if not success:
                logger.error(f"[Addon] Backend event delivery failed for {filename}")

        # --- Forensic report (all severities) ---
        from pipeline_b.forensics import generate_forensic_report, save_forensic_report
        report = generate_forensic_report(
            filepath=str(upload_path),
            prediction=prediction_result["prediction"],
            confidence=confidence,
            severity=severity,
            source_ip=source_ip,
            algorithm_detected=prediction_result.get("algorithm_detected"),
            payload_estimate=prediction_result.get("payload_estimate", 0),
            scores=prediction_result.get("scores"),
            method=prediction_result.get("method", "unknown"),
            cnn_score=prediction_result.get("cnn_score"),
            stat_score=prediction_result.get("stat_score"),
            extracted_message=prediction_result.get("extracted_message"),
            extraction_status=prediction_result.get("extraction_status"),
            mime_type=prediction_result.get("mime_type"),
            file_size=prediction_result.get("file_size"),
        )
        report_path = save_forensic_report(report)
        logger.info(f"[Addon] Forensic report: {report_path}")

        return {
            "filename":       filename,
            "source_ip":      source_ip,
            "confidence":     confidence,
            "severity":       severity,
            "action":         action,
            "prediction":     prediction_result["prediction"],
            "quarantine_path": quarantine_path,
            "report_path":    report_path,
            "upload_path":    str(upload_path),
        }

    except Exception as exc:
        logger.error(f"[Addon] Analysis pipeline error for {filename}: {exc}", exc_info=True)
        return None
    finally:
        # Clean up temporary upload file unless quarantine needed a copy
        # (quarantine_file uses shutil.copy2, so the upload is expendable)
        try:
            if upload_path.exists():
                os.unlink(upload_path)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# mitmproxy Addon class
# ---------------------------------------------------------------------------

class ShieldNetPipelineBAddon:
    """
    ShieldNet Pipeline B — mitmproxy Request Interceptor

    Intercepts all HTTP(S) requests and inspects:
    - Direct image uploads (Content-Type: image/*)
    - Multipart form uploads containing image file fields

    On detection:
    - suspicious → log + backend event
    - likely     → block (HTTP 403) + backend event + forensic report
    - critical   → quarantine + block + backend event + forensic report
    """

    def __init__(self):
        logger.info("[Addon] ShieldNet Pipeline B addon loaded.")
        logger.info(f"[Addon] Uploads directory: {UPLOADS_DIR}")
        logger.info(f"[Addon] Logs directory:    {_LOGS_DIR}")

    def request(self, flow: http.HTTPFlow) -> None:
        """
        Intercept every HTTP request.
        Detect and analyze image uploads synchronously within mitmproxy's event loop.
        """
        client_ip = self._get_client_ip(flow)
        content_type = flow.request.headers.get("Content-Type", "").split(";")[0].strip().lower()
        full_ct_raw = flow.request.headers.get("Content-Type", "")

        # --- Direct image upload ---
        if content_type in IMAGE_MIMES:
            filename = self._extract_filename(flow, content_type)
            logger.info(
                f"[Addon] Intercepted direct image upload: {filename} "
                f"from {client_ip} ({len(flow.request.content)} bytes)"
            )
            context = _analyze_image_bytes(
                flow.request.content,
                filename,
                client_ip,
                content_type,
            )
            if context:
                self._apply_response(flow, context)
            return

        # --- Multipart form-data ---
        if "multipart/form-data" in full_ct_raw.lower() and flow.request.content:
            logger.info(f"[Addon Debug] Attempting multipart extract. Content len: {len(flow.request.content)}, CT: {full_ct_raw}")
            images = _extract_multipart_images(flow.request.content, full_ct_raw)
            logger.info(f"[Addon Debug] Found {len(images)} images in multipart")
            if not images:
                return

            logger.info(
                f"[Addon] Intercepted multipart upload: {len(images)} image(s) "
                f"from {client_ip}"
            )

            # Analyze all image parts; block on highest severity
            contexts = []
            for fname, img_bytes in images:
                part_ct = content_type if content_type in IMAGE_MIMES else "image/png"
                ctx = _analyze_image_bytes(img_bytes, fname, client_ip, part_ct)
                if ctx:
                    contexts.append(ctx)

            if not contexts:
                return

            # Pick highest severity context to determine blocking
            _SEVERITY_ORDER = {"clean": 0, "suspicious": 1, "likely": 2, "critical": 3}
            worst = max(contexts, key=lambda c: _SEVERITY_ORDER.get(c["severity"], 0))
            self._apply_response(flow, worst)

    def _get_client_ip(self, flow: http.HTTPFlow) -> str:
        """Extract the originating client IP address from the flow."""
        try:
            if flow.client_conn.peername:
                return flow.client_conn.peername[0]
        except Exception:
            pass
        # Try X-Forwarded-For header
        xff = flow.request.headers.get("X-Forwarded-For", "")
        if xff:
            return xff.split(",")[0].strip()
        return "unknown"

    def _extract_filename(self, flow: http.HTTPFlow, content_type: str) -> str:
        """
        Best-effort filename extraction from the request:
        1. Content-Disposition header
        2. Last path segment of the URL
        3. Fallback based on content-type
        """
        cd = flow.request.headers.get("Content-Disposition", "")
        fm = re.search(r'filename="?([^";\r\n]+)"?', cd, re.IGNORECASE)
        if fm:
            return fm.group(1).strip()

        path_part = flow.request.path.split("?")[0].split("/")[-1]
        if path_part and "." in path_part:
            return path_part

        ext = _EXT_FROM_MIME.get(content_type, ".jpg")
        return f"intercepted_{datetime.now(timezone.utc).strftime('%H%M%S')}{ext}"

    def _apply_response(self, flow: http.HTTPFlow, context: dict) -> None:
        """
        Set the mitmproxy response based on the decision action:
        - allow / review → pass through (no response override)
        - block / quarantine → return HTTP 403 JSON response
        """
        action   = context.get("action", "allow")
        severity = context.get("severity", "clean")
        filename = context.get("filename", "?")
        confidence = context.get("confidence", 0.0)

        if action in ("block", "quarantine"):
            body = json.dumps({
                "error":    "ShieldNet: Steganographic content detected and blocked.",
                "filename":    filename,
                "confidence":  round(confidence, 4),
                "severity":    severity,
                "action":      action,
                "pipeline":   "B",
                "timestamp":  datetime.now(timezone.utc).isoformat(),
            }, indent=2).encode("utf-8")

            flow.response = http.Response.make(
                403,
                body,
                {"Content-Type": "application/json"},
            )
            logger.warning(
                f"[Addon] REQUEST BLOCKED: {filename} | "
                f"severity={severity} | confidence={confidence:.3f}"
            )
        else:
            logger.info(
                f"[Addon] Request allowed: {filename} | "
                f"severity={severity} | confidence={confidence:.3f}"
            )


# ---------------------------------------------------------------------------
# mitmproxy addon entry point
# ---------------------------------------------------------------------------
addons = [ShieldNetPipelineBAddon()]
