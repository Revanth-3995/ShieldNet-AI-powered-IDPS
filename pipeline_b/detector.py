"""
ShieldNet — Pipeline B: Detection Engine
=========================================
Core steganalysis inference layer.

Public API
----------
predict_image(filepath: str) -> dict
    {"prediction": "clean" | "steg", "confidence": float, "scores": dict, ...}

evaluate_result(confidence: float) -> dict
    {"severity": "clean|suspicious|likely|critical", "action": "allow|review|block|quarantine"}

get_mime_type(filepath: str) -> str
    Returns MIME type string for the given filepath.

IMPORTANT: This module wraps the existing backend services — the EfficientNet-B0
model is NOT retrained or modified. Images are read from disk, passed through
the same statistical algorithms + CNN pipeline used by the FastAPI upload endpoint.
"""
from __future__ import annotations

import io
import logging
import mimetypes
import os
from pathlib import Path
from typing import Optional

import numpy as np

logger = logging.getLogger("shieldnet.pipeline_b.detector")

# ---------------------------------------------------------------------------
# Severity / threshold table (from spec)
# ---------------------------------------------------------------------------
# 0.00 – 0.40 → clean    → allow
# 0.40 – 0.70 → suspicious → review
# 0.70 – 0.85 → likely   → block
# 0.85 – 1.00 → critical → quarantine

_THRESHOLDS = [
    (0.85, "critical", "quarantine"),
    (0.70, "likely",   "block"),
    (0.40, "suspicious", "review"),
    (0.00, "clean",    "allow"),
]

# Supported image MIME types
SUPPORTED_IMAGE_MIMES = {
    "image/jpeg",
    "image/png",
    "image/webp",
    "image/bmp",
    "image/gif",
}

# Extension → MIME fallback map (mimetypes module can be incomplete on Windows)
_EXT_MIME = {
    ".jpg":  "image/jpeg",
    ".jpeg": "image/jpeg",
    ".png":  "image/png",
    ".webp": "image/webp",
    ".bmp":  "image/bmp",
    ".gif":  "image/gif",
}


def get_mime_type(filepath: str) -> str:
    """Return the MIME type for a file based on its extension."""
    ext = Path(filepath).suffix.lower()
    if ext in _EXT_MIME:
        return _EXT_MIME[ext]
    guessed, _ = mimetypes.guess_type(filepath)
    return guessed or "application/octet-stream"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _load_image_array(filepath: str) -> np.ndarray:
    """
    Load an image from disk and return it as an RGB uint8 numpy array.
    Raises FileNotFoundError or IOError on failure.
    """
    try:
        from PIL import Image
        img = Image.open(filepath).convert("RGB")
        return np.array(img)
    except ImportError:
        raise RuntimeError(
            "Pillow is required for image loading. "
            "Install it with: pip install Pillow"
        )


def _run_statistical_analysis(img_array: np.ndarray) -> dict:
    """Run the 7-algorithm statistical steganalysis suite."""
    try:
        from backend.services.steg.algorithms import analyze_image, estimate_payload
        scores = analyze_image(img_array)
        payload_est = estimate_payload(img_array, scores.get("confidence", 0.0))
        scores["payload_estimate"] = payload_est
        return scores
    except ImportError as e:
        logger.warning(f"Statistical algorithms not available: {e}")
        return {"confidence": 0.5, "mock": True}


def _run_cnn_inference(img_array: np.ndarray, stat_scores: dict) -> dict:
    """
    Run EfficientNet-B0 inference fused with statistical scores.
    Falls back to statistical-only if model is unavailable.
    """
    try:
        from backend.services.steg.cnn.cnn_classifier import classify_image
        return classify_image(img_array, stat_scores)
    except ImportError as e:
        logger.warning(f"CNN classifier not available: {e}")
        return {
            "confidence": stat_scores.get("confidence", 0.0),
            "algorithm_detected": stat_scores.get("algorithm_detected"),
            "method": "statistical_fallback",
        }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def predict_image(filepath: str) -> dict:
    """
    Analyze an image file for steganographic content.

    Parameters
    ----------
    filepath : str
        Absolute or relative path to the image file on disk.

    Returns
    -------
    dict with keys:
        prediction    : "clean" | "steg"
        confidence    : float in [0.0, 1.0]
        algorithm_detected : str | None
        method        : str — "efficientnet_b0_fused" | "statistical_fallback" | ...
        payload_estimate   : int — estimated hidden bytes
        scores        : dict — per-algorithm scores
        mock          : bool — True if running without Pillow/algorithms
        file_size     : int — file size in bytes
        mime_type     : str
    """
    filepath = str(filepath)

    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Image file not found: {filepath}")

    file_size = os.path.getsize(filepath)
    mime_type = get_mime_type(filepath)

    logger.info(f"[Detector] Analyzing: {filepath} ({mime_type}, {file_size} bytes)")

    try:
        img_array = _load_image_array(filepath)
    except Exception as exc:
        logger.error(f"[Detector] Failed to load image {filepath}: {exc}")
        return {
            "prediction": "clean",
            "confidence": 0.0,
            "algorithm_detected": None,
            "method": "load_error",
            "payload_estimate": 0,
            "scores": {},
            "mock": True,
            "file_size": file_size,
            "mime_type": mime_type,
            "error": str(exc),
        }

    # --- Statistical analysis ---
    stat_scores = _run_statistical_analysis(img_array)

    # --- CNN inference (fused) ---
    cnn_result = _run_cnn_inference(img_array, stat_scores)

    confidence = float(cnn_result.get("confidence", stat_scores.get("confidence", 0.0)))
    confidence = max(0.0, min(1.0, confidence))  # clamp to [0, 1]

    # --- LSB hidden message extraction (bonus: boosts confidence to 1.0 if readable text found) ---
    try:
        from backend.services.steg.analyzer import extract_lsb_message
        lsb = extract_lsb_message(img_array)
        if lsb.get("extracted_message") is not None:
            confidence = 1.0
            cnn_result["algorithm_detected"] = "LSB-Spatial"
    except Exception:
        lsb = {}

    # --- Numeric algorithm score keys ---
    _ALGO_KEYS = {
        "chi_square", "sample_pair", "rs_analysis",
        "dct_histogram", "pixel_histogram", "noise_residual", "benford_law"
    }
    scores = {
        k: round(float(v), 4)
        for k, v in stat_scores.items()
        if k in _ALGO_KEYS and isinstance(v, (int, float))
    }

    prediction = "steg" if confidence >= 0.40 else "clean"

    result = {
        "prediction": prediction,
        "confidence": round(confidence, 4),
        "algorithm_detected": cnn_result.get("algorithm_detected") or stat_scores.get("algorithm_detected"),
        "method": cnn_result.get("method", "statistical_fallback"),
        "payload_estimate": stat_scores.get("payload_estimate", 0),
        "scores": scores,
        "mock": bool(stat_scores.get("mock", False)),
        "file_size": file_size,
        "mime_type": mime_type,
        **{k: v for k, v in lsb.items() if k in ("extracted_message", "extraction_status", "extraction_method")},
    }

    # Optional CNN debug fields
    if "cnn_score" in cnn_result:
        result["cnn_score"] = round(float(cnn_result["cnn_score"]), 4)
    if "stat_score" in cnn_result:
        result["stat_score"] = round(float(cnn_result["stat_score"]), 4)

    logger.info(
        f"[Detector] Result: prediction={result['prediction']}, "
        f"confidence={result['confidence']:.3f}, "
        f"method={result['method']}"
    )
    return result


def evaluate_result(confidence: float) -> dict:
    """
    Map a confidence score to a severity level and recommended action.

    Parameters
    ----------
    confidence : float
        Confidence score in [0.0, 1.0] returned by predict_image().

    Returns
    -------
    dict with keys:
        severity : "clean" | "suspicious" | "likely" | "critical"
        action   : "allow" | "review" | "block" | "quarantine"
        message  : str — human-readable description
    """
    confidence = max(0.0, min(1.0, float(confidence)))

    for threshold, severity, action in _THRESHOLDS:
        if confidence >= threshold:
            break

    _messages = {
        "clean": "No steganographic content detected. File allowed through.",
        "suspicious": (
            "Possible steganographic content detected. "
            "File flagged for manual review; pass-through allowed but logged."
        ),
        "likely": (
            "Steganography likely present. "
            "Outbound transfer blocked. Source IP flagged for elevated monitoring."
        ),
        "critical": (
            "CONFIRMED steganographic covert channel. "
            "File quarantined. Immediate incident response required."
        ),
    }

    return {
        "severity": severity,
        "action": action,
        "message": _messages[severity],
        "confidence": round(confidence, 4),
    }
