"""
ShieldNet — Pipeline B: Decision Engine & Forensic Report Generator
Four-tier detection system with full forensic reporting.
"""
from __future__ import annotations

import json
import shutil
import math
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from backend.core.config import settings
from backend.core.logging import get_logger

logger = get_logger("shieldnet.steg.decision")

QUARANTINE_BASE = Path("quarantine")

TOOL_SIGNATURES = {
    "F5/OutGuess": ["dct_histogram", "benfords_law"],
    "Steghide/LSB": ["chi_square", "rs_analysis", "sample_pair"],
    "OpenPuff": ["chi_square", "pixel_histogram", "rs_analysis"],
    "Spread-Spectrum": ["noise_residual", "pixel_histogram"],
    "Audio-Echo": ["noise_residual"],
    "OpenStego": ["chi_square", "sample_pair", "benfords_law"],
}

RESPONSE_TEXT = {
    "critical": (
        "IMMEDIATE ACTION REQUIRED. Block source IP at firewall level. "
        "Preserve original file in quarantine with chain-of-custody log. "
        "Notify security team and initiate incident response procedure. "
        "Request legal review before file deletion."
    ),
    "likely": (
        "Block outbound transfer and quarantine file. "
        "Flag source IP for elevated monitoring. "
        "Manual review recommended within 24 hours."
    ),
    "suspicious": (
        "File flagged for manual review. Pass-through allowed but logged. "
        "Consider raising monitoring sensitivity for this source IP."
    ),
    "clean": "No action required.",
}


def _estimate_payload_bytes(scores: dict, file_size_bytes: int) -> int:
    """Estimate hidden payload size based on algorithm scores and file size."""
    top_score = max(scores.values()) if scores else 0.0
    # LSB in 8-bit image: max capacity ≈ 12.5% of pixels × channels
    # Scale by top algorithm score as an embedding rate proxy
    embedding_rate = top_score * 0.125  # conservative: score maps to 0–12.5%
    return int(file_size_bytes * embedding_rate)


def _detect_probable_tool(scores: dict) -> str:
    """Identify the most likely steganographic tool based on which algorithms fired."""
    if not scores:
        return "Unknown"
    triggered = {k for k, v in scores.items() if v >= 0.60}
    best_tool = "Unknown"
    best_overlap = 0
    for tool, sigs in TOOL_SIGNATURES.items():
        overlap = len(set(sigs) & triggered)
        if overlap > best_overlap:
            best_overlap = overlap
            best_tool = tool
    return best_tool


def _shap_attribution(scores: dict) -> list[dict]:
    """
    Compute SHAP-like attribution for Critical tier using KernelExplainer
    on the statistical feature vector. Falls back to sorted scores if shap unavailable.
    """
    try:
        import shap
        import numpy as np

        feature_names = list(scores.keys())
        feature_values = np.array([[scores[k] for k in feature_names]])

        # Simple linear model as explainer background: all-zeros (no steg) vs observed
        background = np.zeros_like(feature_values)

        def predict_fn(x):
            return np.array([[1.0 - float(np.mean(row)), float(np.mean(row))] for row in x])

        explainer = shap.KernelExplainer(predict_fn, background)
        shap_vals = explainer.shap_values(feature_values, nsamples=50, silent=True)
        # shap_vals[1] = SHAP values for class "steganographic"
        attrs = shap_vals[1][0] if isinstance(shap_vals, list) else shap_vals[0]
        result = sorted(
            [{"feature": feature_names[i], "shap_value": round(float(attrs[i]), 4),
              "raw_score": round(scores[feature_names[i]], 4)}
             for i in range(len(feature_names))],
            key=lambda x: abs(x["shap_value"]), reverse=True
        )
        return result
    except Exception:
        # Fallback: sort by raw score
        return sorted(
            [{"feature": k, "shap_value": round(v, 4), "raw_score": round(v, 4)}
             for k, v in scores.items()],
            key=lambda x: x["raw_score"], reverse=True
        )


def _quarantine_file(source_path: str, filename: str, confidence: float) -> Optional[str]:
    """Copy flagged file to quarantine directory. Never overwrites."""
    if not source_path or not Path(source_path).exists():
        return None
    try:
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        q_dir = QUARANTINE_BASE / today
        q_dir.mkdir(parents=True, exist_ok=True)

        stem = Path(filename).stem
        suffix = Path(filename).suffix
        pct = int(confidence * 100)
        dest = q_dir / f"{stem}_{pct}pct{suffix}"

        # Never overwrite
        counter = 2
        while dest.exists():
            dest = q_dir / f"{stem}_{pct}pct_{counter}{suffix}"
            counter += 1

        shutil.copy2(source_path, dest)
        logger.info(f"[Quarantine] {filename} → {dest}")
        return str(dest)
    except Exception as e:
        logger.warning(f"[Quarantine] Failed to copy {filename}: {e}")
        return None


def make_decision(
    scores: dict,
    filename: str,
    file_size_bytes: int,
    media_type: str,
    source_path: Optional[str] = None,
    video_extras: Optional[dict] = None,
) -> dict:
    """
    Four-tier decision engine.
    Returns: severity, confidence, should_block, forensic_json, report, quarantine_path
    """
    final_score = sum(scores.values()) / max(len(scores), 1)

    if final_score >= 0.85:
        severity = "critical"
    elif final_score >= 0.70:
        severity = "likely"
    elif final_score >= 0.40:
        severity = "suspicious"
    else:
        severity = "clean"

    should_block = final_score >= 0.70
    top_algos = sorted(scores.keys(), key=lambda k: scores[k], reverse=True)[:3]
    probable_tool = _detect_probable_tool(scores)
    payload_bytes = _estimate_payload_bytes(scores, file_size_bytes) if should_block else 0

    report: dict = {
        "filename": filename,
        "file_size_bytes": file_size_bytes,
        "media_type": media_type,
        "confidence_score": round(final_score, 4),
        "severity": severity,
        "algorithm_scores": {k: round(v, 4) for k, v in scores.items()},
        "top_contributing_algorithms": top_algos,
        "estimated_payload_bytes": payload_bytes,
        "probable_tool": probable_tool,
        "recommended_response": RESPONSE_TEXT.get(severity, RESPONSE_TEXT["clean"]),
        "quarantine_path": None,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    if video_extras:
        report.update({
            "frame_count_analyzed": video_extras.get("frame_count_analyzed", 0),
            "flagged_frames": video_extras.get("flagged_frames", []),
            "max_frame_confidence": video_extras.get("max_frame_confidence", 0.0),
            "audio_confidence": video_extras.get("audio_confidence", 0.0),
            "metadata_anomaly_score": video_extras.get("metadata_anomaly_score", 0.0),
            "frame_confidence_timeline": video_extras.get("frame_confidence_timeline", []),
        })

    # SHAP attribution for Critical tier
    if severity == "critical":
        report["shap_values"] = _shap_attribution(scores)

    # Quarantine for likely/critical
    if should_block and source_path:
        qpath = _quarantine_file(source_path, filename, final_score)
        report["quarantine_path"] = qpath

    return {
        "severity": severity,
        "confidence": final_score,
        "should_block": should_block,
        "forensic_json": json.dumps(report),
        "report": report,
        "quarantine_path": report.get("quarantine_path"),
    }
