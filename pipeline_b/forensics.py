"""
ShieldNet — Pipeline B: Forensic Report Generator
==================================================
Generates and persists structured forensic reports for every analyzed image.

Public API
----------
generate_forensic_report(filepath, prediction, confidence, severity, source_ip, ...) -> dict
    Builds a comprehensive forensic report dict.

save_forensic_report(report: dict) -> str
    Saves the report as a JSON file under pipeline_b/logs/forensics/
    Returns the file path of the saved report.

load_forensic_report(report_path: str) -> dict
    Loads a previously saved forensic report by path.

Report Schema
-------------
{
    "report_id"         : str,       # unique report identifier
    "filename"          : str,
    "prediction"        : "clean" | "steg",
    "confidence"        : float,
    "severity"          : str,
    "file_size"         : int,
    "mime_type"         : str,
    "source_ip"         : str,
    "timestamp"         : str,       # UTC ISO-8601
    "recommended_action": str,
    "algorithm_detected": str | None,
    "payload_estimate"  : int,
    "algorithm_scores"  : dict,
    "method"            : str,
    "cnn_score"         : float | None,
    "stat_score"        : float | None,
    "extracted_message" : str | None,
    "extraction_status" : str | None,
    "pipeline"          : "B",
    "report_path"       : str,       # filled after save
}
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger("shieldnet.pipeline_b.forensics")

# ---------------------------------------------------------------------------
# Directory layout
# ---------------------------------------------------------------------------
_BASE = Path(__file__).resolve().parent
FORENSICS_DIR = _BASE / "logs" / "forensics"
FORENSICS_DIR.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------------------------
# Recommended action text (mirrored from decision_engine for self-containment)
# ---------------------------------------------------------------------------
_ACTION_TEXT = {
    "clean": (
        "No action required. File passes inspection."
    ),
    "suspicious": (
        "Flag for manual review. Pass-through allowed but monitored. "
        "Consider raising sensitivity for this source IP."
    ),
    "likely": (
        "Block outbound transfer and quarantine file. "
        "Flag source IP for elevated monitoring. "
        "Manual review recommended within 24 hours."
    ),
    "critical": (
        "IMMEDIATE ACTION REQUIRED. Block source IP at firewall level. "
        "Preserve original file in quarantine with chain-of-custody log. "
        "Notify security team and initiate incident response procedure."
    ),
}


def _make_report_id(filename: str, timestamp: str) -> str:
    """Generate a short deterministic report ID from filename + timestamp."""
    seed = f"{filename}:{timestamp}"
    return hashlib.sha256(seed.encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_forensic_report(
    filepath: str,
    prediction: str,
    confidence: float,
    severity: str,
    source_ip: str,
    *,
    algorithm_detected: Optional[str] = None,
    payload_estimate: int = 0,
    scores: Optional[dict] = None,
    method: str = "unknown",
    cnn_score: Optional[float] = None,
    stat_score: Optional[float] = None,
    extracted_message: Optional[str] = None,
    extraction_status: Optional[str] = None,
    mime_type: Optional[str] = None,
    file_size: Optional[int] = None,
) -> dict:
    """
    Build a comprehensive forensic report for a single analyzed image.

    Parameters
    ----------
    filepath          : str — path to the analyzed file on disk
    prediction        : "clean" | "steg"
    confidence        : float [0, 1]
    severity          : "clean" | "suspicious" | "likely" | "critical"
    source_ip         : str — originating client or uploader IP
    algorithm_detected: str | None — top algorithm that flagged the image
    payload_estimate  : int — estimated hidden payload bytes
    scores            : dict | None — per-algorithm numeric scores
    method            : str — classification method used
    cnn_score         : float | None — raw EfficientNet output
    stat_score        : float | None — top statistical algorithm score
    extracted_message : str | None — recovered LSB hidden text (if any)
    extraction_status : str | None — LSB extraction result label
    mime_type         : str | None — MIME type (auto-detected if omitted)
    file_size         : int | None — file size in bytes (auto-read if omitted)

    Returns
    -------
    dict — structured forensic report (not yet saved to disk)
    """
    filepath = str(filepath)
    path_obj  = Path(filepath)
    filename  = path_obj.name
    timestamp = datetime.now(timezone.utc).isoformat()

    # Auto-fill missing file metadata
    if file_size is None:
        try:
            file_size = os.path.getsize(filepath)
        except OSError:
            file_size = 0

    if mime_type is None:
        from pipeline_b.detector import get_mime_type
        mime_type = get_mime_type(filepath)

    report_id = _make_report_id(filename, timestamp)

    report = {
        "report_id":          report_id,
        "filename":           filename,
        "prediction":         prediction,
        "confidence":         round(float(confidence), 4),
        "severity":           severity,
        "file_size":          file_size,
        "mime_type":          mime_type,
        "source_ip":          source_ip,
        "timestamp":          timestamp,
        "recommended_action": _ACTION_TEXT.get(severity, _ACTION_TEXT["clean"]),
        "algorithm_detected": algorithm_detected,
        "payload_estimate":   payload_estimate,
        "algorithm_scores":   scores or {},
        "method":             method,
        "cnn_score":          round(float(cnn_score), 4) if cnn_score is not None else None,
        "stat_score":         round(float(stat_score), 4) if stat_score is not None else None,
        "extracted_message":  extracted_message,
        "extraction_status":  extraction_status,
        "pipeline":           "B",
        "report_path":        None,  # filled by save_forensic_report()
    }

    logger.info(
        f"[Forensics] Report generated: {report_id} | "
        f"{filename} | severity={severity} | confidence={confidence:.3f}"
    )
    return report


def save_forensic_report(report: dict) -> str:
    """
    Save a forensic report to pipeline_b/logs/forensics/<timestamp>_<filename>.json.

    Parameters
    ----------
    report : dict
        Report dict produced by generate_forensic_report().

    Returns
    -------
    str — absolute path to the saved JSON file.
    """
    timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    safe_name = Path(report.get("filename", "unknown")).stem
    # Sanitize filename for filesystem
    import re
    safe_name = re.sub(r"[^\w\-]", "_", safe_name)[:60]
    report_filename = f"{timestamp_str}_{safe_name}_{report.get('report_id', 'x')[:8]}.json"

    report_path = FORENSICS_DIR / report_filename
    report["report_path"] = str(report_path)

    try:
        with open(report_path, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, ensure_ascii=False, default=str)
        logger.info(f"[Forensics] Report saved: {report_path}")
    except OSError as exc:
        logger.error(f"[Forensics] Failed to save report: {exc}")
        raise

    return str(report_path)


def load_forensic_report(report_path: str) -> dict:
    """
    Load a previously saved forensic report from disk.

    Parameters
    ----------
    report_path : str — path to a .json forensic report file.

    Returns
    -------
    dict — the forensic report data.

    Raises
    ------
    FileNotFoundError if the report file does not exist.
    json.JSONDecodeError if the file is not valid JSON.
    """
    path = Path(report_path)
    if not path.exists():
        raise FileNotFoundError(f"Forensic report not found: {report_path}")
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def list_forensic_reports(limit: int = 50) -> list:
    """
    List the most recent forensic reports from pipeline_b/logs/forensics/.

    Parameters
    ----------
    limit : int — maximum number of reports to return (most recent first).

    Returns
    -------
    list[dict] — list of report summaries with report_path, filename,
                 confidence, severity, timestamp.
    """
    reports = sorted(FORENSICS_DIR.glob("*.json"), reverse=True)[:limit]
    summaries = []
    for rp in reports:
        try:
            with open(rp, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            summaries.append({
                "report_path":  str(rp),
                "report_id":    data.get("report_id"),
                "filename":     data.get("filename"),
                "prediction":   data.get("prediction"),
                "confidence":   data.get("confidence"),
                "severity":     data.get("severity"),
                "timestamp":    data.get("timestamp"),
            })
        except Exception as exc:
            logger.warning(f"[Forensics] Could not read report {rp}: {exc}")
    return summaries
