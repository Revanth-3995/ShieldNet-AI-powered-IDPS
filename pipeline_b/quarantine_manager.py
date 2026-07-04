"""
ShieldNet — Pipeline B: Quarantine Manager
==========================================
Handles secure file quarantine and detection record persistence.

Public API
----------
quarantine_file(filepath, detection_record) -> Optional[str]
    Moves/copies a flagged file into the dated quarantine directory.
    Returns the quarantine path, or None on failure.

save_detection_record(record: dict) -> None
    Appends a detection event to logs/detections.json (thread-safe, atomic write).

load_detections() -> list[dict]
    Returns all persisted detection records from logs/detections.json.
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger("shieldnet.pipeline_b.quarantine")

# ---------------------------------------------------------------------------
# Directory layout under pipeline_b/
# ---------------------------------------------------------------------------
_BASE = Path(__file__).resolve().parent
QUARANTINE_DIR = _BASE / "quarantine"
LOGS_DIR       = _BASE / "logs"
DETECTIONS_FILE = LOGS_DIR / "detections.json"

# Ensure directories exist at import time
QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
LOGS_DIR.mkdir(parents=True, exist_ok=True)

# Thread lock for detections.json writes
_LOCK = threading.Lock()


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _safe_filename(name: str, max_len: int = 200) -> str:
    """Strip path separators and dangerous characters from a filename."""
    import re
    base = os.path.basename(name)
    safe = re.sub(r"[^\w.\-]", "_", base)
    return safe[:max_len] or "unknown_file"


def _atomic_append(filepath: Path, record: dict) -> None:
    """
    Thread-safe append of a single record to a JSON-lines-compatible file
    that maintains a top-level JSON array.

    Strategy: read → append → write (under _LOCK).
    Falls back gracefully on any I/O error.
    """
    with _LOCK:
        try:
            if filepath.exists():
                with open(filepath, "r", encoding="utf-8") as fh:
                    try:
                        existing: list = json.load(fh)
                        if not isinstance(existing, list):
                            existing = []
                    except json.JSONDecodeError:
                        existing = []
            else:
                existing = []

            existing.append(record)

            tmp = filepath.with_suffix(".tmp")
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(existing, fh, indent=2, ensure_ascii=False, default=str)

            # Atomic rename (works on Windows too)
            os.replace(tmp, filepath)
        except Exception as exc:
            logger.error(f"[Quarantine] Failed to write detection record: {exc}")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def quarantine_file(filepath: str, detection_record: dict) -> Optional[str]:
    """
    Copy a flagged image file into the quarantine directory and persist
    a detection record to logs/detections.json.

    Parameters
    ----------
    filepath : str
        Absolute path to the file that must be quarantined.
    detection_record : dict
        Pre-built detection record (filename, timestamp, confidence, severity, prediction).
        Additional keys are accepted and stored as-is.

    Returns
    -------
    str | None
        The quarantine destination path on success, None on failure.
    """
    source = Path(filepath)
    if not source.exists():
        logger.warning(f"[Quarantine] Source file not found: {filepath}")
        return None

    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    q_dir = QUARANTINE_DIR / today
    q_dir.mkdir(parents=True, exist_ok=True)

    safe_name = _safe_filename(source.name)
    stem = Path(safe_name).stem
    suffix = Path(safe_name).suffix
    confidence_pct = int(detection_record.get("confidence", 0) * 100)
    dest = q_dir / f"{stem}_{confidence_pct}pct{suffix}"

    # Never overwrite — add counter suffix
    counter = 2
    while dest.exists():
        dest = q_dir / f"{stem}_{confidence_pct}pct_{counter}{suffix}"
        counter += 1

    try:
        shutil.copy2(source, dest)
        logger.warning(
            f"[Quarantine] QUARANTINED: {source.name} → {dest} "
            f"(confidence={detection_record.get('confidence', 0):.2%})"
        )
    except Exception as exc:
        logger.error(f"[Quarantine] Failed to copy {filepath} to quarantine: {exc}")
        return None

    # Enrich record with quarantine path
    enriched = {
        **detection_record,
        "quarantine_path": str(dest),
        "original_path": str(source),
    }

    save_detection_record(enriched)
    return str(dest)


def save_detection_record(record: dict) -> None:
    """
    Persist a detection record to pipeline_b/logs/detections.json.
    Records are stored as a JSON array and appended atomically.

    Parameters
    ----------
    record : dict
        Any detection metadata. Recommended keys:
          filename, timestamp, confidence, severity, prediction
    """
    # Ensure we always have a timestamp
    if "timestamp" not in record:
        record = {**record, "timestamp": datetime.now(timezone.utc).isoformat()}

    _atomic_append(DETECTIONS_FILE, record)
    logger.info(
        f"[Quarantine] Detection record saved: "
        f"{record.get('filename', 'unknown')} | "
        f"severity={record.get('severity', '?')} | "
        f"confidence={record.get('confidence', 0):.3f}"
    )


def load_detections() -> list:
    """
    Load all persisted detection records from logs/detections.json.

    Returns
    -------
    list[dict]
        All records (most recent last), or empty list if file doesn't exist.
    """
    if not DETECTIONS_FILE.exists():
        return []
    try:
        with open(DETECTIONS_FILE, "r", encoding="utf-8") as fh:
            data = json.load(fh)
            return data if isinstance(data, list) else []
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning(f"[Quarantine] Could not load detections.json: {exc}")
        return []


def build_detection_record(
    filename: str,
    confidence: float,
    severity: str,
    prediction: str,
    *,
    source_ip: str = "unknown",
    quarantine_path: Optional[str] = None,
) -> dict:
    """
    Convenience factory to build a well-structured detection record.

    Returns
    -------
    dict matching the schema:
        {filename, timestamp, confidence, severity, prediction, source_ip, quarantine_path}
    """
    return {
        "filename": filename,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "confidence": round(float(confidence), 4),
        "severity": severity,
        "prediction": prediction,
        "source_ip": source_ip,
        "quarantine_path": quarantine_path,
    }
