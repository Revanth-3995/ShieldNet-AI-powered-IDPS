"""
ShieldNet — Centralized Logging System
Supports structured JSON logging, log rotation, per-module levels,
and request-scoped trace IDs for distributed tracing readiness.
"""
from __future__ import annotations

import json
import logging
import logging.handlers
import sys
import threading
from contextvars import ContextVar
from datetime import datetime, timezone
from typing import Any, Optional

# Context variable for per-request trace IDs (async-safe)
_trace_id_var: ContextVar[Optional[str]] = ContextVar("trace_id", default=None)


def get_trace_id() -> Optional[str]:
    return _trace_id_var.get()


def set_trace_id(trace_id: Optional[str]) -> None:
    _trace_id_var.set(trace_id)


# ---------------------------------------------------------------------------
# JSON formatter
# ---------------------------------------------------------------------------
class JSONFormatter(logging.Formatter):
    """Emit each log record as a single-line JSON object."""

    RESERVED = {"message", "levelname", "name", "timestamp", "trace_id", "exc_info"}

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "func": record.funcName,
            "line": record.lineno,
        }

        trace_id = get_trace_id()
        if trace_id:
            payload["trace_id"] = trace_id

        # Any extra keyword args attached to the record
        for key, val in record.__dict__.items():
            if key not in logging.LogRecord.__dict__ and key not in self.RESERVED and not key.startswith("_"):
                payload[key] = val

        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        elif record.exc_text:
            payload["exception"] = record.exc_text

        return json.dumps(payload, default=str)


# ---------------------------------------------------------------------------
# Text formatter (dev-friendly)
# ---------------------------------------------------------------------------
class TextFormatter(logging.Formatter):
    COLORS = {
        "DEBUG":    "\033[36m",   # cyan
        "INFO":     "\033[32m",   # green
        "WARNING":  "\033[33m",   # yellow
        "ERROR":    "\033[31m",   # red
        "CRITICAL": "\033[35m",   # magenta
    }
    RESET = "\033[0m"

    def format(self, record: logging.LogRecord) -> str:
        color = self.COLORS.get(record.levelname, "")
        trace = ""
        tid = get_trace_id()
        if tid:
            trace = f" [{tid[:8]}]"
        base = (
            f"{color}{record.levelname:8s}{self.RESET} "
            f"{datetime.fromtimestamp(record.created).strftime('%H:%M:%S')}"
            f"{trace} "
            f"\033[2m{record.name}\033[0m "
            f"{record.getMessage()}"
        )
        if record.exc_info:
            base += "\n" + self.formatException(record.exc_info)
        return base


# ---------------------------------------------------------------------------
# Setup entry point
# ---------------------------------------------------------------------------
_setup_lock = threading.Lock()
_configured = False


def setup_logging(
    level: str = "INFO",
    fmt: str = "text",
    file_path: Optional[str] = None,
    max_bytes: int = 10 * 1024 * 1024,
    backup_count: int = 5,
    module_levels: Optional[dict[str, str]] = None,
) -> None:
    """Configure the root logger and all handlers.
    Call once at application startup.
    """
    global _configured
    with _setup_lock:
        if _configured:
            return
        _configured = True

    numeric_level = getattr(logging, level.upper(), logging.INFO)

    formatter: logging.Formatter = (
        JSONFormatter() if fmt == "json" else TextFormatter()
    )

    # Root logger
    root = logging.getLogger()
    root.setLevel(numeric_level)

    # Remove any existing handlers (e.g. set by basicConfig)
    root.handlers.clear()

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    console_handler.setLevel(numeric_level)
    root.addHandler(console_handler)

    # Rotating file handler
    if file_path:
        try:
            file_handler = logging.handlers.RotatingFileHandler(
                file_path,
                maxBytes=max_bytes,
                backupCount=backup_count,
                encoding="utf-8",
            )
            file_handler.setFormatter(JSONFormatter())  # always JSON to file
            file_handler.setLevel(numeric_level)
            root.addHandler(file_handler)
        except OSError as exc:
            root.warning(f"Could not open log file {file_path}: {exc}")

    # Per-module overrides
    for module, mod_level in (module_levels or {}).items():
        logging.getLogger(module).setLevel(getattr(logging, mod_level.upper(), numeric_level))

    # Silence noisy third-party loggers
    for noisy in ("uvicorn.access", "sqlalchemy.engine"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    logging.getLogger("shieldnet").info(
        "Logging configured",
        extra={"log_level": level, "log_format": fmt},
    )


def init_from_settings() -> None:
    """Convenience: read backend/core/config.py and call setup_logging."""
    from backend.core.config import settings

    s = settings.log
    setup_logging(
        level=s.LEVEL,
        fmt=s.FORMAT,
        file_path=str(s.FILE_PATH) if s.FILE_ENABLED else None,
        max_bytes=s.FILE_MAX_BYTES,
        backup_count=s.FILE_BACKUP_COUNT,
        module_levels=s.MODULE_LEVELS,
    )


def get_logger(name: str) -> logging.Logger:
    """Return a named logger. Use dotted hierarchy: 'shieldnet.idps'."""
    return logging.getLogger(name)
