"""
ShieldNet — Centralized Configuration System
All settings sourced from environment variables with sensible defaults.
Override via .env file or actual environment variables.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

# ---------------------------------------------------------------------------
# Base paths
# ---------------------------------------------------------------------------
ROOT_DIR = Path(__file__).resolve().parent.parent.parent
LOG_DIR = ROOT_DIR / "logs"
QUARANTINE_DIR = ROOT_DIR / "quarantine"
DATA_DIR = ROOT_DIR / "data"

for _d in (LOG_DIR, QUARANTINE_DIR, DATA_DIR):
    _d.mkdir(parents=True, exist_ok=True)


def _env(key: str, default: str = "") -> str:
    return os.environ.get(key, default)


def _env_int(key: str, default: int) -> int:
    try:
        return int(os.environ.get(key, default))
    except (TypeError, ValueError):
        return default


def _env_float(key: str, default: float) -> float:
    try:
        return float(os.environ.get(key, default))
    except (TypeError, ValueError):
        return default


def _env_bool(key: str, default: bool) -> bool:
    val = os.environ.get(key, str(default)).lower()
    return val in ("1", "true", "yes", "on")


# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------
class AppSettings:
    NAME: str = _env("APP_NAME", "ShieldNet")
    VERSION: str = _env("APP_VERSION", "3.0.0")
    ENV: Literal["development", "staging", "production", "testing"] = _env("APP_ENV", "development")  # type: ignore[assignment]
    DEBUG: bool = _env_bool("APP_DEBUG", True)
    SECRET_KEY: str = _env("APP_SECRET_KEY", "change-me-in-production")

    HOST: str = _env("APP_HOST", "0.0.0.0")
    PORT: int = _env_int("APP_PORT", 8000)
    API_BASE_URL: str = _env("API_BASE_URL", "http://127.0.0.1:8000")

    CORS_ORIGINS: list[str] = _env("CORS_ORIGINS", "*").split(",")
    WORKERS: int = _env_int("APP_WORKERS", 1)

    # Path management
    BASE_DIR: Path = ROOT_DIR
    BACKEND_DIR: Path = ROOT_DIR / "backend"
    DATA_DIR: Path = DATA_DIR
    LOG_DIR: Path = LOG_DIR
    QUARANTINE_DIR: Path = QUARANTINE_DIR
    MODELS_DIR: Path = ROOT_DIR / "models"
    UPLOADS_DIR: Path = ROOT_DIR / "uploads"
    TEMP_DIR: Path = ROOT_DIR / "temp"

    def __init__(self):
        # Create directories
        for _d in (self.DATA_DIR, self.LOG_DIR, self.QUARANTINE_DIR, self.MODELS_DIR, self.UPLOADS_DIR, self.TEMP_DIR):
            _d.mkdir(parents=True, exist_ok=True)
        
        # Validation
        if self.ENV == "production" and self.SECRET_KEY == "change-me-in-production":
            import warnings
            warnings.warn("APP_SECRET_KEY is using a default value in production environment!", UserWarning)


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------
class DatabaseSettings:
    # SQLite default; swap for PostgreSQL by setting DATABASE_URL env var
    # e.g. DATABASE_URL=postgresql+psycopg2://user:pass@host:5432/shieldnet
    URL: str = _env(
        "DATABASE_URL",
        f"sqlite:///{DATA_DIR / 'shieldnet.db'}",
    )
    POOL_SIZE: int = _env_int("DB_POOL_SIZE", 10)
    MAX_OVERFLOW: int = _env_int("DB_MAX_OVERFLOW", 20)
    POOL_TIMEOUT: int = _env_int("DB_POOL_TIMEOUT", 30)
    ECHO_SQL: bool = _env_bool("DB_ECHO_SQL", False)

    # Migrations
    ALEMBIC_MIGRATIONS_DIR: Path = ROOT_DIR / "migrations"


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
class LogSettings:
    LEVEL: str = _env("LOG_LEVEL", "INFO")
    FORMAT: Literal["json", "text"] = _env("LOG_FORMAT", "text")  # type: ignore[assignment]
    FILE_ENABLED: bool = _env_bool("LOG_FILE_ENABLED", True)
    FILE_PATH: Path = LOG_DIR / "shieldnet.log"
    FILE_MAX_BYTES: int = _env_int("LOG_FILE_MAX_BYTES", 10 * 1024 * 1024)  # 10 MB
    FILE_BACKUP_COUNT: int = _env_int("LOG_FILE_BACKUP_COUNT", 5)

    # Per-module log levels (comma-separated key=level pairs)
    # e.g.  MODULE_LEVELS=shieldnet.idps=DEBUG,shieldnet.steg=WARNING
    MODULE_LEVELS: dict[str, str] = dict(
        pair.split("=")
        for pair in _env("LOG_MODULE_LEVELS", "").split(",")
        if "=" in pair
    )


# ---------------------------------------------------------------------------
# Detection thresholds
# ---------------------------------------------------------------------------
class DetectionSettings:
    # Severity bands
    CONFIDENCE_CRITICAL: float = _env_float("CONF_CRITICAL", 0.85)
    CONFIDENCE_HIGH: float = _env_float("CONF_HIGH", 0.70)
    CONFIDENCE_MEDIUM: float = _env_float("CONF_MEDIUM", 0.40)

    # IDPS
    IDPS_ML_THRESHOLD: float = _env_float("IDPS_ML_THRESHOLD", 0.70)
    IDPS_FLOW_WINDOW_SECONDS: int = _env_int("IDPS_FLOW_WINDOW_SECONDS", 10)
    IDPS_MIN_PACKETS_FOR_ML: int = _env_int("IDPS_MIN_PACKETS_FOR_ML", 5)

    # Steg
    STEG_SUSPICIOUS_THRESHOLD: float = _env_float("STEG_SUSPICIOUS_THRESHOLD", 0.40)
    STEG_LIKELY_THRESHOLD: float = _env_float("STEG_LIKELY_THRESHOLD", 0.70)
    STEG_CRITICAL_THRESHOLD: float = _env_float("STEG_CRITICAL_THRESHOLD", 0.85)

    # Correlation
    CORRELATION_WINDOW_MINUTES: int = _env_int("CORRELATION_WINDOW_MINUTES", 30)

    # Auto-block
    AUTO_BLOCK_ENABLED: bool = _env_bool("AUTO_BLOCK_ENABLED", True)
    AUTO_BLOCK_SEVERITIES: set[str] = set(
        _env("AUTO_BLOCK_SEVERITIES", "high,critical").split(",")
    )


# ---------------------------------------------------------------------------
# Queue / async workers
# ---------------------------------------------------------------------------
class QueueSettings:
    # Max queue depths before back-pressure kicks in
    ALERT_BUS_MAXSIZE: int = _env_int("ALERTBUS_MAXSIZE", 1000)
    DETECTION_QUEUE_MAXSIZE: int = _env_int("DETECTION_QUEUE_MAXSIZE", 500)
    PROCESSING_THREAD_POOL_SIZE: int = _env_int("THREAD_POOL_SIZE", 4)

    # How long to wait for workers on shutdown
    SHUTDOWN_TIMEOUT_SECONDS: int = _env_int("SHUTDOWN_TIMEOUT", 10)


# ---------------------------------------------------------------------------
# Simulation / demo
# ---------------------------------------------------------------------------
class SimulationSettings:
    ENABLED: bool = _env_bool("SIM_ENABLED", False)
    STEG_INTERVAL_MIN: float = _env_float("SIM_STEG_INTERVAL_MIN", 4.0)
    STEG_INTERVAL_MAX: float = _env_float("SIM_STEG_INTERVAL_MAX", 8.0)
    IDPS_INTERVAL_MIN: float = _env_float("SIM_IDPS_INTERVAL_MIN", 2.0)
    IDPS_INTERVAL_MAX: float = _env_float("SIM_IDPS_INTERVAL_MAX", 5.0)
    ATTACKER_IPS: list[str] = _env(
        "SIM_ATTACKER_IPS",
        "192.168.1.47,10.0.0.99,172.16.0.5,203.0.113.42,198.51.100.7,192.168.1.22",
    ).split(",")


# ---------------------------------------------------------------------------
# Future: AI pipeline placeholders
# ---------------------------------------------------------------------------
class AISettings:
    MODELS_DIR: Path = ROOT_DIR / "models"
    IDPS_MODEL_PATH: Path = MODELS_DIR / "idps_model.pkl"
    # Deep-learning slots (unused until Part 2 upgrade)
    CNN_STEG_MODEL_PATH: Path = MODELS_DIR / "cnn_steg.pt"
    XAI_ENABLED: bool = _env_bool("XAI_ENABLED", True)
    SHAP_MAX_SAMPLES: int = _env_int("SHAP_MAX_SAMPLES", 100)


# ---------------------------------------------------------------------------
# Assembled settings singleton
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Feature Toggles
# ---------------------------------------------------------------------------
class FeatureToggles:
    ENABLE_REALTIME_ALERTS: bool = _env_bool("FEAT_REALTIME_ALERTS", True)
    ENABLE_AUTO_BLOCK: bool = _env_bool("FEAT_AUTO_BLOCK", True)
    ENABLE_CORRELATION_ENGINE: bool = _env_bool("FEAT_CORRELATION", True)
    ENABLE_HONEYPOT_DETECTION: bool = _env_bool("FEAT_HONEYPOT", True)
    ENABLE_STEG_QUARANTINE: bool = _env_bool("FEAT_STEG_QUARANTINE", True)


# ---------------------------------------------------------------------------
# Assembled settings singleton
# ---------------------------------------------------------------------------
class Settings:
    app = AppSettings()
    db = DatabaseSettings()
    log = LogSettings()
    detection = DetectionSettings()
    queue = QueueSettings()
    sim = SimulationSettings()
    ai = AISettings()
    features = FeatureToggles()

    def __init__(self):
        # Additional validation or cross-setting synchronization
        if self.app.ENV == "production":
            self.app.DEBUG = False
            self.db.ECHO_SQL = False
            self.log.LEVEL = "WARNING"


settings = Settings()
