"""
ShieldNet — Exception Handling Middleware & Base Exceptions
Provides:
  - Typed exception hierarchy
  - FastAPI middleware for uniform error responses
  - Request tracing (trace-id injection)
  - Structured error logging
"""
from __future__ import annotations

import time
import traceback
from typing import Callable
from uuid import uuid4

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from backend.core.logging import get_logger, set_trace_id

logger = get_logger("shieldnet.exceptions")


# ---------------------------------------------------------------------------
# Typed exception hierarchy
# ---------------------------------------------------------------------------
class ShieldNetError(Exception):
    """Base for all ShieldNet application errors."""
    status_code: int = 500
    error_code: str = "INTERNAL_ERROR"

    def __init__(self, message: str, detail: str | None = None, **extra):
        super().__init__(message)
        self.message = message
        self.detail = detail
        self.extra = extra

    def to_dict(self) -> dict:
        payload = {
            "error": self.error_code,
            "message": self.message,
        }
        if self.detail:
            payload["detail"] = self.detail
        if self.extra:
            payload.update(self.extra)
        return payload


class NotFoundError(ShieldNetError):
    status_code = 404
    error_code = "NOT_FOUND"


class ValidationError(ShieldNetError):
    status_code = 422
    error_code = "VALIDATION_ERROR"


class ConflictError(ShieldNetError):
    status_code = 409
    error_code = "CONFLICT"


class DatabaseError(ShieldNetError):
    status_code = 503
    error_code = "DATABASE_ERROR"


class DetectionEngineError(ShieldNetError):
    status_code = 500
    error_code = "DETECTION_ENGINE_ERROR"


class BlockingError(ShieldNetError):
    status_code = 500
    error_code = "BLOCKING_ERROR"


class QueueFullError(ShieldNetError):
    status_code = 503
    error_code = "QUEUE_FULL"


# ---------------------------------------------------------------------------
# Exception handlers (register on FastAPI app)
# ---------------------------------------------------------------------------
def shieldnet_exception_handler(request: Request, exc: ShieldNetError) -> JSONResponse:
    logger.error(
        f"ShieldNet error: {exc.error_code}",
        extra={
            "error_code": exc.error_code,
            "path": str(request.url),
            "message": exc.message,
        },
    )
    return JSONResponse(status_code=exc.status_code, content=exc.to_dict())


def generic_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.critical(
        "Unhandled exception",
        extra={
            "path": str(request.url),
            "exc_type": type(exc).__name__,
            "traceback": traceback.format_exc(),
        },
    )
    return JSONResponse(
        status_code=500,
        content={
            "error": "INTERNAL_ERROR",
            "message": "An unexpected error occurred.",
        },
    )


def register_exception_handlers(app: FastAPI) -> None:
    app.add_exception_handler(ShieldNetError, shieldnet_exception_handler)  # type: ignore[arg-type]
    app.add_exception_handler(Exception, generic_exception_handler)


# ---------------------------------------------------------------------------
# Tracing + timing middleware
# ---------------------------------------------------------------------------
class RequestTracingMiddleware(BaseHTTPMiddleware):
    """Inject X-Trace-ID header and log every request with latency."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        trace_id = request.headers.get("X-Trace-ID") or str(uuid4())
        set_trace_id(trace_id)

        start = time.perf_counter()
        try:
            response: Response = await call_next(request)
        except Exception as exc:
            logger.error(
                "Request failed with unhandled exception",
                extra={
                    "method": request.method,
                    "path": request.url.path,
                    "trace_id": trace_id,
                    "exc": str(exc),
                },
            )
            raise
        finally:
            elapsed_ms = (time.perf_counter() - start) * 1000
            status = getattr(response, "status_code", 0)
            level = logger.warning if status >= 400 else logger.info
            level(
                f"{request.method} {request.url.path} → {status}",
                extra={
                    "method": request.method,
                    "path": request.url.path,
                    "status_code": status,
                    "latency_ms": round(elapsed_ms, 2),
                    "trace_id": trace_id,
                },
            )
            set_trace_id(None)

        response.headers["X-Trace-ID"] = trace_id
        return response
