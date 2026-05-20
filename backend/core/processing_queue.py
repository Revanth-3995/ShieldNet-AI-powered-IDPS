"""
ShieldNet — Processing Queue & Worker Pool
Producer-consumer pipeline for CPU-bound detection tasks.
Keeps FastAPI event loop unblocked by offloading heavy work to a thread pool.

Architecture:
  FastAPI handler → enqueue_task() → asyncio.Queue → worker_loop()
                                                      ↓
                                              ThreadPoolExecutor (CPU work)
                                                      ↓
                                              result callback → alert_bus
"""
from __future__ import annotations

import asyncio
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Callable, Optional
from uuid import uuid4

from backend.core.logging import get_logger
from backend.core.config import settings

logger = get_logger("shieldnet.queue")


# ---------------------------------------------------------------------------
# Task envelope
# ---------------------------------------------------------------------------
@dataclass
class Task:
    task_id: str = field(default_factory=lambda: str(uuid4())[:8])
    task_type: str = ""           # e.g. "steg_analysis", "idps_flow"
    payload: dict = field(default_factory=dict)
    created_at: float = field(default_factory=time.monotonic)
    priority: int = 0             # reserved for priority-queue upgrade

    def age_ms(self) -> float:
        return (time.monotonic() - self.created_at) * 1000


@dataclass
class TaskResult:
    task_id: str
    task_type: str
    success: bool
    result: Any = None
    error: Optional[str] = None
    elapsed_ms: float = 0.0


# ---------------------------------------------------------------------------
# Processing queue
# ---------------------------------------------------------------------------
class ProcessingQueue:
    """
    Async task queue backed by a thread pool for CPU-bound work.
    Each task_type maps to a registered handler function.
    Results are delivered to an optional callback.
    """

    def __init__(
        self,
        maxsize: int = 500,
        thread_pool_size: int = 4,
    ):
        self._queue: asyncio.Queue[Task] = asyncio.Queue(maxsize=maxsize)
        self._executor = ThreadPoolExecutor(
            max_workers=thread_pool_size,
            thread_name_prefix="shieldnet-worker",
        )
        self._handlers: dict[str, Callable] = {}
        self._result_cb: Optional[Callable] = None
        self._running = False

        # Metrics
        self._total_enqueued = 0
        self._total_processed = 0
        self._total_failed = 0
        self._total_dropped = 0

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------
    def register_handler(self, task_type: str, handler: Callable) -> None:
        """Register a sync handler for a task type."""
        self._handlers[task_type] = handler
        logger.debug(f"Registered handler for task type '{task_type}'")

    def set_result_callback(self, cb: Callable) -> None:
        """Optional async callback invoked with each TaskResult."""
        self._result_cb = cb

    # ------------------------------------------------------------------
    # Producer API
    # ------------------------------------------------------------------
    async def enqueue(self, task: Task) -> bool:
        """Non-blocking enqueue. Returns False if queue is full."""
        try:
            self._queue.put_nowait(task)
            self._total_enqueued += 1
            logger.debug(
                f"Task enqueued",
                extra={"task_id": task.task_id, "task_type": task.task_type},
            )
            return True
        except asyncio.QueueFull:
            self._total_dropped += 1
            logger.warning(
                f"Processing queue full — task dropped",
                extra={"task_type": task.task_type, "queue_size": self._queue.qsize()},
            )
            return False

    # ------------------------------------------------------------------
    # Consumer loop
    # ------------------------------------------------------------------
    async def start(self) -> None:
        self._running = True
        logger.info(
            f"ProcessingQueue started",
            extra={"thread_pool_size": self._executor._max_workers},
        )
        while self._running:
            try:
                task = await asyncio.wait_for(self._queue.get(), timeout=1.0)
                asyncio.create_task(self._process(task))
                self._queue.task_done()
            except asyncio.TimeoutError:
                continue
            except Exception as exc:
                logger.error(f"Processing queue loop error: {exc}")

        logger.info("ProcessingQueue stopped")

    async def _process(self, task: Task) -> None:
        handler = self._handlers.get(task.task_type)
        if not handler:
            logger.warning(f"No handler for task type '{task.task_type}'")
            return

        t0 = time.perf_counter()
        try:
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                self._executor, lambda: handler(task.payload)
            )
            elapsed = (time.perf_counter() - t0) * 1000
            self._total_processed += 1
            task_result = TaskResult(
                task_id=task.task_id,
                task_type=task.task_type,
                success=True,
                result=result,
                elapsed_ms=round(elapsed, 2),
            )
            logger.debug(
                f"Task completed",
                extra={
                    "task_id": task.task_id,
                    "task_type": task.task_type,
                    "elapsed_ms": task_result.elapsed_ms,
                },
            )
        except Exception as exc:
            elapsed = (time.perf_counter() - t0) * 1000
            self._total_failed += 1
            task_result = TaskResult(
                task_id=task.task_id,
                task_type=task.task_type,
                success=False,
                error=str(exc),
                elapsed_ms=round(elapsed, 2),
            )
            logger.error(
                f"Task failed",
                extra={
                    "task_id": task.task_id,
                    "task_type": task.task_type,
                    "error": str(exc),
                },
            )

        if self._result_cb:
            try:
                if asyncio.iscoroutinefunction(self._result_cb):
                    await self._result_cb(task_result)
                else:
                    self._result_cb(task_result)
            except Exception as exc:
                logger.error(f"Result callback error: {exc}")

    def stop(self) -> None:
        self._running = False
        self._executor.shutdown(wait=False)

    def metrics(self) -> dict:
        return {
            "queue_size": self._queue.qsize(),
            "enqueued": self._total_enqueued,
            "processed": self._total_processed,
            "failed": self._total_failed,
            "dropped": self._total_dropped,
        }


# ---------------------------------------------------------------------------
# Global singleton
# ---------------------------------------------------------------------------
processing_queue = ProcessingQueue(
    maxsize=settings.queue.DETECTION_QUEUE_MAXSIZE,
    thread_pool_size=settings.queue.PROCESSING_THREAD_POOL_SIZE,
)
