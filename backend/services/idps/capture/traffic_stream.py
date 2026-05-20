"""
ShieldNet — IDPS Traffic Stream
Manages high-throughput packet capture and async processing queues.
"""
import asyncio
import threading
from typing import Optional, Callable, Dict, Any
from backend.core.logging import get_logger
from backend.core.config import settings

logger = get_logger("shieldnet.idps.stream")

class TrafficStream:
    def __init__(self, process_callback: Callable[[Any], None]):
        self.queue: asyncio.Queue = asyncio.Queue(maxsize=10000)
        self.process_callback = process_callback
        self._stop_event = threading.Event()
        self._worker_task: Optional[asyncio.Task] = None

    async def start(self):
        """Start the async processing worker."""
        logger.info("Starting TrafficStream worker...")
        self._worker_task = asyncio.create_task(self._worker())

    async def stop(self):
        """Stop the stream and cleanup."""
        self._stop_event.set()
        if self._worker_task:
            self._worker_task.cancel()
            try:
                await self._worker_task
            except asyncio.CancelledError:
                pass
        logger.info("TrafficStream stopped.")

    async def _worker(self):
        while not self._stop_event.is_set():
            try:
                # Process in batches for better throughput if needed
                packet = await self.queue.get()
                await self.process_callback(packet)
                self.queue.task_done()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"TrafficStream worker error: {e}")

    def enqueue_packet(self, packet):
        """Thread-safe way to add a packet to the async queue from Scapy thread."""
        try:
            # We use the loop from the main thread to put into the queue
            loop = asyncio.get_event_loop()
            if loop.is_running():
                loop.call_soon_threadsafe(self.queue.put_nowait, packet)
            else:
                # Fallback for initialization
                pass
        except asyncio.QueueFull:
            logger.warning("TrafficStream queue full, dropping packet")
        except Exception as e:
            logger.error(f"Failed to enqueue packet: {e}")
