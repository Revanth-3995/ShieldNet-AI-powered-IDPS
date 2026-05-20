"""
ShieldNet Alert Bus — asyncio pub-sub cross-pipeline intelligence sharing.
Both Pipeline A (IDPS) and Pipeline B (Steg) publish events here.
Subscribers receive events within milliseconds.
"""
from __future__ import annotations

import asyncio
from collections import defaultdict
from datetime import datetime
from typing import Callable

from backend.core.logging import get_logger
from backend.core.config import settings

logger = get_logger("shieldnet.alertbus")


class AlertBus:
    """Lightweight asyncio pub-sub alert bus."""

    def __init__(self, maxsize: int = 1000):
        self._subscribers: dict[str, list[Callable]] = defaultdict(list)
        self._queue: asyncio.Queue = asyncio.Queue(maxsize=maxsize)
        self._running = False

    def subscribe(self, topic: str, callback: Callable):
        """Subscribe a callback to a topic."""
        self._subscribers[topic].append(callback)
        logger.debug(f"Subscribed to topic '{topic}'")

    async def publish(self, topic: str, event: dict):
        """Publish an event to all subscribers of a topic."""
        event["_topic"] = topic
        event["_published_at"] = datetime.utcnow().isoformat()
        try:
            await self._queue.put((topic, event))
            logger.debug(f"Published to '{topic}': {event}")
        except asyncio.QueueFull:
            logger.warning(f"AlertBus queue full — event dropped: {topic}")

    async def start(self):
        """Start the event dispatch loop."""
        self._running = True
        logger.info("AlertBus started")
        while self._running:
            try:
                topic, event = await asyncio.wait_for(self._queue.get(), timeout=1.0)
                for cb in self._subscribers.get(topic, []):
                    try:
                        if asyncio.iscoroutinefunction(cb):
                            await cb(event)
                        else:
                            cb(event)
                    except Exception as e:
                        logger.error(f"AlertBus callback error on topic '{topic}': {e}")
                self._queue.task_done()
            except asyncio.TimeoutError:
                continue

    def stop(self):
        self._running = False


# Global singleton
alert_bus = AlertBus(maxsize=settings.queue.ALERT_BUS_MAXSIZE)

# Topic constants
TOPIC_IDPS_DETECTION = "idps.detection"
TOPIC_STEG_DETECTION = "steg.detection"
TOPIC_IP_BLOCKED = "ip.blocked"
TOPIC_WATCH_ENDPOINT = "watch.endpoint"
TOPIC_CORRELATION = "correlation.group"
