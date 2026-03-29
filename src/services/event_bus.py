# src/services/event_bus.py

"""
Event Bus — pub/sub for real-time scan events.
Execution controller publishes events → WebSocket clients receive them.
"""

from typing import Dict, List, Set, Any
from datetime import datetime
import asyncio
import json

from src.utils.logging import logger


class ScanEvent:
    """A single scan event."""
    __slots__ = ('type', 'process_id', 'data', 'timestamp')

    def __init__(self, type: str, process_id: str, data: dict = None):
        self.type = type
        self.process_id = process_id
        self.data = data or {}
        self.timestamp = datetime.utcnow().isoformat()

    def to_json(self) -> str:
        return json.dumps({
            "type": self.type,
            "process_id": self.process_id,
            "data": self.data,
            "timestamp": self.timestamp
        })


class EventBus:
    """In-memory event bus with per-scan subscribers."""

    def __init__(self):
        # process_id → set of asyncio.Queue (one per WebSocket client)
        self._subscribers: Dict[str, Set[asyncio.Queue]] = {}
        # process_id → last N events (for replay on connect)
        self._history: Dict[str, List[ScanEvent]] = {}
        self._max_history = 200

    def subscribe(self, process_id: str) -> asyncio.Queue:
        """Subscribe to events for a scan. Returns a queue to await on."""
        q: asyncio.Queue = asyncio.Queue(maxsize=100)
        self._subscribers.setdefault(process_id, set()).add(q)
        return q

    def unsubscribe(self, process_id: str, q: asyncio.Queue):
        """Remove a subscriber."""
        subs = self._subscribers.get(process_id)
        if subs:
            subs.discard(q)
            if not subs:
                del self._subscribers[process_id]

    async def publish(self, event: ScanEvent):
        """Publish an event to all subscribers of that scan."""
        pid = event.process_id

        # Store in history
        self._history.setdefault(pid, []).append(event)
        if len(self._history[pid]) > self._max_history:
            self._history[pid] = self._history[pid][-self._max_history:]

        # Fan out to subscribers
        for q in list(self._subscribers.get(pid, [])):
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                pass  # Drop oldest if client is slow

    async def emit(self, type: str, process_id: str, **data):
        """Convenience: create + publish in one call."""
        await self.publish(ScanEvent(type, process_id, data))

    def get_history(self, process_id: str, since: int = 0) -> List[ScanEvent]:
        """Get event history (for replay on connect). since = index offset."""
        events = self._history.get(process_id, [])
        return events[since:]

    def cleanup(self, process_id: str):
        """Clean up after scan completes (keep history, remove subs)."""
        self._subscribers.pop(process_id, None)


# Singleton
event_bus = EventBus()
