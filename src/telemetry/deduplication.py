"""
SOC Lab — Event Deduplication Service (Phase 3)
==============================================
Provides safe event deduplication logic.

Deduplication Strategy:
  - Generates a content_hash (SHA256) based on core tuple:
      (source_ip, destination_ip, event_type, username, process_name, hostname, source_type)
  - Maintains an in-memory cache / DB lookup for recent events within `window_seconds` (default 60s).
  - If a duplicate event occurs within the window:
      * Preserves the original event entry or updates occurrence metadata (occurrence_count, last_seen).
      * Flags the event as a duplicate so the detection engine can handle or skip duplicate alerts as appropriate.
      * Does NOT silently destroy data; original raw events and occurrence counts are preserved.
"""

from __future__ import annotations

import hashlib
import time
from datetime import datetime, timezone
from typing import Dict, Optional, Tuple

from src.telemetry.schema import NormalizedEvent


class EventDeduplicator:
    """
    Event deduplication engine using sliding-window content hashing.
    """

    def __init__(self, window_seconds: int = 60):
        self.window_seconds = window_seconds
        # Memory cache: content_hash -> (first_seen_ts, last_seen_ts, count, event_id)
        self._cache: Dict[str, Tuple[float, float, int, str]] = {}

    @staticmethod
    def compute_hash(event: NormalizedEvent) -> str:
        """
        Compute SHA256 content hash for an event.
        """
        fields = [
            str(event.source_type or ""),
            str(event.event_type or ""),
            str(event.hostname or ""),
            str(event.source_ip or ""),
            str(event.destination_ip or ""),
            str(event.username or ""),
            str(event.process_name or ""),
            str(event.event_code or ""),
        ]
        raw_key = "|".join(fields).lower()
        return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()

    def process(self, event: NormalizedEvent) -> Tuple[NormalizedEvent, bool]:
        """
        Process an event for deduplication.

        Returns:
            (updated_event, is_duplicate)
        """
        now_epoch = time.time()
        now_iso = datetime.now(timezone.utc).isoformat()

        content_hash = self.compute_hash(event)
        event.content_hash = content_hash

        # Purge stale entries from in-memory cache
        self._cleanup(now_epoch)

        if content_hash in self._cache:
            first_seen_ts, _, count, orig_event_id = self._cache[content_hash]
            if (now_epoch - first_seen_ts) <= self.window_seconds:
                new_count = count + 1
                self._cache[content_hash] = (first_seen_ts, now_epoch, new_count, orig_event_id)

                event.occurrence_count = new_count
                event.first_seen = datetime.fromtimestamp(first_seen_ts, timezone.utc).isoformat()
                event.last_seen = now_iso
                return event, True

        # New event or outside window
        self._cache[content_hash] = (now_epoch, now_epoch, 1, event.event_id)
        event.occurrence_count = 1
        event.first_seen = event.timestamp or now_iso
        event.last_seen = now_iso
        return event, False

    def _cleanup(self, now_epoch: float):
        """Purge cache entries older than window_seconds."""
        cutoff = now_epoch - (self.window_seconds * 2)
        stale_keys = [k for k, v in self._cache.items() if v[1] < cutoff]
        for k in stale_keys:
            del self._cache[k]
