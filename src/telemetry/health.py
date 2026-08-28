"""
SOC Lab — Telemetry Health Monitor (Phase 3)
===========================================
Tracks operational health and performance metrics for the telemetry ingestion pipeline.

Monitored metrics:
  - Ingestion status (ONLINE / DEGRADED / OFFLINE)
  - Events received, processed, rejected, duplicates, errors
  - Rolling Events Per Second (EPS) calculation
  - Queue depth (0 for single-node synchronous execution; documented scaling path)
  - Last received event timestamp
  - Adapter connection status matrix (READY vs NOT CONFIGURED)
  - Storage backend health & total telemetry event count
"""

from __future__ import annotations

import time
from collections import deque
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


class TelemetryHealthMonitor:
    """Singleton-style monitor for tracking telemetry ingestion performance."""

    _instance: Optional[TelemetryHealthMonitor] = None

    def __new__(cls) -> TelemetryHealthMonitor:
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._init_monitor()
        return cls._instance

    def _init_monitor(self):
        self.start_time = time.time()
        self.events_received = 0
        self.events_processed = 0
        self.events_rejected = 0
        self.events_deduplicated = 0
        self.processing_errors = 0
        self.last_received_timestamp: Optional[str] = None
        self.last_error_message: Optional[str] = None

        # Rolling 60s window timestamp log for EPS calculation
        self._recent_timestamps = deque(maxlen=10000)

    def record_received(self, count: int = 1):
        now = time.time()
        now_iso = datetime.now(timezone.utc).isoformat()
        self.events_received += count
        self.last_received_timestamp = now_iso
        for _ in range(count):
            self._recent_timestamps.append(now)

    def record_processed(self, count: int = 1):
        self.events_processed += count

    def record_rejected(self, count: int = 1, reason: Optional[str] = None):
        self.events_rejected += count
        if reason:
            self.last_error_message = reason

    def record_deduplicated(self, count: int = 1):
        self.events_deduplicated += count

    def record_error(self, error_msg: str):
        self.processing_errors += 1
        self.last_error_message = error_msg

    def calculate_eps(self) -> float:
        """Calculate events per second over the last 60 seconds."""
        now = time.time()
        cutoff = now - 60.0
        # Remove timestamps older than 60s
        while self._recent_timestamps and self._recent_timestamps[0] < cutoff:
            self._recent_timestamps.popleft()

        count_in_window = len(self._recent_timestamps)
        return round(count_in_window / 60.0, 2)

    def get_health_summary(self, storage_count: int = 0) -> Dict[str, Any]:
        """Return comprehensive health summary payload."""
        eps = self.calculate_eps()
        uptime_seconds = int(time.time() - self.start_time)

        # Status logic
        status = "ONLINE"
        if self.processing_errors > 50 or self.events_rejected > self.events_received * 0.5:
            status = "DEGRADED"

        from src.telemetry.normalizer import EnhancedTelemetryNormalizer
        normalizer = EnhancedTelemetryNormalizer()
        adapter_statuses = normalizer.get_adapter_statuses()

        return {
            "service": "telemetry-ingestion-engine",
            "status": status,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "uptime_seconds": uptime_seconds,
            "metrics": {
                "events_received": self.events_received,
                "events_processed": self.events_processed,
                "events_rejected": self.events_rejected,
                "events_deduplicated": self.events_deduplicated,
                "processing_errors": self.processing_errors,
                "events_per_second_rolling_60s": eps,
                "total_stored_telemetry_events": storage_count,
                "queue_depth": 0,  # Single-node synchronous execution
                "queue_capacity": 10000,
            },
            "last_activity": {
                "last_received_event": self.last_received_timestamp,
                "last_error": self.last_error_message,
            },
            "adapters": adapter_statuses,
            "architecture_mode": "Single-Node Lab (Synchronous Pipeline)",
            "scaling_path": "Production path: HTTP Ingestion -> Queue (Redis/Kafka) -> Worker Pool -> PostgreSQL + OpenSearch",
        }
