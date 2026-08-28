"""
SOC Lab — Telemetry Search Backend Abstraction (Phase 4)
=========================================================
Abstract interface and implementations for telemetry search backends.

Allows seamless switching between SQLite (local development/lab)
and OpenSearch / Elasticsearch (production scaling).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Tuple

from src.telemetry.schema import NormalizedEvent
from src.telemetry.storage import SQLiteEventStore, StorageBackend


class EventSearchBackend(ABC):
    """Abstract search backend protocol."""

    @abstractmethod
    def search_events(
        self,
        filters: Dict[str, Any],
        limit: int = 50,
        offset: int = 0
    ) -> Tuple[List[NormalizedEvent], int]:
        """Search telemetry events matching filters."""

    @abstractmethod
    def get_event_by_id(self, event_id: str) -> Optional[NormalizedEvent]:
        """Fetch single event by ID."""

    @abstractmethod
    def get_timeline(
        self,
        entity_type: str,
        entity_value: str,
        limit: int = 100
    ) -> List[NormalizedEvent]:
        """Fetch chronological timeline for entity."""


class SQLiteSearchBackend(EventSearchBackend):
    """SQLite implementation wrapping SQLiteEventStore."""

    def __init__(self, store: Optional[StorageBackend] = None):
        self.store = store or SQLiteEventStore()

    def search_events(
        self,
        filters: Dict[str, Any],
        limit: int = 50,
        offset: int = 0
    ) -> Tuple[List[NormalizedEvent], int]:
        return self.store.query_events(filters, limit=limit, offset=offset)

    def get_event_by_id(self, event_id: str) -> Optional[NormalizedEvent]:
        return self.store.get_event_by_id(event_id)

    def get_timeline(
        self,
        entity_type: str,
        entity_value: str,
        limit: int = 100
    ) -> List[NormalizedEvent]:
        return self.store.get_timeline(entity_type, entity_value, limit=limit)


class OpenSearchBackend(EventSearchBackend):
    """
    OpenSearch / Elasticsearch backend adapter for high-scale enterprise deployment.
    Communicates via OpenSearch REST API when configured.

    NOTE: SQLiteSearchBackend is the current operational lab backend.
    OpenSearchBackend is a future production/scaling adapter. Fallback is logged explicitly.
    """

    def __init__(self, endpoint: str = "http://localhost:9200", index_prefix: str = "soc-telemetry"):
        self.endpoint = endpoint
        self.index_prefix = index_prefix
        self.connected = False
        self.fallback_active = True
        self.fallback_warning = (
            "[OpenSearchBackend] NOTICE: OpenSearch cluster not configured; "
            "explicitly using SQLiteSearchBackend (Operational Lab Backend)."
        )

    def search_events(
        self,
        filters: Dict[str, Any],
        limit: int = 50,
        offset: int = 0
    ) -> Tuple[List[NormalizedEvent], int]:
        import logging
        logging.warning(self.fallback_warning)
        fallback = SQLiteSearchBackend()
        return fallback.search_events(filters, limit=limit, offset=offset)

    def get_event_by_id(self, event_id: str) -> Optional[NormalizedEvent]:
        import logging
        logging.warning(self.fallback_warning)
        fallback = SQLiteSearchBackend()
        return fallback.get_event_by_id(event_id)

    def get_timeline(
        self,
        entity_type: str,
        entity_value: str,
        limit: int = 100
    ) -> List[NormalizedEvent]:
        import logging
        logging.warning(self.fallback_warning)
        fallback = SQLiteSearchBackend()
        return fallback.get_timeline(entity_type, entity_value, limit=limit)

