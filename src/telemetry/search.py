"""
SOC Lab — Event Search & Timeline Service (Phase 3)
==================================================
Provides secure, parameterized event search and timeline capabilities for analysts.

Safety:
  - All input fields are strictly parameterized; arbitrary user SQL string concatenation is impossible.
  - Limits are capped (default max 1,000 per page).
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from src.telemetry.schema import NormalizedEvent
from src.telemetry.storage import StorageBackend, SQLiteEventStore


class SearchFilter(BaseModel):
    """Filter parameters for searching security telemetry."""
    time_from: Optional[str] = Field(None, description="Start timestamp ISO 8601")
    time_to: Optional[str] = Field(None, description="End timestamp ISO 8601")
    source_type: Optional[str] = Field(None, description="windows | linux | network | application | syslog | generic")
    hostname: Optional[str] = Field(None, description="Host / computer name")
    source_ip: Optional[str] = Field(None, description="Source IPv4/IPv6")
    destination_ip: Optional[str] = Field(None, description="Destination IPv4/IPv6")
    username: Optional[str] = Field(None, description="User / account name")
    event_type: Optional[str] = Field(None, description="Event classification")
    severity: Optional[str] = Field(None, description="low | medium | high | critical | info")
    process_name: Optional[str] = Field(None, description="Process image name")
    asset_id: Optional[str] = Field(None, description="Asset ID")
    environment: Optional[str] = Field(None, description="lab | production | simulation")
    search_query: Optional[str] = Field(None, description="Free text search query (safe parameterized substring match)")
    simulation: Optional[bool] = Field(None, description="Filter for simulation mode events")
    source_mode: Optional[str] = Field(None, description="Filter by source mode: live | simulation | all")
    limit: int = Field(50, ge=1, le=1000)
    offset: int = Field(0, ge=0)


class SearchResponse(BaseModel):
    """Paginated search response."""
    total: int
    count: int
    limit: int
    offset: int
    events: List[NormalizedEvent]


class TimelineResponse(BaseModel):
    """Chronological timeline response."""
    entity_type: str
    entity_value: str
    count: int
    events: List[NormalizedEvent]


class EventSearchService:
    """Service handling parameterized search and timeline queries."""

    def __init__(self, search_backend: Optional[Any] = None, storage: Optional[StorageBackend] = None):
        from src.telemetry.search_backend import SQLiteSearchBackend
        if search_backend:
            self.backend = search_backend
        else:
            self.backend = SQLiteSearchBackend(store=storage)

    def search(self, filter_params: SearchFilter) -> SearchResponse:
        filters_dict = filter_params.model_dump(exclude={"limit", "offset"}, exclude_none=True)
        if filters_dict.get("source_mode") == "all":
            filters_dict.pop("source_mode", None)
        events, total = self.backend.search_events(
            filters=filters_dict,
            limit=filter_params.limit,
            offset=filter_params.offset
        )
        return SearchResponse(
            total=total,
            count=len(events),
            limit=filter_params.limit,
            offset=filter_params.offset,
            events=events
        )

    def get_timeline(self, entity_type: str, entity_value: str, limit: int = 100) -> TimelineResponse:
        events = self.backend.get_timeline(entity_type, entity_value, limit=min(limit, 500))
        return TimelineResponse(
            entity_type=entity_type,
            entity_value=entity_value,
            count=len(events),
            events=events
        )

    def get_event_details(self, event_id: str) -> Optional[NormalizedEvent]:
        return self.backend.get_event_by_id(event_id)
