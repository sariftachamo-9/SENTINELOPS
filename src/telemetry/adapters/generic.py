"""
SOC Lab — Generic JSON Telemetry Adapter (Phase 3)
==================================================
Passthrough adapter for arbitrary JSON events that don't match a specific source.
Best-effort field extraction with no source-specific enrichment.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from src.telemetry.adapters.base import TelemetryAdapter
from src.telemetry.schema import NormalizedEvent


class GenericAdapter(TelemetryAdapter):
    """Generic JSON passthrough adapter — accepts any well-formed JSON event."""

    SOURCE_TYPE = "generic"
    DESCRIPTION = "Generic JSON event passthrough — best-effort field extraction"
    REQUIRES_CONFIGURATION = False

    def can_handle(self, raw_event: Dict[str, Any]) -> bool:
        # Generic handles everything as fallback
        return True

    def normalize(
        self,
        raw_event: Dict[str, Any],
        environment: str = "lab",
        sensor_id: Optional[str] = None,
    ) -> NormalizedEvent:
        now = self._now_iso()
        tags = ["generic"]

        # Best-effort extraction using common field name patterns
        hostname = self._safe_str(
            raw_event.get("hostname") or raw_event.get("host") or raw_event.get("computer_name")
        )
        src_ip = self._safe_ip(
            raw_event.get("source_ip") or raw_event.get("src_ip") or raw_event.get("client_ip")
        )
        dst_ip = self._safe_ip(
            raw_event.get("destination_ip") or raw_event.get("dest_ip") or raw_event.get("dst_ip")
        )
        username = self._safe_str(raw_event.get("username") or raw_event.get("user"))
        process_name = self._safe_str(raw_event.get("process_name") or raw_event.get("process"))
        event_type = self._safe_str(
            raw_event.get("event_type") or raw_event.get("action") or raw_event.get("type") or "Generic Event"
        )
        severity = self._map_severity(raw_event.get("severity")) or self._infer_severity_from_text(raw_event)
        message = self._safe_str(raw_event.get("message") or raw_event.get("msg") or raw_event.get("description"))

        if environment in ("lab", "simulation"):
            tags.append("simulation")

        return NormalizedEvent(
            timestamp=str(
                raw_event.get("timestamp")
                or raw_event.get("@timestamp")
                or raw_event.get("time")
                or now
            ),
            ingestion_timestamp=now,
            source_type=raw_event.get("source_type", "generic"),
            source_product=self._safe_str(raw_event.get("source_product") or raw_event.get("product")),
            source_sensor=sensor_id or self._safe_str(raw_event.get("sensor_id") or raw_event.get("agent_id")),
            environment=environment,
            hostname=hostname,
            source_ip=src_ip,
            destination_ip=dst_ip,
            source_port=self._safe_int(raw_event.get("source_port") or raw_event.get("src_port")),
            destination_port=self._safe_int(raw_event.get("destination_port") or raw_event.get("dest_port")),
            protocol=self._safe_str(raw_event.get("protocol") or raw_event.get("proto")),
            username=username,
            process_name=process_name,
            parent_process=self._safe_str(raw_event.get("parent_process")),
            event_type=event_type,
            severity=severity,
            action=self._safe_str(raw_event.get("action")),
            outcome=self._safe_str(raw_event.get("outcome") or raw_event.get("result")),
            message=message,
            tags=tags,
            raw_event=raw_event,
            simulation=(environment in ("lab", "simulation")),
        )
