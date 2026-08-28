"""
SOC Lab — Application Telemetry Adapter (Phase 3)
=================================================
Handles application-level logs:
  - Web application errors/events
  - Database query logs
  - Custom application security events
  - API gateway logs
  - WAF events
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from src.telemetry.adapters.base import TelemetryAdapter
from src.telemetry.schema import NormalizedEvent


class ApplicationAdapter(TelemetryAdapter):
    """Application-level log adapter."""

    SOURCE_TYPE = "application"
    DESCRIPTION = "Application errors, API events, WAF, and database audit logs"
    REQUIRES_CONFIGURATION = False  # Works with any JSON app log

    def can_handle(self, raw_event: Dict[str, Any]) -> bool:
        st = str(raw_event.get("source_type", "")).lower()
        return bool(
            st == "application"
            or raw_event.get("app_name")
            or raw_event.get("service")
            or raw_event.get("http_status_code")
        )

    def normalize(
        self,
        raw_event: Dict[str, Any],
        environment: str = "lab",
        sensor_id: Optional[str] = None,
    ) -> NormalizedEvent:
        now = self._now_iso()
        tags = ["application"]

        app_name = self._safe_str(raw_event.get("app_name") or raw_event.get("service") or raw_event.get("logger"))
        level = str(raw_event.get("level", "") or raw_event.get("log_level", "")).upper()
        message = self._safe_str(raw_event.get("message") or raw_event.get("msg") or raw_event.get("event"))

        # Map log level → severity
        level_sev_map = {"CRITICAL": "critical", "ERROR": "high", "WARN": "medium", "WARNING": "medium", "INFO": "info", "DEBUG": "low"}
        severity = level_sev_map.get(level) or self._infer_severity_from_text(raw_event)

        event_type = raw_event.get("event_type") or f"Application {level}" if level else "Application Event"

        if environment in ("lab", "simulation"):
            tags.append("simulation")
        if app_name:
            tags.append(app_name[:32])

        return NormalizedEvent(
            timestamp=str(raw_event.get("timestamp") or raw_event.get("@timestamp") or now),
            ingestion_timestamp=now,
            source_type="application",
            source_product=app_name or raw_event.get("source_product"),
            source_sensor=sensor_id,
            environment=environment,
            hostname=self._safe_str(raw_event.get("hostname") or raw_event.get("host")),
            source_ip=self._safe_ip(raw_event.get("source_ip") or raw_event.get("client_ip")),
            destination_ip=self._safe_ip(raw_event.get("destination_ip")),
            source_port=self._safe_int(raw_event.get("source_port")),
            destination_port=self._safe_int(raw_event.get("destination_port")),
            username=self._safe_str(raw_event.get("username") or raw_event.get("user")),
            event_type=event_type,
            severity=severity,
            action=self._safe_str(raw_event.get("action")),
            outcome=self._safe_str(raw_event.get("outcome")),
            message=message,
            tags=tags,
            raw_event=raw_event,
            simulation=(environment in ("lab", "simulation")),
        )
