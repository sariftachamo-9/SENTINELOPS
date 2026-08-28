"""
SOC Lab — Syslog Telemetry Adapter (Phase 3)
============================================
Handles RFC 3164 and RFC 5424 syslog format events.
Both structured (parsed) and semi-structured (message string) input supported.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Optional

from src.telemetry.adapters.base import TelemetryAdapter
from src.telemetry.schema import NormalizedEvent

# RFC 3164 syslog header pattern
_SYSLOG_HEADER_RE = re.compile(
    r"^(?:<(?P<pri>\d{1,3})>)?\s*"
    r"(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<program>\S+?)(?:\[(?P<pid>\d+)\])?\s*:\s*(?P<message>.*)$"
)

# Priority → severity mapping (facility.severity)
_SYSLOG_SEV_MAP = {0: "critical", 1: "critical", 2: "critical", 3: "high", 4: "medium", 5: "medium", 6: "info", 7: "low"}


class SyslogAdapter(TelemetryAdapter):
    """RFC 3164/5424 syslog adapter."""

    SOURCE_TYPE = "syslog"
    DESCRIPTION = "RFC 3164/5424 syslog events (both structured and raw string)"
    REQUIRES_CONFIGURATION = False

    def can_handle(self, raw_event: Dict[str, Any]) -> bool:
        return bool(
            raw_event.get("source_type") == "syslog"
            or raw_event.get("facility")
            or raw_event.get("priority")
            or raw_event.get("syslog_severity")
            or (raw_event.get("message") and raw_event.get("program"))
        )

    def normalize(
        self,
        raw_event: Dict[str, Any],
        environment: str = "lab",
        sensor_id: Optional[str] = None,
    ) -> NormalizedEvent:
        now = self._now_iso()
        tags = ["syslog"]

        # Try to parse priority → severity
        pri = raw_event.get("priority") or raw_event.get("pri")
        severity = "low"
        if pri is not None:
            try:
                sev_index = int(pri) % 8
                severity = _SYSLOG_SEV_MAP.get(sev_index, "low")
            except (ValueError, TypeError):
                pass
        if raw_event.get("syslog_severity"):
            severity = self._map_severity(raw_event["syslog_severity"])

        program = self._safe_str(raw_event.get("program") or raw_event.get("process"))
        message = self._safe_str(raw_event.get("message") or raw_event.get("msg") or "")
        hostname = self._safe_str(raw_event.get("hostname") or raw_event.get("host"))

        event_type = f"Syslog {program}" if program else "Syslog Event"
        severity = severity or self._infer_severity_from_text(raw_event)

        if environment in ("lab", "simulation"):
            tags.append("simulation")

        return NormalizedEvent(
            timestamp=str(raw_event.get("timestamp") or raw_event.get("@timestamp") or now),
            ingestion_timestamp=now,
            source_type="syslog",
            source_product=program or "syslog",
            source_sensor=sensor_id,
            environment=environment,
            hostname=hostname,
            source_ip=self._safe_ip(raw_event.get("source_ip")),
            destination_ip=self._safe_ip(raw_event.get("destination_ip")),
            username=self._safe_str(raw_event.get("username")),
            process_name=program,
            process_id=self._safe_int(raw_event.get("pid")),
            event_type=event_type,
            severity=severity,
            message=message[:2048] if message else event_type,
            tags=tags,
            raw_event=raw_event,
            simulation=(environment in ("lab", "simulation")),
        )
