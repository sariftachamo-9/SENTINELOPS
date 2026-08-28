"""
SOC Lab — Suricata EVE JSON Adapter (Phase 4)
==============================================
Normalizes Suricata EVE JSON alerts, DNS, HTTP, and Flow telemetry events.

Supports event_types:
  - alert (IDS signatures)
  - dns (DNS queries/responses)
  - http (HTTP transactions)
  - flow (Network flow statistics)
"""

from __future__ import annotations

from typing import Any, Dict, Optional
from src.telemetry.adapters.base import BaseAdapter
from src.telemetry.schema import NormalizedEvent


class SuricataAdapter(BaseAdapter):
    """Adapter for Suricata EVE JSON output."""

    SOURCE_TYPE = "suricata"
    DESCRIPTION = "Suricata IDS / NSM adapter"

    def __init__(self):
        super().__init__()

    def can_handle(self, raw_event: Dict[str, Any]) -> bool:
        if "event_type" in raw_event and ("alert" in raw_event or "suricata" in str(raw_event.get("engine", "")).lower()):
            return True
        if raw_event.get("source_product") == "suricata" or raw_event.get("source_type") == "suricata":
            return True
        return False

    def normalize(
        self,
        raw_event: Dict[str, Any],
        environment: str = "lab",
        sensor_id: Optional[str] = None
    ) -> NormalizedEvent:
        event_type = raw_event.get("event_type", "alert")
        src_ip = raw_event.get("src_ip") or raw_event.get("source_ip")
        dst_ip = raw_event.get("dest_ip") or raw_event.get("destination_ip")
        src_port = raw_event.get("src_port") or raw_event.get("source_port")
        dst_port = raw_event.get("dest_port") or raw_event.get("destination_port")
        proto = raw_event.get("proto") or raw_event.get("protocol") or "tcp"

        severity = "medium"
        message = f"Suricata {event_type} event"
        event_code = None
        action = "observed"
        outcome = "allowed"
        tags = ["suricata", f"suricata:{event_type}"]

        if event_type == "alert":
            alert = raw_event.get("alert") or {}
            sev_num = alert.get("severity", 3)
            # Suricata severity: 1=high, 2=medium, 3=low
            if sev_num == 1:
                severity = "high"
            elif sev_num == 2:
                severity = "medium"
            else:
                severity = "low"

            signature = alert.get("signature", "IDS Alert")
            sig_id = alert.get("signature_id")
            event_code = str(sig_id) if sig_id else "IDS-ALERT"
            message = f"Suricata IDS Alert: {signature}"
            action = alert.get("action", "alert")
            outcome = "blocked" if action == "blocked" else "detected"
            if alert.get("category"):
                tags.append(f"category:{alert['category']}")

        elif event_type == "dns":
            dns = raw_event.get("dns") or {}
            rrname = dns.get("rrname", "unknown")
            rrtype = dns.get("rrtype", "A")
            message = f"Suricata DNS Query: {rrname} ({rrtype})"
            severity = "info"
            action = "query"

        elif event_type == "http":
            http = raw_event.get("http") or {}
            hostname_http = http.get("hostname", "")
            url = http.get("url", "")
            method = http.get("http_method", "GET")
            message = f"Suricata HTTP {method}: {hostname_http}{url}"
            severity = "info"
            action = "request"

        elif event_type == "flow":
            flow = raw_event.get("flow") or {}
            bytes_sent = flow.get("bytes_toclient", 0)
            bytes_received = flow.get("bytes_toserver", 0)
            message = f"Suricata Network Flow ({proto.upper()})"
            severity = "info"
            action = "flow"

        source_mode = raw_event.get("source_mode", "live")

        return NormalizedEvent(
            source_type="suricata",
            source_product="Suricata NSM",
            source_sensor=sensor_id or raw_event.get("host"),
            environment=environment,
            hostname=raw_event.get("host") or raw_event.get("hostname"),
            source_ip=src_ip,
            destination_ip=dst_ip,
            source_port=src_port,
            destination_port=dst_port,
            protocol=proto.lower(),
            event_type=f"suricata_{event_type}",
            event_code=event_code,
            severity=severity,
            action=action,
            outcome=outcome,
            message=message,
            tags=tags,
            raw_event=raw_event,
            simulation=(source_mode == "simulation"),
            source_mode=source_mode,
        )
