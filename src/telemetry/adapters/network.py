"""
SOC Lab — Network Telemetry Adapter (Phase 3)
============================================
Handles:
  - Firewall logs (allow/deny)
  - DNS query/response events
  - HTTP access logs
  - Network flow records (NetFlow/IPFIX style)
  - IDS alert events (generic — not Suricata/Zeek specific)

Real connection status: NOT CONFIGURED until a network sensor (Suricata/Zeek/firewall syslog)
is configured. See INTEGRATIONS.md for setup instructions.

This adapter provides CLEAN INTERFACES for future Suricata/Zeek adapters in Phase 4.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from src.telemetry.adapters.base import TelemetryAdapter
from src.telemetry.schema import NormalizedEvent


class NetworkAdapter(TelemetryAdapter):
    """Generic network telemetry adapter (firewall, DNS, HTTP, flow, IDS)."""

    SOURCE_TYPE = "network"
    DESCRIPTION = "Firewall, DNS, HTTP, network flow, and generic IDS events"
    REQUIRES_CONFIGURATION = True

    def can_handle(self, raw_event: Dict[str, Any]) -> bool:
        et = str(raw_event.get("event_type", "")).lower()
        st = str(raw_event.get("source_type", "")).lower()
        return bool(
            et in ("alert", "dns", "http", "flow", "conn", "files", "ssl", "tls", "dhcp")
            or st in ("network", "network_ids", "network_flow", "firewall", "dns", "http", "zeek", "suricata")
            or raw_event.get("id.orig_h")   # Zeek-style field
            or raw_event.get("proto")
        )

    def normalize(
        self,
        raw_event: Dict[str, Any],
        environment: str = "lab",
        sensor_id: Optional[str] = None,
    ) -> NormalizedEvent:
        now = self._now_iso()

        event_subtype = str(raw_event.get("event_type", "")).lower()
        tags = ["network"]
        event_type = "Network Event"
        severity = "low"
        action = None
        outcome = None
        message = None

        # --- Firewall / Access Control ---
        if event_subtype in ("firewall", "access", "acl") or raw_event.get("action") in ("allow", "deny", "drop", "reject", "block"):
            tags.append("firewall")
            act = str(raw_event.get("action", "")).lower()
            action = act
            outcome = "allowed" if act == "allow" else "blocked"
            event_type = f"Firewall {act.capitalize()}"
            severity = "low" if act == "allow" else "medium"

        # --- DNS ---
        elif event_subtype == "dns" or raw_event.get("query") or raw_event.get("dns_query"):
            tags.append("dns")
            event_type = "DNS Query"
            action = "query"
            query = raw_event.get("query") or raw_event.get("dns_query") or ""
            answers = raw_event.get("answers") or raw_event.get("dns_answers") or []
            message = f"DNS Query: {query}"
            if answers:
                message += f" -> {', '.join(str(a) for a in answers[:3])}"
            severity = "low"
            # Heuristic: long subdomain = potential DGA/tunneling
            if query and len(query) > 60:
                severity = "medium"
                tags.append("possible_dga")

        # --- HTTP ---
        elif event_subtype in ("http", "web") or raw_event.get("http_method") or raw_event.get("url"):
            tags.append("http")
            method = raw_event.get("http_method") or raw_event.get("method", "")
            url = raw_event.get("url") or raw_event.get("uri", "")
            status = raw_event.get("http_status_code") or raw_event.get("status_code") or ""
            event_type = f"HTTP {method}".strip()
            action = method.lower() if method else "request"
            outcome = "success" if str(status).startswith("2") else ("failure" if str(status).startswith(("4", "5")) else "unknown")
            severity = "high" if str(status) in ("401", "403", "404", "500") else "low"
            message = f"{method} {url} -> {status}"

        # --- IDS Alert (generic) ---
        elif event_subtype == "alert" or raw_event.get("alert"):
            tags.append("ids")
            alert_obj = raw_event.get("alert", {})
            if isinstance(alert_obj, dict):
                sig = alert_obj.get("signature", "IDS Alert")
                sev_num = alert_obj.get("severity", 3)
                event_type = sig
                severity = self._map_severity(sev_num)
                message = f"IDS Alert: {sig}"
                action = "detect"
                outcome = "detected"
            else:
                event_type = "IDS Alert"

        # --- Network Flow ---
        elif event_subtype in ("flow", "conn") or raw_event.get("id.orig_h"):
            tags.append("flow")
            event_type = "Network Flow"
            action = "connect"
            proto = raw_event.get("proto") or raw_event.get("protocol", "")
            dst_port = self._safe_int(raw_event.get("id.resp_p") or raw_event.get("destination_port"))
            message = f"Flow {proto} -> port {dst_port}"

        severity = severity or self._infer_severity_from_text(raw_event)

        if environment in ("lab", "simulation"):
            tags.append("simulation")

        # Source/dest IP - support Zeek id.orig_h / id.resp_h notation
        src_ip = self._safe_ip(
            raw_event.get("source_ip")
            or raw_event.get("src_ip")
            or raw_event.get("id.orig_h")
        )
        dst_ip = self._safe_ip(
            raw_event.get("destination_ip")
            or raw_event.get("dest_ip")
            or raw_event.get("dst_ip")
            or raw_event.get("id.resp_h")
        )
        src_port = self._safe_int(
            raw_event.get("source_port")
            or raw_event.get("src_port")
            or raw_event.get("id.orig_p")
        )
        dst_port = self._safe_int(
            raw_event.get("destination_port")
            or raw_event.get("dest_port")
            or raw_event.get("dst_port")
            or raw_event.get("id.resp_p")
        )

        return NormalizedEvent(
            timestamp=str(
                raw_event.get("timestamp")
                or raw_event.get("@timestamp")
                or raw_event.get("ts")
                or now
            ),
            ingestion_timestamp=now,
            source_type=raw_event.get("source_type", "network"),
            source_product=raw_event.get("source_product", "network_sensor"),
            source_sensor=sensor_id or raw_event.get("sensor_id"),
            environment=environment,
            hostname=self._safe_str(raw_event.get("hostname") or raw_event.get("host")),
            source_ip=src_ip,
            destination_ip=dst_ip,
            source_port=src_port,
            destination_port=dst_port,
            protocol=self._safe_str(raw_event.get("protocol") or raw_event.get("proto")),
            bytes_sent=self._safe_int(raw_event.get("bytes_sent") or raw_event.get("orig_bytes")),
            bytes_received=self._safe_int(raw_event.get("bytes_received") or raw_event.get("resp_bytes")),
            username=self._safe_str(raw_event.get("username")),
            event_type=event_type,
            severity=severity,
            action=action,
            outcome=outcome,
            message=message or event_type,
            tags=tags,
            raw_event=raw_event,
            simulation=(environment in ("lab", "simulation")),
        )
