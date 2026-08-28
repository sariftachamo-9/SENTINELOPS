"""
SOC Lab — Zeek NSM Adapter (Phase 4)
====================================
Normalizes Zeek Network Security Monitor logs (conn, dns, http, ssl, ssh).
"""

from __future__ import annotations

from typing import Any, Dict, Optional
from src.telemetry.adapters.base import BaseAdapter
from src.telemetry.schema import NormalizedEvent


class ZeekAdapter(BaseAdapter):
    """Adapter for Zeek JSON log output."""

    SOURCE_TYPE = "zeek"
    DESCRIPTION = "Zeek Network Security Monitor adapter"

    def __init__(self):
        super().__init__()

    def can_handle(self, raw_event: Dict[str, Any]) -> bool:
        if "_path" in raw_event or raw_event.get("source_product") == "zeek" or raw_event.get("source_type") == "zeek":
            return True
        return False

    def normalize(
        self,
        raw_event: Dict[str, Any],
        environment: str = "lab",
        sensor_id: Optional[str] = None
    ) -> NormalizedEvent:
        log_path = raw_event.get("_path") or raw_event.get("log_type") or "conn"
        src_ip = raw_event.get("id.orig_h") or raw_event.get("source_ip")
        dst_ip = raw_event.get("id.resp_h") or raw_event.get("destination_ip")
        src_port = raw_event.get("id.orig_p") or raw_event.get("source_port")
        dst_port = raw_event.get("id.resp_p") or raw_event.get("destination_port")
        proto = raw_event.get("proto") or raw_event.get("protocol") or "tcp"

        severity = "info"
        message = f"Zeek {log_path} event"
        action = "observed"
        tags = ["zeek", f"zeek:{log_path}"]

        if log_path == "conn":
            history = raw_event.get("history", "")
            orig_bytes = raw_event.get("orig_bytes") or 0
            resp_bytes = raw_event.get("resp_bytes") or 0
            message = f"Zeek Connection ({proto.upper()}) state={raw_event.get('conn_state', 'unknown')}"
            action = "connect"

        elif log_path == "dns":
            query = raw_event.get("query", "")
            qtype_name = raw_event.get("qtype_name", "A")
            message = f"Zeek DNS Query: {query} ({qtype_name})"
            action = "query"

        elif log_path == "http":
            host = raw_event.get("host", "")
            uri = raw_event.get("uri", "")
            method = raw_event.get("method", "GET")
            message = f"Zeek HTTP {method}: {host}{uri}"
            action = "request"

        elif log_path == "ssh":
            client = raw_event.get("client", "")
            auth_success = raw_event.get("auth_success")
            outcome = "success" if auth_success else "failure" if auth_success is False else "unknown"
            severity = "low" if outcome == "success" else "medium" if outcome == "failure" else "info"
            message = f"Zeek SSH Authentication ({outcome})"
            action = "authenticate"

        source_mode = raw_event.get("source_mode", "live")

        return NormalizedEvent(
            source_type="zeek",
            source_product="Zeek NSM",
            source_sensor=sensor_id or raw_event.get("node"),
            environment=environment,
            hostname=raw_event.get("host") or raw_event.get("node"),
            source_ip=src_ip,
            destination_ip=dst_ip,
            source_port=src_port,
            destination_port=dst_port,
            protocol=proto.lower(),
            event_type=f"zeek_{log_path}",
            severity=severity,
            action=action,
            message=message,
            tags=tags,
            raw_event=raw_event,
            simulation=(source_mode == "simulation"),
            source_mode=source_mode,
        )
