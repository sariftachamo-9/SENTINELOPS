"""
SOC Lab — Integration Health Management System (Phase 4)
========================================================
Tracks and manages health, status, reachability, metrics, and error rates for
all external integrations (Wazuh, Suricata, Zeek, Syslog, Windows, Linux).

Status Policy:
- Never report ONLINE unless a real health check / recent telemetry heartbeat confirms it.
- Default unconfigured integrations report status: NOT_CONFIGURED.
- Offline integrations report status: OFFLINE.
- Lab/Simulated integrations report status: SIMULATION.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


class IntegrationHealthManager:
    """Singleton manager tracking real-time status of all security integrations."""

    _instance: Optional[IntegrationHealthManager] = None

    def __new__(cls) -> IntegrationHealthManager:
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._init_manager()
        return cls._instance

    def _init_manager(self):
        self._integrations: Dict[str, Dict[str, Any]] = {
            "windows": {
                "integration_id": "windows",
                "name": "Windows Lab Agent / Winlogbeat",
                "type": "agent",
                "status": "NOT_CONFIGURED",
                "configured": False,
                "reachable": False,
                "authenticated": False,
                "last_event": None,
                "events_received": 0,
                "events_processed": 0,
                "events_failed": 0,
                "processing_latency_ms": 0.0,
                "error_count": 0,
                "last_error": None,
            },
            "linux": {
                "integration_id": "linux",
                "name": "Linux Lab Collector / Filebeat",
                "type": "agent",
                "status": "NOT_CONFIGURED",
                "configured": False,
                "reachable": False,
                "authenticated": False,
                "last_event": None,
                "events_received": 0,
                "events_processed": 0,
                "events_failed": 0,
                "processing_latency_ms": 0.0,
                "error_count": 0,
                "last_error": None,
            },
            "syslog": {
                "integration_id": "syslog",
                "name": "Syslog Listener (RFC3164 / RFC5424)",
                "type": "syslog",
                "status": "NOT_CONFIGURED",
                "configured": False,
                "reachable": False,
                "authenticated": True,
                "last_event": None,
                "events_received": 0,
                "events_processed": 0,
                "events_failed": 0,
                "processing_latency_ms": 0.0,
                "error_count": 0,
                "last_error": None,
            },
            "wazuh": {
                "integration_id": "wazuh",
                "name": "Wazuh Manager SIEM / EDR",
                "type": "siem",
                "status": "NOT_CONFIGURED",
                "configured": False,
                "reachable": False,
                "authenticated": False,
                "last_event": None,
                "events_received": 0,
                "events_processed": 0,
                "events_failed": 0,
                "processing_latency_ms": 0.0,
                "error_count": 0,
                "last_error": None,
            },
            "suricata": {
                "integration_id": "suricata",
                "name": "Suricata IDS / NSM",
                "type": "ids",
                "status": "NOT_CONFIGURED",
                "configured": False,
                "reachable": False,
                "authenticated": False,
                "last_event": None,
                "events_received": 0,
                "events_processed": 0,
                "events_failed": 0,
                "processing_latency_ms": 0.0,
                "error_count": 0,
                "last_error": None,
            },
            "zeek": {
                "integration_id": "zeek",
                "name": "Zeek Network Security Monitor",
                "type": "nsm",
                "status": "NOT_CONFIGURED",
                "configured": False,
                "reachable": False,
                "authenticated": False,
                "last_event": None,
                "events_received": 0,
                "events_processed": 0,
                "events_failed": 0,
                "processing_latency_ms": 0.0,
                "error_count": 0,
                "last_error": None,
            },
        }

    def register_integration(
        self,
        integration_id: str,
        name: str,
        integration_type: str,
        configured: bool = False,
        status: str = "NOT_CONFIGURED",
    ):
        if integration_id not in self._integrations:
            self._integrations[integration_id] = {
                "integration_id": integration_id,
                "name": name,
                "type": integration_type,
                "status": status,
                "configured": configured,
                "reachable": False,
                "authenticated": False,
                "last_event": None,
                "events_received": 0,
                "events_processed": 0,
                "events_failed": 0,
                "processing_latency_ms": 0.0,
                "error_count": 0,
                "last_error": None,
            }

    def update_status(
        self,
        integration_id: str,
        status: str,
        reachable: Optional[bool] = None,
        authenticated: Optional[bool] = None,
        configured: Optional[bool] = None,
    ):
        if integration_id in self._integrations:
            data = self._integrations[integration_id]
            data["status"] = status
            if configured is not None:
                data["configured"] = configured
            if reachable is not None:
                data["reachable"] = reachable
            if authenticated is not None:
                data["authenticated"] = authenticated

    def record_event_processed(
        self,
        integration_id: str,
        success: bool = True,
        latency_ms: float = 0.0,
        error_msg: Optional[str] = None,
        source_mode: str = "live",
    ):
        if integration_id in self._integrations:
            data = self._integrations[integration_id]
            now_iso = datetime.now(timezone.utc).isoformat()
            data["last_event"] = now_iso
            data["events_received"] += 1
            data["configured"] = True
            data["reachable"] = True
            data["authenticated"] = True

            if source_mode == "simulation":
                if data["status"] != "ONLINE":
                    data["status"] = "SIMULATION"
            else:
                data["status"] = "ONLINE"

            if success:
                data["events_processed"] += 1
            else:
                data["events_failed"] += 1
                data["error_count"] += 1
                if error_msg:
                    data["last_error"] = error_msg

            # Exponential moving average for latency
            current_lat = data["processing_latency_ms"]
            data["processing_latency_ms"] = round(current_lat * 0.8 + latency_ms * 0.2, 2) if current_lat > 0 else round(latency_ms, 2)

    def record_error(self, integration_id: str, error_msg: str):
        if integration_id in self._integrations:
            data = self._integrations[integration_id]
            data["error_count"] += 1
            data["last_error"] = error_msg
            if data["events_received"] == 0:
                data["status"] = "OFFLINE"

    def get_integration_health(self, integration_id: str) -> Optional[Dict[str, Any]]:
        return self._integrations.get(integration_id)

    def get_all_health(self) -> List[Dict[str, Any]]:
        return list(self._integrations.values())
