"""
SOC Lab — Wazuh Manager Adapter (Phase 4)
========================================
Normalizes raw Wazuh Manager JSON alert events into canonical NormalizedEvent instances.

Wazuh Alert Fields Mapped:
  - id -> event_code
  - timestamp -> timestamp
  - agent.name / agent.id -> hostname / source_sensor
  - agent.ip -> source_ip
  - rule.id / rule.description -> event_type / message
  - rule.level -> severity mapping
  - rule.mitre -> mitre_tactic / tags
  - data.srcip / data.dstip -> source_ip / destination_ip
  - data.srcuser / data.dstuser -> username
"""

from __future__ import annotations

from typing import Any, Dict, Optional
from src.telemetry.adapters.base import BaseAdapter
from src.telemetry.schema import NormalizedEvent


class WazuhAdapter(BaseAdapter):
    """Adapter for Wazuh Manager JSON alerts."""

    SOURCE_TYPE = "wazuh"
    DESCRIPTION = "Wazuh Manager SIEM / EDR adapter"

    def __init__(self):
        super().__init__()

    def can_handle(self, raw_event: Dict[str, Any]) -> bool:
        if "rule" in raw_event and ("agent" in raw_event or "wazuh" in str(raw_event.get("manager", "")).lower()):
            return True
        if raw_event.get("source_product") == "wazuh" or raw_event.get("source_type") == "wazuh":
            return True
        return False

    def normalize(
        self,
        raw_event: Dict[str, Any],
        environment: str = "lab",
        sensor_id: Optional[str] = None
    ) -> NormalizedEvent:
        agent = raw_event.get("agent") or {}
        rule = raw_event.get("rule") or {}
        data = raw_event.get("data") or {}

        # Rule level to severity mapping
        # Wazuh rule levels: 0-15
        rule_level = rule.get("level", 0)
        if rule_level >= 12:
            severity = "critical"
        elif rule_level >= 8:
            severity = "high"
        elif rule_level >= 5:
            severity = "medium"
        elif rule_level >= 1:
            severity = "low"
        else:
            severity = "info"

        # Hostname & IP
        hostname = agent.get("name") or data.get("system_name") or raw_event.get("hostname")
        source_ip = data.get("srcip") or agent.get("ip") or raw_event.get("source_ip")
        destination_ip = data.get("dstip") or raw_event.get("destination_ip")
        username = data.get("srcuser") or data.get("dstuser") or data.get("user") or raw_event.get("username")

        # Process & command line
        process_name = data.get("process") or data.get("exe") or raw_event.get("process_name")
        command_line = data.get("command") or raw_event.get("command_line")

        # MITRE tags
        mitre = rule.get("mitre") or {}
        tags = ["wazuh"]
        if isinstance(mitre, dict):
            for tactic in mitre.get("tactic", []):
                tags.append(f"mitre:{tactic}")
            for tech in mitre.get("id", []):
                tags.append(f"mitre:{tech}")

        event_code = str(rule.get("id", "")) or str(raw_event.get("id", ""))
        message = rule.get("description") or raw_event.get("full_log") or raw_event.get("message") or "Wazuh Alert"

        source_mode = raw_event.get("source_mode", "live")

        return NormalizedEvent(
            source_type="wazuh",
            source_product="Wazuh Manager",
            source_sensor=sensor_id or agent.get("id"),
            environment=environment,
            hostname=hostname,
            source_ip=source_ip,
            destination_ip=destination_ip,
            source_port=data.get("srcport"),
            destination_port=data.get("dstport"),
            username=username,
            process_name=process_name,
            command_line=command_line,
            event_type=f"Wazuh Rule {event_code}",
            event_code=event_code,
            severity=severity,
            action="alert",
            outcome="detected",
            message=message,
            tags=tags,
            raw_event=raw_event,
            simulation=(source_mode == "simulation"),
            source_mode=source_mode,
        )
