"""
SOC Lab — Telemetry Normalizer Router (Phase 3)
==============================================
Routes incoming raw telemetry events to the appropriate source adapter
(Windows, Linux, Network, Application, Syslog, Generic) or auto-detects.

Normalizes raw events into canonical NormalizedEvent objects without destroying
the original raw payload.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from src.telemetry.adapters.base import TelemetryAdapter
from src.telemetry.adapters.windows import WindowsAdapter
from src.telemetry.adapters.linux import LinuxAdapter
from src.telemetry.adapters.network import NetworkAdapter
from src.telemetry.adapters.application import ApplicationAdapter
from src.telemetry.adapters.syslog import SyslogAdapter
from src.telemetry.adapters.wazuh import WazuhAdapter
from src.telemetry.adapters.suricata import SuricataAdapter
from src.telemetry.adapters.zeek import ZeekAdapter
from src.telemetry.adapters.generic import GenericAdapter
from src.telemetry.schema import NormalizedEvent


class EnhancedTelemetryNormalizer:
    """
    Main normalizer router that dispatches events to concrete source adapters.
    """

    def __init__(self):
        self.windows_adapter = WindowsAdapter()
        self.linux_adapter = LinuxAdapter()
        self.network_adapter = NetworkAdapter()
        self.app_adapter = ApplicationAdapter()
        self.syslog_adapter = SyslogAdapter()
        self.wazuh_adapter = WazuhAdapter()
        self.suricata_adapter = SuricataAdapter()
        self.zeek_adapter = ZeekAdapter()
        self.generic_adapter = GenericAdapter()

        self.adapters: List[TelemetryAdapter] = [
            self.windows_adapter,
            self.linux_adapter,
            self.network_adapter,
            self.app_adapter,
            self.syslog_adapter,
            self.wazuh_adapter,
            self.suricata_adapter,
            self.zeek_adapter,
            self.generic_adapter,
        ]

    def normalize(
        self,
        raw_event: Dict[str, Any],
        source_type: str = "auto",
        environment: str = "lab",
        sensor_id: Optional[str] = None,
    ) -> NormalizedEvent:
        """
        Normalize a raw event dictionary into a canonical NormalizedEvent instance.
        """
        adapter = self._resolve_adapter(raw_event, source_type)
        return adapter.normalize(raw_event, environment=environment, sensor_id=sensor_id)

    def _resolve_adapter(self, raw_event: Dict[str, Any], source_type: str) -> TelemetryAdapter:
        st = source_type.lower().strip() if source_type else "auto"

        if st == "windows":
            return self.windows_adapter
        elif st == "linux":
            return self.linux_adapter
        elif st == "wazuh":
            return self.wazuh_adapter
        elif st == "suricata":
            return self.suricata_adapter
        elif st == "zeek":
            return self.zeek_adapter
        elif st in ("network", "network_ids", "network_flow", "firewall", "dns", "http"):
            if self.suricata_adapter.can_handle(raw_event):
                return self.suricata_adapter
            if self.zeek_adapter.can_handle(raw_event):
                return self.zeek_adapter
            return self.network_adapter
        elif st == "application":
            return self.app_adapter
        elif st == "syslog":
            return self.syslog_adapter
        elif st == "generic":
            return self.generic_adapter

        # Auto-detect mode
        if st == "auto":
            for adapter in self.adapters[:-1]:  # Exclude generic fallback in loop
                if adapter.can_handle(raw_event):
                    return adapter

        return self.generic_adapter

    def get_adapter_statuses(self) -> List[Dict[str, Any]]:
        """Return status listing for health monitoring."""
        return [
            {
                "source_type": adapter.SOURCE_TYPE,
                "description": adapter.DESCRIPTION,
                "status": adapter.status,
                "requires_configuration": adapter.REQUIRES_CONFIGURATION,
            }
            for adapter in self.adapters
        ]
