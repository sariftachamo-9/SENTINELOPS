"""
SOC Lab — Telemetry Adapter Base Class (Phase 3)
================================================
Abstract base class for all telemetry source adapters.

Architecture:
    TelemetryAdapter (base)
         │
    ┌────┼────┬────┬──────┬──────┐
    ▼    ▼    ▼    ▼      ▼      ▼
  Win  Linux Net  App  Syslog Generic

Each adapter is responsible for:
  1. Detecting if a raw event belongs to its source type
  2. Extracting and mapping fields to NormalizedEvent fields
  3. Never failing silently — returning a partial event is OK, raising is not

Adapters MUST NOT:
  - Modify the raw_event payload
  - Make network calls
  - Block execution (no I/O)
  - Raise unhandled exceptions (use try/except and defaults)
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from src.telemetry.schema import NormalizedEvent


class TelemetryAdapter(ABC):
    """
    Abstract base class for all telemetry source adapters.
    Subclasses implement normalize() for their specific source type.
    """

    #: Override in subclass. Used for display and routing.
    SOURCE_TYPE: str = "generic"

    #: Human-readable description for documentation/health endpoint.
    DESCRIPTION: str = "Generic telemetry adapter"

    #: Whether this adapter requires real configuration (external service).
    REQUIRES_CONFIGURATION: bool = False

    def __init__(self):
        self._is_configured = not self.REQUIRES_CONFIGURATION

    @property
    def status(self) -> str:
        """Returns adapter status for health reporting."""
        if not self.REQUIRES_CONFIGURATION:
            return "READY"
        return "CONFIGURED" if self._is_configured else "NOT CONFIGURED"

    @abstractmethod
    def can_handle(self, raw_event: Dict[str, Any]) -> bool:
        """
        Returns True if this adapter can handle the given raw event.
        Used for auto-detection when source_type='auto'.
        """

    @abstractmethod
    def normalize(
        self,
        raw_event: Dict[str, Any],
        environment: str = "lab",
        sensor_id: Optional[str] = None,
    ) -> NormalizedEvent:
        """
        Convert raw_event to a NormalizedEvent.
        Must always return a NormalizedEvent (never raise).
        Set raw_event field verbatim — never modify the original.
        """

    # -----------------------------------------------------------------------
    # Shared helpers available to all adapters
    # -----------------------------------------------------------------------

    @staticmethod
    def _safe_str(value: Any, max_len: int = 256) -> Optional[str]:
        """Convert to string safely, returning None for falsy values."""
        if value is None or value == "":
            return None
        return str(value)[:max_len]

    @staticmethod
    def _safe_int(value: Any) -> Optional[int]:
        """Convert to int safely."""
        try:
            return int(value)
        except (ValueError, TypeError):
            return None

    @staticmethod
    def _safe_ip(value: Any) -> Optional[str]:
        """Return IP only if non-trivial."""
        import ipaddress
        if value is None:
            return None
        s = str(value).strip()
        if s in ("0.0.0.0", "::", "", "unknown", "N/A"):
            return None
        try:
            ipaddress.ip_address(s)
            return s
        except ValueError:
            return None

    @staticmethod
    def _now_iso() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _map_severity(raw: Any) -> str:
        """Map numeric or string severity to normalized levels."""
        from src.telemetry.schema import VALID_SEVERITIES
        if raw is None:
            return "low"
        s = str(raw).lower().strip()
        # Numeric (1=critical, 2=high, 3=medium, 4=low)
        numeric_map = {"1": "critical", "2": "high", "3": "medium", "4": "low", "5": "info"}
        if s in numeric_map:
            return numeric_map[s]
        if s in VALID_SEVERITIES:
            return s
        return "unknown"

    @staticmethod
    def _infer_severity_from_text(raw_event: Dict[str, Any]) -> str:
        """Heuristic severity from event content when no explicit severity is given."""
        text = str(raw_event).lower()
        if any(k in text for k in ("critical", "malware", "ransomware", "exploit", "rootkit")):
            return "critical"
        if any(k in text for k in ("failed", "denied", "unauthorized", "intrusion", "attack", "scan")):
            return "high"
        if any(k in text for k in ("warning", "sudo", "privilege", "escalation", "modified")):
            return "medium"
        if any(k in text for k in ("info", "notice", "accepted", "success")):
            return "info"
        return "low"


# Alias for backwards compatibility with vendor adapters
BaseAdapter = TelemetryAdapter
