"""
SOC Lab — Normalized Event Schema (Phase 3)
==========================================
Defines the canonical NormalizedEvent Pydantic model used throughout the platform.
Every event that enters the SOC platform — regardless of source — is converted to
this model before storage, detection, or alerting.

Field naming follows a flat, vendor-neutral format inspired by ECS (Elastic Common Schema)
but does not require ECS compliance.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator, model_validator


# ---------------------------------------------------------------------------
# Valid controlled-vocabulary values
# ---------------------------------------------------------------------------

VALID_SEVERITIES = {"low", "medium", "high", "critical", "info", "unknown"}
VALID_SOURCE_TYPES = {
    "windows", "linux", "network", "network_ids", "network_flow",
    "application", "syslog", "zeek", "suricata", "wazuh", "firewall",
    "dns", "http", "generic", "simulation", "unknown"
}
VALID_ENVIRONMENTS = {"lab", "production", "staging", "test", "simulation"}
VALID_OUTCOMES = {"success", "failure", "unknown", "blocked", "allowed", "detected"}
VALID_SOURCE_MODES = {"live", "simulation"}

# Maximum raw event payload (bytes) — prevents memory exhaustion attacks
MAX_RAW_EVENT_BYTES = 524_288  # 512 KB


# ---------------------------------------------------------------------------
# Raw Ingestion Input Models
# ---------------------------------------------------------------------------

class TelemetryIngestRequest(BaseModel):
    """Single-event ingestion payload sent by a telemetry source."""
    source_type: str = Field(default="auto", description="Source type hint (windows/linux/network/generic/auto)")
    raw_event: Dict[str, Any] = Field(..., description="Original raw event, preserved verbatim")
    environment: str = Field(default="lab", description="Deployment environment label")
    sensor_id: Optional[str] = Field(default=None, description="Unique sensor/agent identifier")
    source_mode: str = Field(default="live", description="Origin of event: live | simulation")

    @field_validator("environment")
    @classmethod
    def validate_environment(cls, v: str) -> str:
        v = v.lower().strip()
        if v not in VALID_ENVIRONMENTS:
            raise ValueError(f"environment must be one of {sorted(VALID_ENVIRONMENTS)}")
        return v

    @field_validator("raw_event")
    @classmethod
    def validate_raw_event_size(cls, v: dict) -> dict:
        import json
        serialized = json.dumps(v)
        if len(serialized.encode()) > MAX_RAW_EVENT_BYTES:
            raise ValueError(f"raw_event exceeds maximum size of {MAX_RAW_EVENT_BYTES // 1024} KB")
        return v


class TelemetryBatchRequest(BaseModel):
    """Batch ingestion payload (up to MAX_BATCH_SIZE events)."""
    MAX_BATCH_SIZE: int = Field(default=500, exclude=True)

    source_type: str = Field(default="auto")
    environment: str = Field(default="lab")
    events: List[Dict[str, Any]] = Field(..., description="List of raw events")
    sensor_id: Optional[str] = Field(default=None)

    @field_validator("events")
    @classmethod
    def validate_batch_size(cls, v: list) -> list:
        if len(v) == 0:
            raise ValueError("Batch must contain at least 1 event")
        if len(v) > 500:
            raise ValueError("Batch size exceeds maximum of 500 events")
        return v

    @field_validator("environment")
    @classmethod
    def validate_environment(cls, v: str) -> str:
        v = v.lower().strip()
        if v not in VALID_ENVIRONMENTS:
            raise ValueError(f"environment must be one of {sorted(VALID_ENVIRONMENTS)}")
        return v


# ---------------------------------------------------------------------------
# Normalized Event Model
# ---------------------------------------------------------------------------

class NormalizedEvent(BaseModel):
    """
    Canonical SOC platform normalized event.

    All fields except event_id, timestamp, source_type, and environment are optional.
    Optional fields MUST remain None if unknown — do not fabricate values.

    Storage: stored in telemetry_events table as JSON + indexed columns.
    Raw event: always preserved in raw_event field verbatim.
    """
    model_config = {"extra": "ignore"}

    # --- Identity ---
    event_id: str = Field(
        default_factory=lambda: f"EVT-{uuid.uuid4().hex[:16].upper()}",
        description="Unique event identifier. Auto-generated if not provided by source."
    )
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="Event occurrence time (ISO 8601). From source if available."
    )
    ingestion_timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="Time the SOC platform received this event. Always set by platform."
    )

    # --- Source Classification ---
    source_type: str = Field(
        default="generic",
        description="Primary source classification: windows | linux | network | application | syslog | generic"
    )
    source_product: Optional[str] = Field(
        default=None,
        description="Specific product name: WinEvtLog | sysmon | auditd | nginx | palo_alto | etc."
    )
    source_sensor: Optional[str] = Field(
        default=None,
        description="Sensor/agent ID that collected this event."
    )
    environment: str = Field(
        default="lab",
        description="Deployment environment: lab | simulation | production | staging | test"
    )

    # --- Asset / Host ---
    hostname: Optional[str] = Field(default=None, description="Reporting host FQDN or short name.")
    asset_id: Optional[str] = Field(default=None, description="Asset ID from inventory (if matched).")
    fqdn: Optional[str] = Field(default=None, description="Fully qualified domain name of reporting host.")

    # --- Network ---
    source_ip: Optional[str] = Field(default=None, description="Source IP address (IPv4 or IPv6).")
    destination_ip: Optional[str] = Field(default=None, description="Destination IP address.")
    source_port: Optional[int] = Field(default=None, ge=0, le=65535, description="Source port (0–65535).")
    destination_port: Optional[int] = Field(default=None, ge=0, le=65535, description="Destination port.")
    protocol: Optional[str] = Field(default=None, description="Network protocol: tcp | udp | icmp | http | dns | etc.")
    network_direction: Optional[str] = Field(default=None, description="inbound | outbound | internal | unknown")
    bytes_sent: Optional[int] = Field(default=None, ge=0)
    bytes_received: Optional[int] = Field(default=None, ge=0)

    # --- Identity ---
    username: Optional[str] = Field(default=None, description="Subject/actor username.")
    domain: Optional[str] = Field(default=None, description="Windows domain or auth realm.")
    user_id: Optional[str] = Field(default=None, description="Unique user identifier (SID, UID, etc.).")

    # --- Process ---
    process_name: Optional[str] = Field(default=None, description="Process executable name.")
    process_id: Optional[int] = Field(default=None, ge=0, description="Process ID (PID).")
    parent_process: Optional[str] = Field(default=None, description="Parent process name.")
    parent_process_id: Optional[int] = Field(default=None, ge=0)
    command_line: Optional[str] = Field(default=None, description="Full command line arguments.")
    executable_hash: Optional[str] = Field(default=None, description="SHA256 of the process executable.")

    # --- Event Classification ---
    event_type: Optional[str] = Field(default=None, description="Normalized event type label.")
    event_code: Optional[str] = Field(default=None, description="Source-specific event code (e.g. Windows EventID).")
    severity: str = Field(default="low", description="Event severity: low | medium | high | critical | info | unknown")
    action: Optional[str] = Field(default=None, description="What action was taken: login | execute | connect | read | write | delete | etc.")
    outcome: Optional[str] = Field(default=None, description="Action outcome: success | failure | blocked | allowed | detected | unknown")
    message: Optional[str] = Field(default=None, description="Human-readable event summary.")
    risk_score: int = Field(default=0, ge=0, le=100, description="Risk score (0–100). Calculated by risk engine.")

    # --- Correlation ---
    correlation_id: Optional[str] = Field(default=None, description="Correlation ID linking related events.")
    session_id: Optional[str] = Field(default=None, description="Session or authentication session ID.")
    tags: List[str] = Field(default_factory=list, description="Analyst and system tags for filtering.")

    # --- Raw Preservation ---
    raw_event: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Original raw event preserved verbatim. Never modified after ingestion."
    )

    # --- Deduplication ---
    content_hash: Optional[str] = Field(
        default=None,
        description="SHA256 hash of key event fields for deduplication."
    )
    occurrence_count: int = Field(default=1, ge=1, description="How many times this event was seen (dedup counter).")
    first_seen: Optional[str] = Field(default=None, description="First time this event was observed (ISO 8601).")
    last_seen: Optional[str] = Field(default=None, description="Most recent observation time (ISO 8601).")

    # --- Processing flags ---
    processed: bool = Field(default=False, description="Whether this event passed through the detection pipeline.")
    simulation: bool = Field(default=False, description="True if this is simulated/lab data, not a real event.")
    source_mode: str = Field(default="live", description="Origin of event: live | simulation")

    @field_validator("source_mode")
    @classmethod
    def validate_source_mode(cls, v: str) -> str:
        v = v.lower().strip() if v else "live"
        if v not in VALID_SOURCE_MODES:
            return "live"
        return v

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v: str) -> str:
        v = v.lower().strip() if v else "unknown"
        if v not in VALID_SEVERITIES:
            return "unknown"
        return v

    @field_validator("source_type")
    @classmethod
    def validate_source_type(cls, v: str) -> str:
        v = v.lower().strip() if v else "generic"
        if v not in VALID_SOURCE_TYPES and v != "auto":
            return "generic"
        return v

    @field_validator("environment")
    @classmethod
    def validate_environment(cls, v: str) -> str:
        v = v.lower().strip() if v else "lab"
        if v not in VALID_ENVIRONMENTS:
            return "lab"
        return v

    def to_storage_dict(self) -> dict:
        """Convert to a flat dict suitable for database storage."""
        import json
        d = self.model_dump()
        d["tags"] = json.dumps(d.get("tags") or [])
        d["raw_event"] = json.dumps(d.get("raw_event") or {})
        return d

    @classmethod
    def from_storage_dict(cls, d: dict) -> "NormalizedEvent":
        """Reconstruct from a database row dict."""
        import json
        if isinstance(d.get("tags"), str):
            try:
                d["tags"] = json.loads(d["tags"])
            except Exception:
                d["tags"] = []
        if isinstance(d.get("raw_event"), str):
            try:
                d["raw_event"] = json.loads(d["raw_event"])
            except Exception:
                d["raw_event"] = {}
        return cls(**d)


# ---------------------------------------------------------------------------
# Pipeline result model
# ---------------------------------------------------------------------------

class PipelineResult(BaseModel):
    """Result returned by TelemetryPipeline.process()"""
    event_id: Optional[str] = None
    stored: bool = False
    deduplicated: bool = False
    alerts_triggered: int = 0
    validation_errors: List[str] = Field(default_factory=list)
    pipeline_errors: List[str] = Field(default_factory=list)
    status: str = "ok"  # ok | rejected | error | duplicate
