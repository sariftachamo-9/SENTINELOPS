"""
SOC Lab — Telemetry Validation Layer (Phase 3)
=============================================
Validates raw incoming telemetry payloads BEFORE normalization.
Malformed events are rejected safely without crashing the ingestion service.

Validation rules:
  - Payload size limit
  - IP address format (IPv4/IPv6)
  - Port range (0-65535)
  - Timestamp parsability (if present)
  - Severity value in allowlist (if present)
  - Username/hostname pattern safety (no injection characters)
  - Protocol name safety
"""

from __future__ import annotations

import ipaddress
import json
import re
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, field

from src.telemetry.schema import VALID_SEVERITIES, VALID_SOURCE_TYPES, MAX_RAW_EVENT_BYTES


# ---------------------------------------------------------------------------
# Safe pattern rules
# ---------------------------------------------------------------------------

# Allow alphanumeric, dot, dash, underscore, @, space
_SAFE_STRING_RE = re.compile(r'^[\w.\-@\s]{0,256}$')

# Protocol allowlist
VALID_PROTOCOLS = {
    "tcp", "udp", "icmp", "icmpv6", "http", "https", "dns", "ftp", "smtp",
    "ssh", "smb", "rdp", "telnet", "snmp", "ldap", "kerberos", "ntlm",
    "tls", "ssl", "ipv4", "ipv6", "arp", "sctp", "gre", "esp", "ah", "unknown"
}


# ---------------------------------------------------------------------------
# Validation Result
# ---------------------------------------------------------------------------

@dataclass
class ValidationResult:
    ok: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    sanitized: Optional[Dict[str, Any]] = None

    def add_error(self, msg: str):
        self.errors.append(msg)
        self.ok = False

    def add_warning(self, msg: str):
        self.warnings.append(msg)


# ---------------------------------------------------------------------------
# Core Validator
# ---------------------------------------------------------------------------

class TelemetryValidator:
    """
    Validates raw telemetry payloads.

    Usage:
        validator = TelemetryValidator()
        result = validator.validate(raw_event, source_type="windows")
        if result.ok:
            proceed_to_normalization(result.sanitized)
        else:
            reject_with_errors(result.errors)
    """

    def validate(
        self,
        raw_event: Any,
        source_type: str = "generic",
        environment: str = "lab"
    ) -> ValidationResult:
        result = ValidationResult(ok=True)

        # 1. Type check — must be dict (or parsable to dict)
        if not isinstance(raw_event, dict):
            if isinstance(raw_event, (str, bytes)):
                try:
                    raw_event = json.loads(raw_event)
                except (json.JSONDecodeError, ValueError):
                    result.add_error("raw_event is not valid JSON and cannot be parsed")
                    return result
            else:
                result.add_error(f"raw_event must be a dict or JSON string, got {type(raw_event).__name__}")
                return result

        # 2. Payload size
        try:
            serialized_size = len(json.dumps(raw_event).encode("utf-8"))
            if serialized_size > MAX_RAW_EVENT_BYTES:
                result.add_error(
                    f"Payload too large: {serialized_size} bytes exceeds limit of {MAX_RAW_EVENT_BYTES} bytes"
                )
                return result  # hard stop — do not process oversized payloads
        except (TypeError, ValueError) as e:
            result.add_error(f"Payload serialization failed: {e}")
            return result

        # 3. Source type validation (warning only — normalizer handles auto-detect)
        if source_type and source_type not in ("auto", "") and source_type not in VALID_SOURCE_TYPES:
            result.add_warning(f"Unknown source_type '{source_type}' — will be treated as 'generic'")

        # 4. Timestamp (if present)
        ts_value = (
            raw_event.get("timestamp")
            or raw_event.get("@timestamp")
            or raw_event.get("time")
            or raw_event.get("TimeCreated")
        )
        if ts_value is not None:
            self._validate_timestamp(str(ts_value), result)

        # 5. IP addresses (if present)
        for ip_field in ("source_ip", "src_ip", "id.orig_h", "destination_ip", "dest_ip", "dst_ip", "id.resp_h"):
            ip_val = raw_event.get(ip_field)
            if ip_val and ip_val not in ("0.0.0.0", "::", "", "unknown"):
                self._validate_ip(ip_val, ip_field, result)

        # 6. Ports (if present)
        for port_field in ("source_port", "src_port", "id.orig_p", "destination_port", "dest_port", "dst_port", "id.resp_p"):
            port_val = raw_event.get(port_field)
            if port_val is not None:
                self._validate_port(port_val, port_field, result)

        # 7. Protocol (if present)
        proto = raw_event.get("protocol") or raw_event.get("proto")
        if proto:
            self._validate_protocol(str(proto), result)

        # 8. Severity (if present)
        severity = raw_event.get("severity")
        if severity:
            self._validate_severity(str(severity), result)

        # 9. Username safety (if present)
        username = raw_event.get("username") or raw_event.get("user") or raw_event.get("TargetUserName")
        if username:
            self._validate_safe_string(str(username), "username", result)

        # 10. Hostname safety (if present)
        hostname = raw_event.get("hostname") or raw_event.get("host") or raw_event.get("computer_name")
        if hostname:
            self._validate_safe_string(str(hostname), "hostname", result)

        if result.ok:
            result.sanitized = raw_event

        return result

    # -----------------------------------------------------------------------
    # Field validators
    # -----------------------------------------------------------------------

    def _validate_timestamp(self, ts: str, result: ValidationResult):
        """Accept ISO 8601, Unix timestamps, and common log formats."""
        formats = [
            "%Y-%m-%dT%H:%M:%S.%f%z",
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d",
        ]
        # Try Unix epoch (int or float)
        try:
            float_ts = float(ts)
            if 0 < float_ts < 9_999_999_999_999:
                return  # Valid epoch
        except (ValueError, TypeError):
            pass

        for fmt in formats:
            try:
                datetime.strptime(ts[:26], fmt)
                return
            except (ValueError, TypeError):
                continue

        result.add_warning(f"timestamp '{ts[:64]}' could not be parsed — will use ingestion time")

    def _validate_ip(self, ip: str, field_name: str, result: ValidationResult):
        try:
            ipaddress.ip_address(str(ip).strip())
        except ValueError:
            result.add_error(f"Invalid IP address in field '{field_name}': '{ip}'")

    def _validate_port(self, port: Any, field_name: str, result: ValidationResult):
        try:
            p = int(port)
            if not (0 <= p <= 65535):
                result.add_error(f"Port out of range in field '{field_name}': {port} (must be 0-65535)")
        except (ValueError, TypeError):
            result.add_error(f"Invalid port value in field '{field_name}': '{port}'")

    def _validate_protocol(self, proto: str, result: ValidationResult):
        if proto.lower() not in VALID_PROTOCOLS:
            result.add_warning(f"Unknown protocol '{proto}' — will be stored as-is")

    def _validate_severity(self, sev: str, result: ValidationResult):
        if sev.lower() not in VALID_SEVERITIES:
            result.add_warning(f"Unknown severity '{sev}' — will be mapped to 'unknown'")

    def _validate_safe_string(self, value: str, field_name: str, result: ValidationResult):
        """Reject strings with injection-risk characters."""
        # Strip whitespace before checking
        if len(value) > 256:
            result.add_warning(f"Field '{field_name}' exceeds 256 chars — will be truncated")
        # Check for SQL/command injection patterns
        danger_patterns = [";", "--", "/*", "*/", "xp_", "DROP ", "SELECT ", "UNION ", "<script", "$(", "`"]
        for pat in danger_patterns:
            if pat.lower() in value.lower():
                result.add_error(f"Field '{field_name}' contains potentially dangerous string: '{pat}'")
                return

    # -----------------------------------------------------------------------
    # Batch validation
    # -----------------------------------------------------------------------

    def validate_batch(
        self,
        events: list,
        source_type: str = "generic",
        environment: str = "lab",
    ) -> Tuple[List[ValidationResult], List[ValidationResult]]:
        """
        Validate a list of raw events.

        Returns:
            (valid_results, invalid_results)
            Partial failures are allowed — valid events still proceed.
        """
        valid = []
        invalid = []
        for idx, event in enumerate(events):
            res = self.validate(event, source_type, environment)
            if res.ok:
                valid.append(res)
            else:
                # Attach index for error reporting
                res.errors = [f"[event #{idx}] {e}" for e in res.errors]
                invalid.append(res)
        return valid, invalid
