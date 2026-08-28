"""
SOC Lab — Windows Telemetry Adapter (Phase 3)
============================================
Handles:
  - Windows Security Event Log (Evtx)
  - Sysmon (System Monitor)
  - PowerShell Script Block Logging
  - Windows authentication events
  - Windows process creation events
  - Windows account management events

Real connection status: NOT CONFIGURED until a Windows agent (Wazuh/NXLog/Winlogbeat)
is configured and sending events. See INTEGRATIONS.md for setup instructions.

Supported Windows Event IDs (partial list):
  Authentication:
    4624 — Successful logon
    4625 — Failed logon
    4648 — Explicit credential logon
    4672 — Special privileges assigned to new logon
    4768 — Kerberos TGT requested
    4769 — Kerberos service ticket requested
    4771 — Kerberos pre-authentication failed
    4776 — NTLM authentication attempt
  Account Management:
    4720 — User account created
    4722 — User account enabled
    4723 — Password change attempt
    4724 — Password reset
    4725 — User account disabled
    4726 — User account deleted
    4732 — Member added to security group
    4733 — Member removed from security group
  Process:
    4688 — Process created
    4689 — Process exited
    4698 — Scheduled task created
  Sysmon:
    1   — Process creation (Sysmon)
    3   — Network connection (Sysmon)
    7   — Image loaded (Sysmon)
    8   — CreateRemoteThread (Sysmon)
    10  — ProcessAccess (Sysmon)
    11  — FileCreate (Sysmon)
    13  — RegistryValueSet (Sysmon)
  PowerShell:
    4103 — Module logging
    4104 — Script block logging
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from src.telemetry.adapters.base import TelemetryAdapter
from src.telemetry.schema import NormalizedEvent


# Map Windows EventID → (event_type, default_severity, action, outcome)
_WINDOWS_EVENT_MAP: Dict[int, Dict[str, str]] = {
    4624: {"event_type": "User Logon",             "severity": "info",     "action": "login",   "outcome": "success"},
    4625: {"event_type": "Failed Logon",            "severity": "high",     "action": "login",   "outcome": "failure"},
    4648: {"event_type": "Explicit Credential Use", "severity": "medium",   "action": "login",   "outcome": "success"},
    4656: {"event_type": "Object Access Requested", "severity": "low",      "action": "read",    "outcome": "unknown"},
    4663: {"event_type": "Object Access",           "severity": "low",      "action": "access",  "outcome": "success"},
    4672: {"event_type": "Special Privileges",      "severity": "medium",   "action": "privilege","outcome": "success"},
    4698: {"event_type": "Scheduled Task Created",  "severity": "medium",   "action": "create",  "outcome": "success"},
    4720: {"event_type": "Account Created",         "severity": "medium",   "action": "create",  "outcome": "success"},
    4722: {"event_type": "Account Enabled",         "severity": "low",      "action": "enable",  "outcome": "success"},
    4723: {"event_type": "Password Changed",        "severity": "medium",   "action": "modify",  "outcome": "success"},
    4724: {"event_type": "Password Reset",          "severity": "high",     "action": "modify",  "outcome": "success"},
    4725: {"event_type": "Account Disabled",        "severity": "medium",   "action": "disable", "outcome": "success"},
    4726: {"event_type": "Account Deleted",         "severity": "high",     "action": "delete",  "outcome": "success"},
    4732: {"event_type": "Group Member Added",      "severity": "medium",   "action": "modify",  "outcome": "success"},
    4733: {"event_type": "Group Member Removed",    "severity": "medium",   "action": "modify",  "outcome": "success"},
    4768: {"event_type": "Kerberos TGT Request",    "severity": "info",     "action": "auth",    "outcome": "success"},
    4769: {"event_type": "Kerberos Service Ticket", "severity": "info",     "action": "auth",    "outcome": "success"},
    4771: {"event_type": "Kerberos Pre-Auth Failed","severity": "high",     "action": "auth",    "outcome": "failure"},
    4776: {"event_type": "NTLM Authentication",     "severity": "info",     "action": "auth",    "outcome": "unknown"},
    4688: {"event_type": "Process Creation",        "severity": "low",      "action": "execute", "outcome": "success"},
    4689: {"event_type": "Process Exit",            "severity": "info",     "action": "execute", "outcome": "success"},
    # Sysmon
    1:    {"event_type": "Process Creation (Sysmon)","severity": "low",     "action": "execute", "outcome": "success"},
    3:    {"event_type": "Network Connection (Sysmon)","severity": "low",   "action": "connect", "outcome": "success"},
    7:    {"event_type": "Image Load (Sysmon)",     "severity": "low",      "action": "load",    "outcome": "success"},
    8:    {"event_type": "Remote Thread (Sysmon)",  "severity": "critical", "action": "inject",  "outcome": "success"},
    10:   {"event_type": "Process Access (Sysmon)", "severity": "high",     "action": "access",  "outcome": "success"},
    11:   {"event_type": "File Create (Sysmon)",    "severity": "low",      "action": "create",  "outcome": "success"},
    13:   {"event_type": "Registry Set (Sysmon)",   "severity": "medium",   "action": "modify",  "outcome": "success"},
    # PowerShell
    4103: {"event_type": "PowerShell Module",       "severity": "medium",   "action": "execute", "outcome": "success"},
    4104: {"event_type": "PowerShell Script Block", "severity": "high",     "action": "execute", "outcome": "success"},
}


class WindowsAdapter(TelemetryAdapter):
    """Windows Event Log and Sysmon telemetry adapter."""

    SOURCE_TYPE = "windows"
    DESCRIPTION = "Windows Security Event Log, Sysmon, and PowerShell events"
    REQUIRES_CONFIGURATION = True  # Needs Wazuh/Winlogbeat agent

    def can_handle(self, raw_event: Dict[str, Any]) -> bool:
        return bool(
            raw_event.get("EventID")
            or raw_event.get("winlog")
            or raw_event.get("event_data")
            or "sysmon" in str(raw_event).lower()
        )

    def normalize(
        self,
        raw_event: Dict[str, Any],
        environment: str = "lab",
        sensor_id: Optional[str] = None,
    ) -> NormalizedEvent:
        now = self._now_iso()

        # Extract event ID (various formats from different shippers)
        event_id_num = (
            self._safe_int(raw_event.get("EventID"))
            or self._safe_int(raw_event.get("event_id"))
            or self._safe_int((raw_event.get("winlog") or {}).get("event_id"))
        )

        # Lookup event metadata
        event_meta = _WINDOWS_EVENT_MAP.get(event_id_num, {}) if event_id_num else {}

        # Extract common fields from various Windows log formats
        computer = (
            self._safe_str(raw_event.get("hostname"))
            or self._safe_str(raw_event.get("computer_name"))
            or self._safe_str(raw_event.get("ComputerName"))
            or self._safe_str((raw_event.get("winlog") or {}).get("computer_name"))
            or self._safe_str(raw_event.get("host"))
        )

        username = (
            self._safe_str(raw_event.get("TargetUserName"))
            or self._safe_str(raw_event.get("SubjectUserName"))
            or self._safe_str(raw_event.get("username"))
            or self._safe_str(raw_event.get("user"))
        )

        domain = (
            self._safe_str(raw_event.get("TargetDomainName"))
            or self._safe_str(raw_event.get("SubjectDomainName"))
        )

        src_ip = self._safe_ip(
            raw_event.get("IpAddress")
            or raw_event.get("source_ip")
            or raw_event.get("src_ip")
        )

        process_name = (
            self._safe_str(raw_event.get("NewProcessName"))
            or self._safe_str(raw_event.get("Image"))
            or self._safe_str(raw_event.get("process_name"))
        )

        parent_process = (
            self._safe_str(raw_event.get("ParentImage"))
            or self._safe_str(raw_event.get("ParentProcessName"))
            or self._safe_str(raw_event.get("parent_process"))
        )

        cmd_line = (
            self._safe_str(raw_event.get("CommandLine"))
            or self._safe_str(raw_event.get("command_line"))
        )

        severity = event_meta.get("severity") or self._infer_severity_from_text(raw_event)
        event_type = event_meta.get("event_type") or raw_event.get("event_type") or "Windows Event"
        action = event_meta.get("action")
        outcome = event_meta.get("outcome")

        # Build message
        msg_parts = []
        if event_id_num:
            msg_parts.append(f"EventID={event_id_num}")
        if username:
            msg_parts.append(f"User={username}")
        if computer:
            msg_parts.append(f"Host={computer}")
        if process_name:
            msg_parts.append(f"Process={process_name}")
        message = " | ".join(msg_parts) if msg_parts else event_type

        # Tags
        tags = ["windows"]
        if event_id_num in (4688, 1):
            tags.append("process_creation")
        if event_id_num in (4624, 4625, 4648, 4768, 4769, 4771, 4776):
            tags.append("authentication")
        if event_id_num in (4720, 4722, 4723, 4724, 4725, 4726, 4732, 4733):
            tags.append("account_management")
        if environment in ("lab", "simulation"):
            tags.append("simulation")

        return NormalizedEvent(
            timestamp=str(
                raw_event.get("timestamp")
                or raw_event.get("@timestamp")
                or raw_event.get("TimeCreated")
                or now
            ),
            ingestion_timestamp=now,
            source_type="windows",
            source_product=raw_event.get("source_product", "WinEvtLog"),
            source_sensor=sensor_id or raw_event.get("agent_id") or raw_event.get("sensor_id"),
            environment=environment,
            hostname=computer,
            source_ip=src_ip,
            destination_ip=self._safe_ip(raw_event.get("destination_ip") or raw_event.get("dest_ip")),
            source_port=self._safe_int(raw_event.get("source_port") or raw_event.get("src_port")),
            destination_port=self._safe_int(raw_event.get("destination_port") or raw_event.get("DestPort")),
            username=username,
            domain=domain,
            process_name=process_name,
            parent_process=parent_process,
            command_line=cmd_line,
            event_type=event_type,
            event_code=str(event_id_num) if event_id_num else None,
            severity=severity,
            action=action,
            outcome=outcome,
            message=message,
            tags=tags,
            raw_event=raw_event,
            simulation=(environment in ("lab", "simulation")),
        )
