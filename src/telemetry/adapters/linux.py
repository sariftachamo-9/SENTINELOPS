"""
SOC Lab — Linux Telemetry Adapter (Phase 3)
==========================================
Handles:
  - SSH authentication events (sshd)
  - sudo events
  - PAM authentication
  - System auth log (/var/log/auth.log, /var/log/secure)
  - Systemd journal
  - Web server access logs (nginx, apache)
  - Auditd events
  - Process activity (execve, fork)

Real connection status: NOT CONFIGURED until a Linux agent (Wazuh/Filebeat/rsyslog)
is configured to forward logs. See INTEGRATIONS.md for setup instructions.

Supported event_type patterns:
  SSH: Accepted/Failed/Invalid user, Disconnected
  Sudo: session opened/closed, authentication failure
  PAM: authentication failure, session opened
  Auditd: EXECVE, OPEN, CONNECT, USER_AUTH
"""

from __future__ import annotations

import re
from typing import Any, Dict, Optional

from src.telemetry.adapters.base import TelemetryAdapter
from src.telemetry.schema import NormalizedEvent


# SSH event patterns
_SSH_ACCEPTED_RE = re.compile(r"Accepted (?P<method>\w+) for (?P<user>\S+) from (?P<ip>[\d:.a-fA-F]+)", re.I)
_SSH_FAILED_RE = re.compile(r"Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d:.a-fA-F]+)", re.I)
_SSH_INVALID_RE = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>[\d:.a-fA-F]+)", re.I)
_SUDO_RE = re.compile(r"(?P<user>\S+) : (?:TTY=\S+\s*)?PWD=\S+\s*;\s*USER=(?P<run_as>\S+)\s*;\s*COMMAND=(?P<cmd>.+)", re.I)


class LinuxAdapter(TelemetryAdapter):
    """Linux system log telemetry adapter."""

    SOURCE_TYPE = "linux"
    DESCRIPTION = "Linux auth, SSH, sudo, auditd, and system log events"
    REQUIRES_CONFIGURATION = True  # Needs Wazuh/Filebeat agent

    def can_handle(self, raw_event: Dict[str, Any]) -> bool:
        msg = str(raw_event.get("message", "")).lower()
        program = str(raw_event.get("program", "") or raw_event.get("process", "")).lower()
        return bool(
            any(k in msg for k in ("sshd", "sudo", "pam_unix", "su:", "auditd", "execve"))
            or any(k in program for k in ("sshd", "sudo", "su", "pam", "auditd", "login"))
            or raw_event.get("source_type", "") == "linux"
        )

    def normalize(
        self,
        raw_event: Dict[str, Any],
        environment: str = "lab",
        sensor_id: Optional[str] = None,
    ) -> NormalizedEvent:
        now = self._now_iso()

        message = str(raw_event.get("message", "") or raw_event.get("msg", "") or "")
        program = str(raw_event.get("program", "") or raw_event.get("process", "") or "").lower()
        hostname = self._safe_str(raw_event.get("hostname") or raw_event.get("host"))

        event_type = raw_event.get("event_type") or "System Event"
        severity = "low"
        action = None
        outcome = None
        src_ip = None
        username = self._safe_str(raw_event.get("username") or raw_event.get("user"))
        process_name = self._safe_str(raw_event.get("process_name") or raw_event.get("program") or raw_event.get("process"))
        tags = ["linux"]

        # --- SSH events ---
        if "sshd" in program or "sshd" in message.lower():
            tags.append("ssh")
            m = _SSH_ACCEPTED_RE.search(message)
            if m:
                event_type = "SSH Login"
                action = "login"
                outcome = "success"
                severity = "info"
                username = username or m.group("user")
                src_ip = self._safe_ip(m.group("ip"))
            else:
                m = _SSH_FAILED_RE.search(message) or _SSH_INVALID_RE.search(message)
                if m:
                    event_type = "SSH Failed Login"
                    action = "login"
                    outcome = "failure"
                    severity = "high"
                    username = username or m.group("user")
                    src_ip = self._safe_ip(m.group("ip"))
                elif "disconnect" in message.lower():
                    event_type = "SSH Disconnect"
                    action = "disconnect"
                    outcome = "success"
                    severity = "info"

        # --- Sudo events ---
        elif "sudo" in program or "sudo" in message.lower():
            tags.append("sudo")
            m = _SUDO_RE.search(message)
            if m:
                event_type = "Sudo Command Execution"
                action = "execute"
                outcome = "success"
                severity = "medium"
                username = username or m.group("user")
                process_name = process_name or m.group("cmd")[:100]
            elif "authentication failure" in message.lower():
                event_type = "Sudo Auth Failure"
                action = "authenticate"
                outcome = "failure"
                severity = "high"

        # --- PAM events ---
        elif "pam_unix" in program or "pam_unix" in message.lower():
            tags.append("pam")
            if "authentication failure" in message.lower():
                event_type = "PAM Auth Failure"
                action = "authenticate"
                outcome = "failure"
                severity = "high"
            elif "session opened" in message.lower():
                event_type = "PAM Session Opened"
                action = "login"
                outcome = "success"
                severity = "info"
            elif "session closed" in message.lower():
                event_type = "PAM Session Closed"
                action = "logout"
                outcome = "success"
                severity = "info"

        # --- Auditd events ---
        elif "auditd" in program or raw_event.get("type", "").startswith("AVC") or raw_event.get("type", "") == "EXECVE":
            tags.append("auditd")
            audit_type = raw_event.get("type", "")
            if audit_type == "EXECVE":
                event_type = "Process Execution (auditd)"
                action = "execute"
                severity = "low"
            elif audit_type in ("USER_AUTH", "USER_LOGIN"):
                event_type = f"User Auth ({audit_type})"
                action = "authenticate"
                severity = "medium"
            elif audit_type == "SYSCALL":
                event_type = "Syscall (auditd)"
                action = "syscall"
                severity = "low"

        # Fallback heuristic
        severity = severity or self._infer_severity_from_text(raw_event)

        if environment in ("lab", "simulation"):
            tags.append("simulation")

        return NormalizedEvent(
            timestamp=str(
                raw_event.get("timestamp")
                or raw_event.get("@timestamp")
                or raw_event.get("time")
                or now
            ),
            ingestion_timestamp=now,
            source_type="linux",
            source_product=raw_event.get("source_product", "syslog"),
            source_sensor=sensor_id or raw_event.get("agent_id"),
            environment=environment,
            hostname=hostname,
            source_ip=src_ip or self._safe_ip(raw_event.get("source_ip")),
            destination_ip=self._safe_ip(raw_event.get("destination_ip")),
            source_port=self._safe_int(raw_event.get("source_port")),
            destination_port=self._safe_int(raw_event.get("destination_port")),
            username=username,
            process_name=process_name,
            event_type=event_type,
            severity=severity,
            action=action,
            outcome=outcome,
            message=message[:1024] if message else event_type,
            tags=tags,
            raw_event=raw_event,
            simulation=(environment in ("lab", "simulation")),
        )
