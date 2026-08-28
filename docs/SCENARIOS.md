# Attack Scenario Catalog

Phase 9 provides **8 standard attack scenarios** covering common threat categories observed in enterprise SOC environments.  
All scenarios are exclusively simulated — no real endpoints are targeted.

## Scenario Index

| ID | Name | Category | Difficulty | MITRE |
|---|---|---|---|---|
| SCEN-001 | Linux SSH Brute Force & Login | CREDENTIAL_ACCESS | EASY | T1110.001, T1078 |
| SCEN-002 | Windows AD Brute Force | CREDENTIAL_ACCESS | EASY | T1110, T1078.002 |
| SCEN-003 | Obfuscated PowerShell Execution | EXECUTION | MEDIUM | T1059.001, T1027 |
| SCEN-004 | Account Compromise & Privilege Escalation | PRIVILEGE_ESCALATION | MEDIUM | T1003.001, T1098 |
| SCEN-005 | DNS Tunneling & DGA Queries | COMMAND_AND_CONTROL | MEDIUM | T1071.004, T1568.002 |
| SCEN-006 | High-Confidence Malicious IOC Match | DEFENSE_EVASION | EASY | T1071.001, T1589 |
| SCEN-007 | Multi-Stage Ransomware Killchain | ATTACK_SIMULATION | HARD | T1566, T1059.001, T1003.001, T1021.002, T1486 |
| SCEN-008 | Large Volume Data Exfiltration | EXFILTRATION | MEDIUM | T1560.001, T1048.003 |

---

## Scenario Lifecycle States

```
DRAFT → READY → RUNNING → COMPLETED
                        ↘ PAUSED → RUNNING
                        ↘ FAILED
                        ↘ CANCELLED
```

## Control Operations

| Operation | API Endpoint | Description |
|---|---|---|
| Start | `POST /api/v1/scenarios/{id}/start` | Launch a new scenario run |
| Pause | `POST /api/v1/scenario-runs/{id}/pause` | Pause an active run |
| Resume | `POST /api/v1/scenario-runs/{id}/resume` | Resume a paused run |
| Cancel | `POST /api/v1/scenario-runs/{id}/cancel` | Cancel a run permanently |
| Replay | `POST /api/v1/scenario-runs/{id}/replay` | New run from existing run's scenario |
| Get Status | `GET /api/v1/scenario-runs/{id}` | Get current run state |
| Timeline | `GET /api/v1/scenario-runs/{id}/timeline` | Get ordered event log |

## Speed Multipliers

| Multiplier | Use Case |
|---|---|
| `1x` | Full realistic timing |
| `5x` | Accelerated investigation practice |
| `10x` | Demo mode |
| `50x` | Automated testing |

## Event Schema

Every generated event enforces these mandatory fields:
```json
{
  "event_id": "sim-ev-a1b2c3d4e5",
  "timestamp": "2026-08-24T15:00:00.000000",
  "source": "simulated_sensor",
  "source_mode": "simulation",
  "simulation": true,
  "environment": "lab",
  "hostname": "linux-srv-01",
  "user": "root",
  "source_ip": "198.51.100.44",
  "destination_ip": "10.0.0.15",
  "process": "/usr/sbin/sshd",
  "event_category": "authentication",
  "event_type": "SSH_LOGIN_FAILED",
  "severity": "medium",
  "raw_event": {}
}
```
