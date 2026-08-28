# SOC Demo Mode Guide

## Overview

**Demo Mode** executes a complete, automated end-to-end SOC simulation workflow in a single API call.  
It demonstrates the full detection and response pipeline without requiring manual analyst input.

> 🛡️ **Safety Notice**: Demo Mode operates exclusively in SIMULATION mode. No physical endpoints are contacted. No real-world actions are performed.

## What Demo Mode Does

```
1. Analyst selects Scenario & Speed
        ↓
2. ScenarioEngine generates simulated telemetry events
        ↓
3. TelemetryPipeline processes events:
   Validation → Normalization → Deduplication → Storage
        ↓
4. DetectionEngine fires alert rules
        ↓
5. CorrelationEngine groups related events
        ↓
6. RiskEngine scores alerts
        ↓
7. SOAR PlaybookEngine executes in SIMULATION mode
        ↓
8. SOCMetricsEngine captures operational snapshot
        ↓
9. Response includes run summary + metrics snapshot
```

## API

```
POST /api/v1/demo/start
Authorization: Bearer <jwt_token>
Content-Type: application/json

{
  "scenario_id": "SCEN-001",
  "speed_multiplier": 10.0
}
```

**Permissions required**: `demo.execute`

## Available Scenarios for Demo

| Scenario | ID | Duration at 10x |
|---|---|---|
| SSH Brute Force | SCEN-001 | ~1s |
| Windows AD Brute Force | SCEN-002 | ~1s |
| Suspicious PowerShell | SCEN-003 | ~1s |
| Account Compromise | SCEN-004 | ~1s |
| DNS Tunneling | SCEN-005 | ~1s |
| Malicious IOC Detection | SCEN-006 | ~1s |
| Multi-Stage Ransomware | SCEN-007 | ~1s |
| Data Exfiltration | SCEN-008 | ~1s |

## Example Response

```json
{
  "demo_status": "COMPLETED",
  "source_mode": "simulation",
  "simulation_safety_notice": "SOC LAB — SIMULATION MODE. No physical endpoints were contacted. No real-world actions were performed.",
  "scenario_run": {
    "run_id": "run-a1b2c3d4",
    "scenario_id": "SCEN-001",
    "status": "COMPLETED",
    "events_count": 4,
    "alerts_count": 1,
    "source_mode": "simulation"
  },
  "playbook_result": {
    "status": "COMPLETED",
    "execution_mode": "SIMULATION",
    "actions_completed": 3
  },
  "metrics_snapshot": {
    "total_alerts": 15,
    "open_incidents": 4,
    "soar_executions": 8
  }
}
```

## Speed Recommendations

| Use Case | Speed |
|---|---|
| Live SOC demonstration | `5x` |
| Training walkthrough | `1x` |
| Quick integration test | `50x` |
| Automated CI pipeline | `50x` |

## Safety Guarantees

- `source_mode = "simulation"` is enforced on every generated event
- SOAR LIVE mode remains disabled (Phase 8 server-side gate)
- Physical endpoint adapters return `NOT_CONFIGURED`, never fabricate real-world actions
- Demo audit log records all actions with `source_mode = "simulation"`
