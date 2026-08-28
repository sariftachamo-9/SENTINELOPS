# Playbooks Specification & Catalog Guide

## Playbook Definition Schema

Playbooks in the SOC platform are stored as JSON-serializable records in the `playbooks` table:

```json
{
  "id": "PB-002",
  "playbook_id": "PB-002",
  "name": "Controlled Endpoint Host Isolation",
  "description": "Isolates workstation network interface in simulated lab environment. Requires Analyst Approval.",
  "trigger": {
    "event": "high_risk_alert",
    "min_risk_score": 80
  },
  "conditions": [
    "alert.risk_score >= 80",
    "alert.status == 'NEW'"
  ],
  "actions": [
    {"action_type": "ISOLATE_HOST"},
    {"action_type": "ADD_CASE_NOTE"}
  ],
  "required_permission": "playbook.execute",
  "approval_required": 1,
  "risk_level": "HIGH",
  "enabled": 1,
  "execution_mode": "SIMULATION",
  "created_by": "System"
}
```

---

## Seed Playbook Catalog

| Playbook ID | Name | Trigger Condition | Risk Level | Requires Approval | Execution Mode |
|---|---|---|---|---|---|
| **PB-001** | Automated Threat Intel & IP Reputation Enrichment | `alert.risk_score >= 50` | LOW | Auto (No) | `SIMULATION` |
| **PB-002** | Controlled Endpoint Host Isolation | `alert.risk_score >= 80 AND alert.status == 'NEW'` | HIGH | Yes | `SIMULATION` |
| **PB-003** | User Account Suspend & Incident Escalation | `alert.severity in ['high', 'critical']` | HIGH | Yes | `SIMULATION` |
| **PB-004** | Automated IOC Blocklist Escalation | `ioc.classification == 'MALICIOUS'` | MEDIUM | Auto (No) | `SIMULATION` |

---

## Trigger & Condition Expression Syntax

The condition parser supports dot-notation attribute paths, numerical comparisons, string equality, and set inclusion:

- **Numerical Comparisons**: `alert.risk_score >= 80`, `alert.event_count > 5`
- **String Equality**: `alert.status == 'NEW'`, `ioc.classification == 'MALICIOUS'`
- **Set Inclusion**: `alert.severity in ['high', 'critical']`
- **Path Resolution**:
  - `alert.risk_score` -> `context["alert"]["risk_score"]`
  - `ioc.classification` -> `context["ioc"]["classification"]`
  - `incident.priority` -> `context["incident"]["priority"]`

---

## API Lifecycle Operations

- `GET /api/v1/playbooks`: Retrieve catalog of registered playbooks.
- `POST /api/v1/playbooks`: Create a new custom playbook (requires `playbook.create`).
- `GET /api/v1/playbooks/{id}`: Get playbook details by ID.
- `PATCH /api/v1/playbooks/{id}`: Update playbook configuration (requires `playbook.update`).
- `DELETE /api/v1/playbooks/{id}`: Delete playbook definition (requires `playbook.delete`).
