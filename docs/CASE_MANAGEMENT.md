# Case Management — Phase 6

## Overview
Cases are the primary investigation unit. Each case aggregates alerts, incidents, evidence, notes, entity relationships, and timelines into a single analyst workspace.

> **Source Limitation**: All telemetry is collector-generated live API telemetry. Physical Windows/Linux VM endpoint telemetry is NOT yet connected.

## Data Model

| Field | Type | Description |
|---|---|---|
| id | TEXT | CASE-YYYYMMDD-XXXXXX |
| title | TEXT | Short description |
| description | TEXT | Full investigation summary |
| severity | TEXT | low / medium / high / critical |
| priority | TEXT | LOW / MEDIUM / HIGH / CRITICAL |
| status | TEXT | See state machine below |
| assigned_to | TEXT | Analyst username |
| created_by | TEXT | Creator username |
| created_at | ISO8601 | Creation timestamp |
| updated_at | ISO8601 | Last update |
| closed_at | ISO8601 | Set when status=CLOSED |
| disposition | TEXT | See dispositions below |
| tags | JSON array | Free-form labels |
| due_date | TEXT | Optional SLA date |

## State Machine

```
OPEN → IN_PROGRESS → CONTAINED → RESOLVED → CLOSED
```

- Forward transitions allowed for all case-authorized roles.
- Backward transitions require `cases.manage` permission.
- CLOSED cases cannot be re-opened.
- `closed_at` is set automatically when status becomes CLOSED.

## Dispositions

| Value | Meaning |
|---|---|
| TRUE_POSITIVE | Confirmed real attack |
| FALSE_POSITIVE | Not a real threat |
| BENIGN | Legitimate activity |
| UNDETERMINED | Investigation incomplete |

## Alert → Incident → Case Relationship

```
Alert --[case_alerts]--> Case
Incident --[case_incidents]--> Case
```

- One alert may belong to multiple cases.
- One case may contain multiple alerts and incidents.
- Analysts control linking; no automatic case creation per alert.

## API

| Method | Path | Permission |
|---|---|---|
| GET | /api/v1/cases | cases.read |
| POST | /api/v1/cases | cases.create |
| GET | /api/v1/cases/{id} | cases.read |
| PATCH | /api/v1/cases/{id}/status | cases.read |
| PATCH | /api/v1/cases/{id}/disposition | cases.read |
| PATCH | /api/v1/cases/{id}/assign | cases.manage |
| POST | /api/v1/cases/{id}/alerts | cases.create |
| POST | /api/v1/cases/{id}/incidents | cases.create |

## RBAC

| Role | Create | Assign | Manage | Close |
|---|---|---|---|---|
| SOC Analyst L1 | ✓ | ✗ | ✗ | ✗ |
| SOC Analyst L2 | ✓ | ✗ | ✗ | ✗ |
| Incident Responder | ✓ | ✓ | ✓ | ✓ |
| SOC Manager | ✓ | ✓ | ✓ | ✓ |
| Administrator | ✓ | ✓ | ✓ | ✓ |
