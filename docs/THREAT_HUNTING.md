# Threat Hunting — Phase 6

## Overview
Structured threat hunting across normalized telemetry. No raw SQL accepted from users.

> **Source Limitation**: Hunts run against collector-generated live API telemetry. Physical endpoint telemetry not yet connected.

## Safe Structured Query Model

```json
{
  "time_range": {"from": "2026-08-01T00:00:00", "to": "2026-08-24T23:59:59"},
  "filters": [
    {"field": "hostname", "operator": "equals", "value": "WIN-SRV-01"},
    {"field": "event_type", "operator": "contains", "value": "Login"}
  ]
}
```

## Whitelisted Fields
`hostname` | `username` | `source_ip` | `destination_ip` | `process_name` | `event_type` | `severity` | `source_type` | `mitre_technique` | `rule_id` | `environment`

## Whitelisted Operators
`equals` | `not_equals` | `contains` | `starts_with` | `ends_with` | `in` | `greater_than` | `less_than`

Any field or operator not in the whitelist is rejected with HTTP 400.

## Saved Hunts
- Analysts can save named hunt queries for reuse.
- RBAC: `hunting.save` permission required.
- IDOR: non-admin users can only access their own saved hunts.

## Hunt → Alert Promotion
Analysts can promote interesting hunt results to an investigation reference attached to a case. This does NOT automatically create a detection rule. Analyst must explicitly initiate the action.

## API

| Method | Path | Permission |
|---|---|---|
| POST | /api/v1/hunting/execute | hunting.execute |
| GET | /api/v1/hunting/saved | hunting.read |
| POST | /api/v1/hunting/saved | hunting.save |
| GET | /api/v1/hunting/saved/{id} | hunting.read |
| DELETE | /api/v1/hunting/saved/{id} | hunting.save |
| POST | /api/v1/hunting/promote | hunting.promote |

## Security
- All SQL is parameterized. User input never concatenated into queries.
- Fields and operators validated against whitelists before query construction.
- SQL injection attempts raise `HuntQueryValidationError` (HTTP 400).
