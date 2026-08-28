# Investigation Workspace — Phase 6

## Overview
The Investigation Workspace aggregates all data needed to investigate a case into a single view.

## Workspace Components

| Section | Source |
|---|---|
| Case Info | cases table |
| Linked Alerts | case_alerts junction |
| Linked Incidents | case_incidents junction |
| Affected Assets | Extracted from alerts + entities |
| Users | Extracted from alerts + entities |
| Source IPs | Extracted from alerts + entities |
| Destination IPs | Extracted from alerts + entities |
| Processes | Entity graph (PROCESS nodes) |
| IOCs | Indicators from alerts + IOC entities |
| MITRE Techniques | Extracted from linked alerts |
| Entity Graph | entity_relationships table (real data only) |
| Timeline | Combined events + alerts + case-audit + evidence |
| Evidence | evidence table |
| Notes | case_notes table |
| Audit History | audit_logs for this case_id |

## Investigation Timeline

The unified timeline merges:
1. **Telemetry Events** — raw endpoint/network events that triggered alerts
2. **Alerts** — detection engine alerts linked to the case
3. **Case Events** — status changes, assignments (from audit_logs)
4. **Evidence** — additions and updates

All items sorted chronologically. Supports filters: time_range, hostname, username, source_ip, event_type, severity.

## Entity Graph

- Backed entirely by `entity_relationships` table.
- Entities auto-extracted when an alert is linked to a case.
- Clicking a node returns: entity_type, value, first_seen, last_seen, relationships.
- Zero fake or placeholder nodes.

## MITRE Coverage

Extracted from MITRE tactic/technique fields of linked alerts. Displays per-technique alert counts.

## API

| Method | Path | Permission |
|---|---|---|
| GET | /api/v1/cases/{id}/workspace | cases.read |
| GET | /api/v1/cases/{id}/timeline | cases.read |
| GET | /api/v1/cases/{id}/entity-graph | cases.read |
| GET | /api/v1/cases/{id}/mitre | cases.read |

## Source Limitation
All telemetry data is **collector-generated live API telemetry**. Physical Windows/Linux VM endpoint telemetry is NOT yet connected.
