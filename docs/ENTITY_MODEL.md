# Entity Model — Phase 6

## Overview
Entities represent real-world objects extracted from telemetry events and alerts. Relationships between entities form the investigation graph.

## Entity Types
`USER` | `HOST` | `IP` | `DOMAIN` | `PROCESS` | `FILE` | `IOC` | `ALERT` | `INCIDENT` | `CASE`

## Schema

**entities table**
| Field | Description |
|---|---|
| entity_id | ENT-{hex12} |
| entity_type | See types above |
| value | The entity value (e.g., "192.168.1.1") |
| first_seen | Earliest observation |
| last_seen | Most recent observation |
| metadata | JSON bag of additional attributes |

**entity_relationships table**
| Field | Description |
|---|---|
| rel_id | REL-{hex10} |
| source_entity_id | Source entity |
| target_entity_id | Target entity |
| relationship_type | e.g., logged_into, connected_to, matched_ioc |
| confidence | 0–100 |
| first_seen | When relationship was first observed |
| case_id | Optional case scope |

## Auto-Extraction
Entities are automatically extracted from:
- Normalized telemetry events (hostname, username, source_ip, destination_ip, process_name)
- Alerts (affected_asset, affected_user, destination, detection_rule)

When an alert is linked to a case, entities are extracted and relationships created scoped to that case.

## Graph Integrity
- **No fake/decorative nodes.** Every node in the graph corresponds to a stored entity.
- Every edge corresponds to a stored relationship.

## API

| Method | Path | Permission |
|---|---|---|
| GET | /api/v1/entities | cases.read |
| GET | /api/v1/entities/{id} | cases.read |
| GET | /api/v1/entities/{id}/relationships | cases.read |
| GET | /api/v1/cases/{id}/entity-graph | cases.read |
