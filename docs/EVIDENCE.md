# Evidence Management — Phase 6

## Overview
Evidence items are attached to cases. Every evidence item carries an append-only chain of custody.

> No arbitrary executable files are stored. Only metadata, references, and hashes.

## Fields

| Field | Description |
|---|---|
| evidence_id | EV-{hex12} |
| case_id | Parent case |
| type | Evidence type (see below) |
| source | Origin (e.g., SIEM, Endpoint, Feed) |
| timestamp | When collected |
| added_by | Analyst username |
| description | Free-text (HTML-escaped) |
| hash | SHA-256 or MD5 of referenced artifact |
| content_ref | External reference URL or path |
| chain_of_custody | Append-only JSON audit trail |

## Evidence Types
`telemetry_event` | `alert` | `screenshot_meta` | `ioc` | `analyst_note` | `external_ref` | `file_meta`

## Chain of Custody
Every state change appends an entry:
```json
{"action": "ADDED", "by": "analyst", "at": "2026-08-24T...", "note": "..."}
{"action": "METADATA_UPDATED", "by": "manager", "at": "...", "fields_changed": ["description"]}
```
Historical entries are never removed or overwritten.

## Security
- `description` and `source` are HTML-escaped before storage.
- Modification requires `evidence.modify` permission.
- IDOR: `case_id` must match stored record on every request.

## API

| Method | Path | Permission |
|---|---|---|
| GET | /api/v1/cases/{id}/evidence | cases.read |
| POST | /api/v1/cases/{id}/evidence | evidence.add |
| GET | /api/v1/cases/{id}/evidence/{ev_id} | cases.read |
| PATCH | /api/v1/cases/{id}/evidence/{ev_id} | evidence.modify |
