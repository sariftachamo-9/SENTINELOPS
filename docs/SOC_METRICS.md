# SOC Operational Metrics Reference

## Overview

The SOC Metrics Engine (`src/soc_metrics.py`) calculates **real operational metrics** exclusively from stored platform database records.

> ⚠️ **Honesty Guarantee**: If the database has no data for a metric, it returns `0` or `"NO DATA"` — never fabricated placeholder numbers.

## Available Metrics

### Volume Metrics

| Metric | Field | Description |
|---|---|---|
| Events per second | `events_per_second` | Rolling 60-second EPS from TelemetryHealthMonitor |
| Total events | `total_events` | All events in `events` table |
| Alerts today | `alerts_today` | Alerts with today's date prefix |
| Total alerts | `total_alerts` | All alerts ever stored |
| Critical alerts | `critical_alerts` | Alerts with severity = CRITICAL |

### Incident & Case Metrics

| Metric | Field | Description |
|---|---|---|
| Open incidents | `open_incidents` | Incidents in OPEN / INVESTIGATING / IN_PROGRESS |
| Open cases | `open_cases` | Cases in OPEN / IN_PROGRESS / TRIAGE |

### Performance Metrics

| Metric | Field | Formula |
|---|---|---|
| MTTD | `mttd_seconds` | Avg(alert.timestamp − alert.first_seen) for recent alerts |
| MTTR | `mttr_seconds` | Avg(case.closed_at − case.created_at) for closed cases |
| False Positive Rate | `false_positive_rate_pct` | FP alerts / total alerts × 100 |

### Threat Intelligence Metrics

| Metric | Field | Description |
|---|---|---|
| IOC Matches | `ioc_matches` | IOCs with reputation = MALICIOUS |
| MITRE Coverage | `mitre_technique_coverage` | Count of distinct MITRE techniques in alerts |
| Covered Techniques | `mitre_techniques` | List of ATT&CK technique IDs |

### SOAR Metrics

| Metric | Field | Description |
|---|---|---|
| SOAR Executions | `soar_executions` | Total rows in `playbook_executions` |
| Failed Playbooks | `failed_playbooks` | Rows with status = FAILED |

## API Reference

```
GET /api/v1/soc/metrics
GET /api/v1/soc/metrics/timeline?days=7
```

**Permissions required**: `metrics.read`

## Example Response

```json
{
  "timestamp": "2026-08-24T15:00:00",
  "events_per_second": 2.4,
  "total_events": 842,
  "alerts_today": 12,
  "total_alerts": 134,
  "critical_alerts": 3,
  "open_incidents": 4,
  "open_cases": 6,
  "mttd_seconds": 3.2,
  "mttd_display": "3.2s",
  "mttr_seconds": 0.0,
  "mttr_display": "NO DATA",
  "false_positive_rate_pct": 12.5,
  "false_positive_rate_display": "12.5%",
  "ioc_matches": 17,
  "mitre_technique_coverage": 8,
  "mitre_techniques": ["T1110", "T1059.001", "T1486"],
  "soar_executions": 23,
  "failed_playbooks": 1,
  "alert_volume_by_severity": {
    "low": 44, "medium": 72, "high": 15, "critical": 3
  },
  "has_data": true
}
```

## NO DATA Behavior

| Condition | Value |
|---|---|
| No alerts ever stored | `mttd_display: "NO DATA"`, `false_positive_rate_display: "NO DATA"` |
| No closed cases | `mttr_display: "NO DATA"` |
| Empty database | All counts = 0, `has_data: false` |
