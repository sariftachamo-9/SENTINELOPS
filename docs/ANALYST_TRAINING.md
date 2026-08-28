# Analyst Training Guide

## Overview

The Analyst Training Module provides an **interactive, guided SOC investigation workflow** that teaches analysts to correctly identify, investigate, and respond to security incidents using real platform workflows.

## Training Workflow

```
1. Alert Triage       → Classify alert as TRUE_POSITIVE / FALSE_POSITIVE
2. Severity Assessment → Assign severity (LOW, MEDIUM, HIGH, CRITICAL)
3. Investigation       → Identify affected host, user, and source
4. Evidence Review     → Link telemetry events to case chain-of-custody
5. IOC Enrichment      → Classify threat indicators using Threat Intel
6. MITRE Analysis      → Map to ATT&CK technique ID
7. Risk Assessment     → Validate risk score and logic
8. Incident Creation   → Escalate true positive to Incident
9. Case Investigation  → Document findings in Case notes
10. SOAR Simulation   → Select and simulate response playbook
11. Final Resolution   → Resolve with correct disposition
```

## Scoring Dimensions (10 × 10 points each = 100 total)

| Dimension | Points | What's Evaluated |
|---|---|---|
| Alert Triage | 10 | Correct TRUE_POSITIVE / FALSE_POSITIVE verdict |
| Severity Assessment | 10 | Correct or near-correct severity classification |
| Investigation Quality | 10 | Identified affected host and user |
| MITRE Identification | 10 | Correctly mapped ATT&CK technique |
| IOC Classification | 10 | Identified and classified threat indicator |
| Incident Escalation | 10 | Escalated TRUE_POSITIVE to Incident |
| Evidence Handling | 10 | Attached telemetry to case record |
| Case Documentation | 10 | Provided ≥15 character investigation notes |
| Response Selection | 10 | Selected appropriate SOAR action |
| Final Resolution | 10 | Resolved with valid disposition |

**Pass threshold: 75% (75/100 points)**

## Hint System

- Each scenario provides up to 3 optional hints
- Each hint used deducts **2 points** from the final score
- Maximum penalty: 20 points (10 hints)
- Hints are progressive — they reveal increasingly specific details

## API Reference

| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/v1/training/start` | Start a training session |
| GET | `/api/v1/training/{id}` | Get session state & prompts |
| POST | `/api/v1/training/{id}/hint` | Request a hint |
| POST | `/api/v1/training/{id}/answer` | Submit answers |
| POST | `/api/v1/training/{id}/submit` | Submit for scoring |
| GET | `/api/v1/training/{id}/score` | Get scorecard |
| GET | `/api/v1/training/{id}/report/json` | Download JSON report |
| GET | `/api/v1/training/{id}/report/csv` | Download CSV report |

## RBAC Permissions

| Role | Access |
|---|---|
| Read Only | ❌ Cannot access training |
| SOC Analyst L1 | ✅ Run & submit training sessions |
| SOC Analyst L2 | ✅ Advanced training access |
| SOC Manager | ✅ View all analyst sessions & scores |
| Administrator | ✅ Full access |

## Example Answer Submission

```json
POST /api/v1/training/{session_id}/submit
{
  "triage_verdict": "TRUE_POSITIVE",
  "severity": "HIGH",
  "target_host": "linux-srv-01",
  "mitre_technique": "T1110.001",
  "ioc_classification": "198.51.100.44",
  "incident_escalated": true,
  "evidence_added": true,
  "case_notes": "SSH brute force from 198.51.100.44 with 3 failed attempts followed by successful root login.",
  "recommended_soar": "ADD_IOC_SIMULATED_BLOCKLIST",
  "resolution": "RESOLVED"
}
```

## Scorecard Response

```json
{
  "total_score": 92,
  "max_possible": 100,
  "percentage": 92.0,
  "passed": true,
  "hints_used_count": 1,
  "hint_penalty_points": 2,
  "breakdown": {
    "ALERT_TRIAGE": {"score": 10, "max": 10, "comment": "Correct triage verdict: TRUE_POSITIVE"},
    "MITRE_IDENTIFICATION": {"score": 10, "max": 10, "comment": "Valid MITRE technique mapping: T1110.001"}
  },
  "correct_actions": ["Correctly triaged alert as TRUE_POSITIVE", "Mapped to T1110.001"],
  "mistakes": ["Requested 1 hint(s) (-2 points penalty)"],
  "recommendations": []
}
```
