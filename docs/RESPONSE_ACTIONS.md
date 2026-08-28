# SOAR Response Action Reference & Endpoint Adapters

## Action Registry Summary

All response actions inherit from `BaseAction` (`src/soar/actions.py`) and implement `execute(context, execution_mode)` and `rollback(context, execution_mode)`.

| Action Type | Class Name | Target | Reversible | Default Mode Output | Risk Level |
|---|---|---|---|---|---|
| `ISOLATE_HOST` | `IsolateHostAction` | Hostname / IP | Yes | `SIMULATED_SUCCESS` | HIGH |
| `DISABLE_ACCOUNT` | `DisableAccountAction` | Username | Yes | `SIMULATED_SUCCESS` | HIGH |
| `ADD_IOC_SIMULATED_BLOCKLIST` | `AddIOCToSimulatedBlocklistAction` | IP / Domain / Hash | Yes | `SIMULATED_SUCCESS` | MEDIUM |
| `REMOVE_IOC_SIMULATED_BLOCKLIST` | `RemoveIOCFromSimulatedBlocklistAction` | IP / Domain / Hash | Yes | `SIMULATED_SUCCESS` | MEDIUM |
| `CHANGE_ALERT_SEVERITY` | `ChangeAlertSeverityAction` | Alert ID | No | `SUCCESS` | LOW |
| `CREATE_INCIDENT` | `CreateIncidentAction` | Alert ID | No | `SUCCESS` | LOW |
| `ADD_CASE_NOTE` | `AddCaseNoteAction` | Case ID | No | `SUCCESS` | LOW |
| `ENRICH_IOC` | `EnrichIOCAction` | Indicator | No | `SUCCESS` | LOW |
| `NOTIFY_ANALYST` | `NotifyAnalystAction` | Analyst / Channel | No | `SUCCESS` | LOW |
| `ADD_EVIDENCE` | `AddEvidenceAction` | Case ID | No | `SUCCESS` | LOW |
| `CREATE_INVESTIGATION_TASK` | `CreateInvestigationTaskAction` | Case ID | No | `SUCCESS` | LOW |

---

## Endpoint Integration Safety & Adapters

Physical Windows, Linux, Firewall, and EDR endpoint integrations are currently disconnected in the laboratory environment.

To prevent deceptive state output, physical endpoint adapters return `NOT_CONFIGURED` status when invoked in `LIVE` mode:

```python
from src.soar.actions import EndpointAdapterFactory

adapter = EndpointAdapterFactory.get_adapter("Windows")
res = adapter.execute_containment("10.0.0.50", "ISOLATE_HOST")

# Output:
# {
#   "status": "NOT_CONFIGURED",
#   "adapter": "Windows_ActiveDirectory_EDR",
#   "action": "ISOLATE_HOST",
#   "target": "10.0.0.50",
#   "execution_mode": "LIVE",
#   "details": "Physical integration 'Windows_ActiveDirectory_EDR' is NOT_CONFIGURED in current laboratory environment. Real-world containment was NOT performed.",
#   "error": "Endpoint adapter 'Windows_ActiveDirectory_EDR' is NOT_CONFIGURED for physical execution."
# }
```

### Supported Endpoint Adapters (Stubs)

1. `WindowsEndpointAdapter` (`Windows_ActiveDirectory_EDR`)
2. `LinuxEndpointAdapter` (`Linux_SSH_PAM_Iptables`)
3. `FirewallEndpointAdapter` (`PaloAlto_Fortinet_API`)
4. `CloudIAMAdapter` (`AWS_GCP_Azure_IAM`)

---

## Action Rollback Mechanisms

Reversible actions (such as `ISOLATE_HOST`, `DISABLE_ACCOUNT`, and `ADD_IOC_SIMULATED_BLOCKLIST`) implement a `rollback()` method.

Analysts can trigger rollbacks via API:
`POST /api/v1/playbook-executions/{id}/rollback`

Upon invocation, the SOAR engine iterates through executed actions in **reverse order**, calling `rollback()` on each action, logging the outcome, and updating `rollback_status` to `COMPLETED`.
