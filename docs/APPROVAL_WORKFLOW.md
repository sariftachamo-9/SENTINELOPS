# Analyst Approval Workflow & RBAC Reference

## Approval Workflow State Machine

High-risk actions (e.g. Host Isolation, Account Disablement) and playbooks flagged with `approval_required=True` are protected by a manual analyst approval gate:

```
                      +-------------------+
                      | Playbook Trigger  |
                      +---------+---------+
                                |
                   [ requires_approval == True ]
                                |
                                v
                    +-----------------------+
                    |   PENDING_APPROVAL    |
                    +---+---------------+---+
                        |               |
           [ Approved ] |               | [ Rejected / Cancelled ]
                        v               v
                +---------------+  +-------------------+
                |   EXECUTING   |  | REJECTED/CANCELLED|
                +-------+-------+  +-------------------+
                        |
                        v
                +---------------+
                |   COMPLETED   |
                +---------------+
```

---

## State Machine API Operations

### 1. Trigger Playbook Execution
`POST /api/v1/playbooks/{id}/execute` or `POST /api/v1/playbooks/execute`
- Request body:
  ```json
  {
    "playbook_id": "PB-002",
    "target": "10.0.0.15",
    "approved": false
  }
  ```
- If the playbook requires approval and `approved` is false, returns status `PENDING_APPROVAL` with `execution_id`.

### 2. Approve Pending Execution
`POST /api/v1/playbook-executions/{execution_id}/approve`
- Requires RBAC permission `playbook.approve` (SOC Analyst L2, Incident Responder, SOC Manager, Admin).
- Request body: `{"reason": "Analyst verified compromise on host 10.0.0.15"}`
- Transitions status to `EXECUTING` -> `COMPLETED`, returning execution action outputs.

### 3. Reject Pending Execution
`POST /api/v1/playbook-executions/{execution_id}/reject`
- Requires RBAC permission `playbook.approve`.
- Request body: `{"reason": "False positive alert"}`
- Transitions status to `REJECTED`.

### 4. Cancel Active/Pending Execution
`POST /api/v1/playbook-executions/{execution_id}/cancel`
- Requires RBAC permission `playbook.execute`.
- Request body: `{"reason": "Superceded by manual investigation"}`
- Transitions status to `CANCELLED`.

---

## Granular RBAC Permissions Mapping

| Role | `playbook.read` | `playbook.execute` | `playbook.approve` | `playbook.create` | `playbook.update` | `playbook.delete` |
|---|---|---|---|---|---|---|
| **Read Only** | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **SOC Analyst L1** | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ |
| **SOC Analyst L2** | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ |
| **Incident Responder** | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ |
| **SOC Manager** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Admin** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |

---

## Immutable Audit Trail

Every state transition in the approval workflow produces a structured record in `playbook_executions` and logs an entry in `audit_logs`:

- `PLAYBOOK_PENDING_APPROVAL`: Logged when an execution pauses for approval.
- `PLAYBOOK_APPROVED`: Logged when an analyst approves execution.
- `PLAYBOOK_REJECTED`: Logged when execution is rejected.
- `EXECUTE_PLAYBOOK_COMPLETED`: Logged after all actions complete successfully.
- `ROLLBACK_PLAYBOOK_COMPLETED`: Logged after actions are rolled back.
