# SOAR & Response Automation Architecture

## Executive Overview
Phase 8 introduces the **SOAR / Controlled Response Automation** engine to the Enterprise SOC Platform. Designed specifically for controlled laboratory environments, the SOAR engine enables automated triage, enrichment, and response workflows while enforcing safety boundaries, analyst approval gates, and immutable execution logging.

```
       Alert / Incident / IOC Context
                     ↓
             Playbook Engine
                     ↓
          Condition Evaluation Engine
                     ↓
      Risk-Based Approval Gate (PENDING_APPROVAL)
                     ↓
             Action Execution
   (SIMULATION / LAB / NOT_CONFIGURED Adapter)
                     ↓
             Action Verification
                     ↓
      Immutable Audit & Execution Log
```

---

## Core Principles & Safety Controls

1. **Explicit Honest Status Output**:
   - Simulated actions in `SIMULATION` / `LAB` mode return status `SIMULATED_SUCCESS`.
   - Real endpoint containment adapters (EDR, Windows AD, Linux SSH, Firewalls) return `NOT_CONFIGURED` without claiming real-world containment.
   - Execution mode defaults strictly to `SIMULATION`.

2. **Analyst Approval Gates**:
   - High and Critical risk actions (`ISOLATE_HOST`, `DISABLE_ACCOUNT`) require explicit analyst approval via `POST /api/v1/playbook-executions/{id}/approve`.
   - Actions pause in `PENDING_APPROVAL` status until an analyst with `playbook.approve` permission approves or rejects the execution.

3. **Idempotency Guard**:
   - Every playbook execution supports an `idempotency_key`.
   - Re-submitting the same idempotency key returns the cached execution log without executing duplicate response actions.

4. **Secret Scrubbing**:
   - All credentials, API tokens, passwords, and private keys are scrubbed automatically before persistence into the database or audit logs.

5. **Failure Isolation**:
   - Playbook execution failures are caught gracefully per action step, logging an error status without causing pipeline crashes or interrupting telemetry ingestion.

---

## System Architecture

| Component | Class / Module | Purpose |
|---|---|---|
| **Playbook Engine** | `PlaybookEngine` (`src/playbooks.py`) | Core engine managing playbook definitions, condition evaluation, execution, and state transitions. |
| **Action Framework** | `BaseAction` (`src/soar/actions.py`) | Abstract class for response actions with `execute()` and `rollback()` interfaces. |
| **Endpoint Adapters** | `BaseEndpointAdapter` (`src/soar/actions.py`) | Safe adapters returning `NOT_CONFIGURED` state when live endpoints are disconnected. |
| **Database Store** | `playbooks` & `playbook_executions` (`src/database.py`) | Persistent SQLite storage for playbooks and append-only execution logs. |
| **RBAC Security** | `ROLES_PERMISSIONS` (`src/security.py`) | Granular RBAC permissions for playbook execution, approval, and management. |
| **REST API** | `api.py` (`src/api.py`) | FastAPI endpoints for SOAR operations. |
| **Web UI Console** | `web_ui.py` (`src/web_ui.py`) | Visual management catalog, execution log, and approval gate. |
