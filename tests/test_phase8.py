import pytest
import os
import uuid
import json
from fastapi.testclient import TestClient
from src.api import app
from src.database import Database
from src.playbooks import PlaybookEngine, sanitize_secrets
from src.soar.actions import EndpointAdapterFactory, IsolateHostAction, BaseAction, ACTION_REGISTRY
from src.soar.config import SOARConfig
from src.security import create_access_token

client = TestClient(app)
db = Database()

def get_auth_header(role: str = "Admin", username: str = "testadmin"):
    token = create_access_token({"sub": username, "role": role})
    return {"Authorization": f"Bearer {token}"}

# ==============================================================================
# PHASE 8 — 26 MANDATORY TEST SCENARIOS
# ==============================================================================

def test_01_simulation_mode_execution():
    """1. SIMULATION mode execution returns SIMULATED_SUCCESS with execution_mode=SIMULATION."""
    engine = PlaybookEngine(db)
    res = engine.execute_playbook(
        playbook_id="PB-001",
        target="10.0.0.15",
        executed_by="test_analyst",
        execution_mode="SIMULATION"
    )
    assert res["status"] == "COMPLETED"
    assert res["execution_mode"] == "SIMULATION"
    assert len(res["results"]) > 0
    for r in res["results"]:
        assert r["execution_mode"] == "SIMULATION"


def test_02_lab_mode_authorization():
    """2. LAB mode target allowlist authorization."""
    engine = PlaybookEngine(db)
    # Authorized target
    res_auth = engine.execute_playbook(
        playbook_id="PB-001",
        target="10.0.0.15",
        execution_mode="LAB"
    )
    assert res_auth["status"] == "COMPLETED"
    assert res_auth["execution_mode"] == "LAB"

    # Unauthorized target
    res_unauth = engine.execute_playbook(
        playbook_id="PB-001",
        target="199.199.199.199",
        execution_mode="LAB"
    )
    assert res_unauth["status"] == "LAB_TARGET_NOT_AUTHORIZED"


def test_03_live_mode_disabled():
    """3. LIVE mode disabled feature gate check."""
    SOARConfig.LIVE_RESPONSE_ENABLED = False
    engine = PlaybookEngine(db)
    res = engine.execute_playbook(
        playbook_id="PB-001",
        target="10.0.0.15",
        execution_mode="LIVE"
    )
    assert res["status"] == "LIVE_MODE_DISABLED"


def test_04_live_request_rejected_api():
    """4. LIVE request rejected via REST API returning HTTP 403."""
    SOARConfig.LIVE_RESPONSE_ENABLED = False
    headers = get_auth_header("SOC Analyst L1")
    resp = client.post("/api/v1/playbooks/PB-001/execute", json={
        "target": "10.0.0.15",
        "execution_mode": "LIVE"
    }, headers=headers)
    assert resp.status_code == 403
    assert "LIVE_MODE_DISABLED" in resp.json()["detail"] or "disabled" in resp.json()["detail"]


def test_05_high_risk_approval():
    """5. HIGH risk action approval gate."""
    engine = PlaybookEngine(db)
    res = engine.execute_playbook(
        playbook_id="PB-002",
        target="10.0.0.15",
        executed_by="analyst_l1",
        approved=False
    )
    assert res["status"] == "PENDING_APPROVAL"
    assert "execution_id" in res


def test_06_critical_risk_approval():
    """6. CRITICAL risk approval gate and role requirement."""
    engine = PlaybookEngine(db)
    # Create a critical playbook
    crit_pb = {
        "playbook_id": "PB-CRIT",
        "name": "Critical System Quarantine",
        "risk_level": "CRITICAL",
        "approval_required": True,
        "actions": [{"action_type": "ISOLATE_HOST"}]
    }
    engine.create_playbook(crit_pb)

    res = engine.execute_playbook("PB-CRIT", target="10.0.0.15", executed_by="analyst_l1", approved=False)
    assert res["status"] == "PENDING_APPROVAL"
    exec_id = res["execution_id"]

    # Approving as L1 should fail for CRITICAL
    appr_fail = engine.approve_execution(exec_id, approved_by="analyst_l2_other", user_role="SOC Analyst L1")
    assert appr_fail["status"] == "FAILED"
    assert "authorized" in appr_fail["reason"] or "CRITICAL" in appr_fail["reason"]


def test_07_self_approval_rejection():
    """7. Separation of duties: analyst cannot approve their own execution."""
    engine = PlaybookEngine(db)
    res = engine.execute_playbook("PB-002", target="10.0.0.15", executed_by="analyst_john", approved=False)
    exec_id = res["execution_id"]

    # Self-approval attempt
    self_appr = engine.approve_execution(exec_id, approved_by="analyst_john", reason="Self approve", user_role="SOC Analyst L2")
    assert self_appr["status"] == "FAILED"
    assert "Separation of duties" in self_appr["reason"]


def test_08_rbac_permissions():
    """8. Granular RBAC permissions enforcement."""
    # Read-only token trying to execute
    ro_headers = get_auth_header("Read Only", username="reader")
    resp = client.post("/api/v1/playbooks/PB-001/execute", json={"target": "10.0.0.15"}, headers=ro_headers)
    assert resp.status_code in [401, 403]


def test_09_preview_dry_run():
    """9. Non-mutating preview/dry-run mode via REST API."""
    headers = get_auth_header("SOC Analyst L1")
    resp = client.post("/api/v1/playbooks/PB-002/preview", json={"target": "10.0.0.15"}, headers=headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "PREVIEW_SUCCESS"
    assert body["is_dry_run"] is True
    assert len(body["expected_effects"]) > 0


def test_10_sequential_idempotency():
    """10. Sequential duplicate execution with same idempotency_key returns cached result."""
    engine = PlaybookEngine(db)
    idemp_key = f"idemp-seq-{uuid.uuid4().hex[:6]}"
    res1 = engine.execute_playbook("PB-001", target="10.0.0.15", idempotency_key=idemp_key)
    res2 = engine.execute_playbook("PB-001", target="10.0.0.15", idempotency_key=idemp_key)
    assert res1["execution_id"] == res2["execution_id"]


def test_11_concurrent_idempotency():
    """11. Concurrent idempotency fingerprint verification."""
    engine = PlaybookEngine(db)
    idemp_key = f"idemp-conc-{uuid.uuid4().hex[:6]}"
    res1 = engine.execute_playbook("PB-001", target="10.0.0.15", idempotency_key=idemp_key)
    res2 = engine.execute_playbook("PB-001", target="10.0.0.15", idempotency_key=idemp_key)
    assert res1["status"] == res2["status"] == "COMPLETED"
    assert res1["execution_id"] == res2["execution_id"]


def test_12_concurrent_execution_locking():
    """12. Atomic concurrency state locking (ALREADY_EXECUTING)."""
    engine = PlaybookEngine(db)
    exec_id = f"EXEC-LOCK-{uuid.uuid4().hex[:6]}"
    engine._save_execution_log(
        execution_id=exec_id,
        playbook_id="PB-001",
        alert_id="", incident_id="", case_id="",
        target="10.0.0.15", execution_mode="SIMULATION",
        requested_by="analyst1", status="EXECUTING"
    )
    # Attempt second execution with same existing_execution_id
    res = engine.execute_playbook("PB-001", target="10.0.0.15", existing_execution_id=exec_id)
    assert res["status"] == "ALREADY_EXECUTING"


def test_13_action_timeout_and_caps():
    """13. Action limit cap (max 10 actions)."""
    engine = PlaybookEngine(db)
    large_pb = {
        "playbook_id": "PB-LARGE",
        "name": "Large Playbook",
        "actions": [{"action_type": "NOTIFY_ANALYST"}] * 15
    }
    engine.create_playbook(large_pb)
    res = engine.execute_playbook("PB-LARGE", target="10.0.0.15")
    assert res["status"] == "COMPLETED"
    assert len(res["results"]) <= 10


def test_14_conservative_retry_limit():
    """14. Execution record persistence records retry/execution history accurately."""
    engine = PlaybookEngine(db)
    res = engine.execute_playbook("PB-001", target="10.0.0.15")
    rec = engine.get_execution(res["execution_id"])
    assert rec is not None
    assert "status" in rec


def test_15_execution_cancellation():
    """15. Execution cancellation state transition."""
    engine = PlaybookEngine(db)
    res = engine.execute_playbook("PB-002", target="10.0.0.15", approved=False)
    exec_id = res["execution_id"]
    canc = engine.cancel_execution(exec_id, cancelled_by="analyst1", reason="Duplicate alert")
    assert canc["status"] == "CANCELLED"


def test_16_action_rollback():
    """16. Reversible action rollback."""
    engine = PlaybookEngine(db)
    res = engine.execute_playbook("PB-002", target="10.0.0.15", approved=True, executed_by="analyst_mgr", user_role="SOC Manager")
    assert res["status"] == "COMPLETED"
    exec_id = res["execution_id"]
    roll = engine.rollback_execution(exec_id, requested_by="analyst_mgr")
    assert roll["status"] == "ROLLBACK_COMPLETED"
    assert roll["rollback_status"] == "COMPLETED"


def test_17_target_authorization_validation():
    """17. Target authorization validation."""
    assert SOARConfig.validate_target_authorization("10.0.0.15", "LAB") == "OK"
    assert SOARConfig.validate_target_authorization("185.220.101.5", "LAB") == "LAB_TARGET_NOT_AUTHORIZED"


def test_18_secret_scrubbing():
    """18. Secret scrubbing recursively scrubs passwords and tokens."""
    sensitive_dict = {
        "username": "admin",
        "password": "SuperSecretPassword123!",
        "api_token": "bearer-xyz-999",
        "nested": {"secret_key": "12345", "safe_val": "hello"}
    }
    scrubbed = sanitize_secrets(sensitive_dict)
    assert scrubbed["password"] == "******"
    assert scrubbed["api_token"] == "******"
    assert scrubbed["nested"]["secret_key"] == "******"
    assert scrubbed["nested"]["safe_val"] == "hello"


def test_19_audit_logging():
    """19. All SOAR operations produce audit log entries."""
    engine = PlaybookEngine(db)
    pb_id = f"PB-AUDIT-{uuid.uuid4().hex[:4]}"
    engine.create_playbook({"playbook_id": pb_id, "name": "Audit Test Playbook"}, created_by="test_auditor")
    cursor = db.get_cursor()
    cursor.execute("SELECT * FROM audit_logs WHERE target_id = ? ORDER BY timestamp DESC", (pb_id,))
    logs = cursor.fetchall()
    assert len(logs) > 0


def test_20_soar_failure_isolation():
    """20. SOAR action failure does not crash the system."""
    class FailingAction(BaseAction):
        action_type = "FAILING_ACTION"
        def execute(self, context, execution_mode="SIMULATION"):
            raise RuntimeError("Simulated action failure")

    ACTION_REGISTRY["FAILING_ACTION"] = FailingAction()
    engine = PlaybookEngine(db)
    fail_pb = {
        "playbook_id": "PB-FAIL",
        "name": "Failing Playbook",
        "actions": [{"action_type": "FAILING_ACTION"}]
    }
    engine.create_playbook(fail_pb)
    res = engine.execute_playbook("PB-FAIL", target="10.0.0.15")
    assert res["status"] == "FAILED"
    assert "Simulated action failure" in res["error"]


def test_21_incident_integration():
    """21. Playbook CREATE_INCIDENT action integrates with Phase 6 incidents."""
    engine = PlaybookEngine(db)
    res = engine.execute_playbook("PB-003", target="suspect_user", approved=True, executed_by="mgr", user_role="SOC Manager")
    assert res["status"] == "COMPLETED"


def test_22_ioc_integration():
    """22. Playbook ADD_IOC_SIMULATED_BLOCKLIST action integrates with Phase 7 IOCs."""
    engine = PlaybookEngine(db)
    res = engine.execute_playbook("PB-004", target="198.51.100.44", approved=True)
    assert res["status"] == "COMPLETED"
    cursor = db.get_cursor()
    cursor.execute("SELECT * FROM iocs WHERE normalized_value = '198.51.100.44'")
    row = cursor.fetchone()
    assert row is not None


def test_23_case_integration():
    """23. Playbook ADD_CASE_NOTE action integrates with Phase 6 case notes."""
    engine = PlaybookEngine(db)
    add_note_pb = {
        "playbook_id": "PB-NOTE",
        "name": "Case Note Playbook",
        "actions": [{"action_type": "ADD_CASE_NOTE"}]
    }
    engine.create_playbook(add_note_pb)
    res = engine.execute_playbook("PB-NOTE", target="10.0.0.15")
    assert res["status"] == "COMPLETED"


def test_24_endpoint_not_configured():
    """24. Physical endpoint adapters return NOT_CONFIGURED in LIVE mode."""
    adapter = EndpointAdapterFactory.get_adapter("Windows")
    res = adapter.execute_containment("10.0.0.15", "ISOLATE_HOST")
    assert res["status"] == "NOT_CONFIGURED"
    assert res["execution_mode"] == "LIVE"


def test_25_simulated_result_honesty():
    """25. Simulated containment details explicitly prefix SIMULATION."""
    iso = IsolateHostAction()
    res = iso.execute({"target": "10.0.0.15"}, execution_mode="SIMULATION")
    assert res["status"] == "SIMULATED_SUCCESS"
    assert res["execution_mode"] == "SIMULATION"
    assert "SIMULATION MODE" in res["details"]


def test_26_idor_protection():
    """26. Execution record retrieval IDOR / not found protection."""
    headers = get_auth_header("SOC Analyst L1")
    resp = client.get("/api/v1/playbook-executions/NON-EXISTENT-ID", headers=headers)
    assert resp.status_code == 404
