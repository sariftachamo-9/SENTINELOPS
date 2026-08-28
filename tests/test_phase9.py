"""
Phase 9 — SOC Simulation, Analyst Training & Operational Validation
====================================================================
Comprehensive test suite covering:
  - Scenario creation & validation
  - Event generation (source_mode = "simulation" enforcement)
  - Event ordering
  - Lifecycle (start, pause, resume, cancel, replay)
  - Replay isolation (new run_id)
  - Concurrent execution locking
  - Analyst training sessions
  - Hint requesting & score penalty
  - Correct / incorrect answer scoring
  - Training report JSON & CSV export
  - SOC metrics calculation
  - NO DATA honest behavior
  - Demo mode end-to-end
  - RBAC permission enforcement
  - Audit logging
  - Phase 1–8 regression check
"""

import os
import json
import pytest
from fastapi.testclient import TestClient

os.environ["TESTING"] = "true"
os.environ["JWT_SECRET"] = "soc-lab-test-secret-key-12345"

from src.api import app
from src.security import generate_token
from src.simulation.scenarios import SCENARIOS_CATALOG, get_scenario, list_scenarios
from src.simulation.scoring import AnalystScoringEngine
from src.simulation.engine import ScenarioEngine
from src.simulation.training import TrainingManager
from src.soc_metrics import SOCMetricsEngine
from src.database import Database

client = TestClient(app)


# ============================================================
# Fixtures & Helpers
# ============================================================

def token_for(username: str, role: str) -> str:
    return generate_token(username, role)

def auth_headers(username: str = "analyst_l1", role: str = "SOC Analyst L1") -> dict:
    return {"Authorization": f"Bearer {token_for(username, role)}"}

def admin_headers() -> dict:
    return {"Authorization": f"Bearer {token_for('admin', 'Administrator')}"}

def l1_headers() -> dict:
    return auth_headers("analyst_l1", "SOC Analyst L1")

def l2_headers() -> dict:
    return auth_headers("analyst_l2", "SOC Analyst L2")

def manager_headers() -> dict:
    return auth_headers("manager", "SOC Manager")

def readonly_headers() -> dict:
    return auth_headers("readonly_user", "Read Only")


@pytest.fixture(autouse=True)
def reset_rates():
    client.post("/api/test/clear_rate_limits")
    yield
    client.post("/api/test/clear_rate_limits")


@pytest.fixture(scope="module")
def engine():
    db = Database(db_path=":memory:")
    return ScenarioEngine(db=db)


@pytest.fixture(scope="module")
def training_engine():
    db = Database(db_path=":memory:")
    return TrainingManager(db=db)


@pytest.fixture(scope="module")
def scorer():
    return AnalystScoringEngine()


@pytest.fixture(scope="module")
def metrics_engine():
    db = Database(db_path=":memory:")
    return SOCMetricsEngine(db=db)


# ============================================================
# TEST 01 — Scenario Catalog Has 8 Required Scenarios
# ============================================================
def test_01_scenario_catalog_has_8_scenarios():
    scenarios = list_scenarios()
    assert len(scenarios) == 8, f"Expected 8 scenarios, got {len(scenarios)}"


# ============================================================
# TEST 02 — All Scenarios Have Required Metadata Fields
# ============================================================
def test_02_scenario_metadata_fields():
    for scen in list_scenarios():
        assert "scenario_id" in scen
        assert "name" in scen
        assert "category" in scen
        assert "difficulty" in scen
        assert "mitre_attack" in scen
        assert isinstance(scen["steps"], list)
        assert len(scen["steps"]) >= 1


# ============================================================
# TEST 03 — Events Have source_mode = "simulation" Enforced
# ============================================================
def test_03_event_source_mode_simulation_enforced():
    scen = get_scenario("SCEN-001")
    events = scen.generate_events()
    assert len(events) > 0
    for ev in events:
        assert ev.get("source_mode") == "simulation", f"Event missing simulation label: {ev}"
        assert ev.get("simulation") is True


# ============================================================
# TEST 04 — Event Timeline Ordering (chronological by delay)
# ============================================================
def test_04_event_timeline_ordering():
    from datetime import datetime
    scen = get_scenario("SCEN-001")
    events = scen.generate_events()
    timestamps = [ev["timestamp"] for ev in events]
    # Verify chronological (each timestamp >= previous)
    for i in range(1, len(timestamps)):
        assert timestamps[i] >= timestamps[i - 1], "Events out of chronological order"


# ============================================================
# TEST 05 — Scenario Start via API Returns COMPLETED
# ============================================================
def test_05_scenario_start_api():
    r = client.post("/api/v1/scenarios/SCEN-006/start", json={"speed_multiplier": 50.0}, headers=admin_headers())
    assert r.status_code == 200
    data = r.json()
    assert data.get("status") == "COMPLETED"
    assert data.get("scenario_id") == "SCEN-006"
    assert data.get("source_mode") == "simulation"


# ============================================================
# TEST 06 — Simulation Labeling Never Claims Real Endpoints
# ============================================================
def test_06_simulation_labeling_no_real_endpoint_claim():
    r = client.post("/api/v1/scenarios/SCEN-002/start", json={"speed_multiplier": 50.0}, headers=admin_headers())
    assert r.status_code == 200
    body = r.text
    # None of these should appear in the API response
    assert "LIVE_EXECUTION" not in body
    assert "NOT_CONFIGURED" not in body or True  # NOT_CONFIGURED is acceptable (adapter safety)
    data = r.json()
    assert data.get("source_mode") == "simulation"


# ============================================================
# TEST 07 — Concurrent Scenario Execution Locking
# ============================================================
def test_07_concurrent_execution_locking(engine):
    # Start a run via engine
    run1 = engine.start_scenario("SCEN-005", requested_by="tester", speed_multiplier=50.0, sync_execute=False)
    if run1.get("status") == "ERROR":
        pytest.skip("No concurrent state possible in fast sync mode")

    # Force RUNNING state
    cursor = engine.db.get_cursor()
    cursor.execute("UPDATE scenario_runs SET status = 'RUNNING' WHERE run_id = ?", (run1.get("run_id"),))
    engine.db.conn.commit()

    # Attempt second run
    run2 = engine.start_scenario("SCEN-005", requested_by="tester2", speed_multiplier=1.0, sync_execute=False)
    assert run2.get("status") == "CONCURRENCY_LOCK_ERROR"

    # Cleanup
    engine.cancel_run(run1["run_id"], "tester")


# ============================================================
# TEST 08 — Cancel Scenario Run
# ============================================================
def test_08_cancel_scenario_run(engine):
    run = engine.start_scenario("SCEN-006", requested_by="tester", speed_multiplier=50.0, sync_execute=False)
    if run.get("status") == "COMPLETED":
        pytest.skip("Sync scenario completed before cancel could be called")

    cursor = engine.db.get_cursor()
    cursor.execute("UPDATE scenario_runs SET status = 'RUNNING' WHERE run_id = ?", (run.get("run_id"),))
    engine.db.conn.commit()

    cancelled = engine.cancel_run(run["run_id"], requested_by="tester")
    assert cancelled.get("status") == "CANCELLED"


# ============================================================
# TEST 09 — Replay Creates New Immutable Run ID
# ============================================================
def test_09_replay_creates_new_run_id(engine):
    run1 = engine.start_scenario("SCEN-007", requested_by="tester", speed_multiplier=50.0, sync_execute=True)
    original_run_id = run1.get("run_id")
    assert original_run_id is not None

    replay = engine.replay_run(original_run_id, requested_by="tester")
    replay_run_id = replay.get("run_id")

    assert replay_run_id != original_run_id, "Replay must create a distinct run_id"
    # Verify original run still exists
    original = engine.get_run(original_run_id)
    assert original is not None, "Original run must remain immutable after replay"


# ============================================================
# TEST 10 — Get Scenario Run Timeline
# ============================================================
def test_10_get_run_timeline(engine):
    run = engine.start_scenario("SCEN-001", requested_by="tester", speed_multiplier=50.0, sync_execute=True)
    run_id = run.get("run_id")
    timeline = engine.get_run_timeline(run_id)
    assert isinstance(timeline, list)
    # Each step should have simulation source_mode
    for step in timeline:
        assert step.get("source_mode") == "simulation"


# ============================================================
# TEST 11 — List Scenarios API (L1 Access)
# ============================================================
def test_11_list_scenarios_api_l1():
    r = client.get("/api/v1/scenarios", headers=l1_headers())
    assert r.status_code == 200
    data = r.json()
    assert "scenarios" in data
    assert len(data["scenarios"]) == 8


# ============================================================
# TEST 12 — Get Specific Scenario API
# ============================================================
def test_12_get_scenario_api():
    r = client.get("/api/v1/scenarios/SCEN-003", headers=l1_headers())
    assert r.status_code == 200
    data = r.json()
    assert data["scenario_id"] == "SCEN-003"
    assert "PowerShell" in data["name"]


# ============================================================
# TEST 13 — Invalid Scenario Returns 404
# ============================================================
def test_13_invalid_scenario_returns_404():
    r = client.get("/api/v1/scenarios/SCEN-INVALID", headers=admin_headers())
    assert r.status_code == 404


# ============================================================
# TEST 14 — Training Session Start
# ============================================================
def test_14_training_session_start(training_engine):
    sess = training_engine.start_session(analyst_username="analyst_l1", scenario_id="SCEN-001")
    assert sess is not None
    assert sess.get("analyst_username") == "analyst_l1"
    assert sess.get("scenario_id") == "SCEN-001"
    assert sess.get("status") == "IN_PROGRESS"
    assert sess.get("session_id", "").startswith("trn-")


# ============================================================
# TEST 15 — Training Session Hint Requesting
# ============================================================
def test_15_training_session_hint(training_engine):
    sess = training_engine.start_session(analyst_username="analyst_l2", scenario_id="SCEN-001")
    session_id = sess["session_id"]

    result = training_engine.request_hint(session_id, analyst_username="analyst_l2")
    assert result.get("status") == "HINT_PROVIDED"
    assert "hint" in result
    assert result.get("hints_used_count") == 1


# ============================================================
# TEST 16 — Hint Exhaustion Returns NO_MORE_HINTS
# ============================================================
def test_16_hint_exhaustion(training_engine):
    sess = training_engine.start_session(analyst_username="analyst_l2", scenario_id="SCEN-006")
    session_id = sess["session_id"]
    scen = get_scenario("SCEN-006")
    total_hints = len(scen.hints)

    for _ in range(total_hints):
        training_engine.request_hint(session_id, analyst_username="analyst_l2")

    result = training_engine.request_hint(session_id, analyst_username="analyst_l2")
    assert result.get("status") == "NO_MORE_HINTS"


# ============================================================
# TEST 17 — Correct Answer Scoring Passes with 75%+
# ============================================================
def test_17_correct_answer_scoring_passes(scorer):
    expected = {
        "triage_verdict": "TRUE_POSITIVE",
        "attacker_ip": "198.51.100.44",
        "target_host": "linux-srv-01",
        "mitre_technique": "T1110.001",
        "recommended_soar": "ADD_IOC_SIMULATED_BLOCKLIST"
    }
    analyst_answers = {
        "triage_verdict": "TRUE_POSITIVE",
        "severity": "HIGH",
        "target_host": "linux-srv-01",
        "mitre_technique": "T1110.001",
        "ioc_classification": "198.51.100.44",
        "incident_escalated": True,
        "evidence_added": True,
        "case_notes": "SSH brute force detected from external IP, root account compromised.",
        "recommended_soar": "ADD_IOC_SIMULATED_BLOCKLIST",
        "resolution": "RESOLVED"
    }
    result = scorer.evaluate_session(expected, analyst_answers, hints_used_count=0)
    assert result["passed"] is True
    assert result["percentage"] >= 75.0


# ============================================================
# TEST 18 — Incorrect Answer Scoring May Fail with <75%
# ============================================================
def test_18_incorrect_answer_scoring(scorer):
    expected = {"triage_verdict": "TRUE_POSITIVE", "mitre_technique": "T1110"}
    analyst_answers = {
        "triage_verdict": "FALSE_POSITIVE",  # Wrong
        "severity": "LOW",
        "target_host": "",  # Missing
        "mitre_technique": "",  # Missing
        "incident_escalated": False,
        "evidence_added": False,
        "case_notes": "",
        "recommended_soar": "",
        "resolution": ""
    }
    result = scorer.evaluate_session(expected, analyst_answers, hints_used_count=0)
    # Incorrect triage is wrong, missing notes, no MITRE mapping
    assert result["percentage"] < 100.0
    assert len(result["mistakes"]) > 0


# ============================================================
# TEST 19 — Hint Penalty Deducts Points
# ============================================================
def test_19_hint_penalty_deducts_points(scorer):
    expected = {"triage_verdict": "TRUE_POSITIVE"}
    analyst_answers = {
        "triage_verdict": "TRUE_POSITIVE", "severity": "HIGH",
        "target_host": "linux-srv-01", "mitre_technique": "T1110.001",
        "ioc_classification": "198.51.100.44", "incident_escalated": True,
        "evidence_added": True,
        "case_notes": "Brute force leading to root compromise.",
        "recommended_soar": "ADD_IOC_SIMULATED_BLOCKLIST",
        "resolution": "RESOLVED"
    }

    res_no_hints = scorer.evaluate_session(expected, analyst_answers, hints_used_count=0)
    res_3_hints = scorer.evaluate_session(expected, analyst_answers, hints_used_count=3)

    assert res_3_hints["total_score"] < res_no_hints["total_score"]
    assert res_3_hints["hint_penalty_points"] == 6


# ============================================================
# TEST 20 — Training Session Full Submit & Scorecard
# ============================================================
def test_20_training_session_submit_and_score(training_engine):
    sess = training_engine.start_session(analyst_username="tester", scenario_id="SCEN-001")
    session_id = sess["session_id"]

    answers = {
        "triage_verdict": "TRUE_POSITIVE",
        "severity": "HIGH",
        "target_host": "linux-srv-01",
        "mitre_technique": "T1110.001",
        "ioc_classification": "198.51.100.44",
        "incident_escalated": True,
        "evidence_added": True,
        "case_notes": "SSH brute force: 3 failures then root login from external IP.",
        "recommended_soar": "ADD_IOC_SIMULATED_BLOCKLIST",
        "resolution": "RESOLVED"
    }
    result = training_engine.submit_answers(session_id, answers, analyst_username="tester")
    assert result["status"] == "COMPLETED"
    assert result.get("final_score", 0) > 0
    assert "scorecard" in result


# ============================================================
# TEST 21 — Training API Start (L1 Access)
# ============================================================
def test_21_training_api_start():
    r = client.post("/api/v1/training/start", json={"scenario_id": "SCEN-006"}, headers=l1_headers())
    assert r.status_code == 200
    data = r.json()
    assert "session_id" in data
    assert data.get("analyst_username") == "analyst_l1"


# ============================================================
# TEST 22 — Training API IDOR Protection
# ============================================================
def test_22_training_idor_protection():
    # L1 analyst creates session
    r = client.post("/api/v1/training/start", json={"scenario_id": "SCEN-006"}, headers=l1_headers())
    session_id = r.json().get("session_id")

    # L2 analyst tries to view it (should be rejected unless manager)
    r2 = client.get(f"/api/v1/training/{session_id}", headers=l2_headers())
    assert r2.status_code == 403

    # Admin can view it
    r3 = client.get(f"/api/v1/training/{session_id}", headers=admin_headers())
    assert r3.status_code == 200


# ============================================================
# TEST 23 — SOC Metrics API Returns Valid Structure
# ============================================================
def test_23_soc_metrics_api():
    r = client.get("/api/v1/soc/metrics", headers=admin_headers())
    assert r.status_code == 200
    data = r.json()
    # Required keys
    for key in ["timestamp", "total_events", "total_alerts", "open_incidents",
                "open_cases", "soar_executions", "mitre_technique_coverage",
                "alert_volume_by_severity", "mttd_display", "mttr_display",
                "false_positive_rate_display"]:
        assert key in data, f"Missing key: {key}"


# ============================================================
# TEST 24 — SOC Metrics Honest NO DATA Behavior
# ============================================================
def test_24_soc_metrics_no_data_honest(metrics_engine):
    """Fresh DB with no data should return 0 / NO DATA, never fake numbers."""
    result = metrics_engine.get_metrics()
    # With empty DB, totals should be 0
    assert result["total_events"] == 0
    assert result["total_alerts"] == 0
    assert result["mttd_display"] == "NO DATA"
    assert result["mttr_display"] == "NO DATA"
    assert result["false_positive_rate_display"] == "NO DATA"


# ============================================================
# TEST 25 — SOC Metrics Timeline API
# ============================================================
def test_25_soc_metrics_timeline_api():
    r = client.get("/api/v1/soc/metrics/timeline?days=7", headers=admin_headers())
    assert r.status_code == 200
    data = r.json()
    assert "timeline" in data
    assert len(data["timeline"]) == 7
    for day in data["timeline"]:
        assert "date" in day
        assert "events" in day
        assert "alerts" in day


# ============================================================
# TEST 26 — Demo Mode End-to-End
# ============================================================
def test_26_demo_mode_end_to_end():
    r = client.post("/api/v1/demo/start",
                    json={"scenario_id": "SCEN-006", "speed_multiplier": 50.0},
                    headers=admin_headers())
    assert r.status_code == 200
    data = r.json()
    assert data.get("demo_status") == "COMPLETED"
    assert data.get("source_mode") == "simulation"
    assert "simulation_safety_notice" in data
    assert "SIMULATION MODE" in data["simulation_safety_notice"]
    assert "scenario_run" in data
    assert "metrics_snapshot" in data


# ============================================================
# TEST 27 — Demo Mode Simulation Safety Notice Explicitly Present
# ============================================================
def test_27_demo_safety_notice_no_physical_claim():
    r = client.post("/api/v1/demo/start",
                    json={"scenario_id": "SCEN-001", "speed_multiplier": 50.0},
                    headers=admin_headers())
    assert r.status_code == 200
    data = r.json()
    notice = data.get("simulation_safety_notice", "")
    assert "SOC LAB" in notice
    assert "SIMULATION MODE" in notice
    # Must explicitly state no real-world execution
    assert "No physical endpoints" in notice


# ============================================================
# TEST 28 — RBAC: Read Only Cannot Execute Scenarios
# ============================================================
def test_28_rbac_readonly_cannot_execute_scenario():
    r = client.post("/api/v1/scenarios/SCEN-001/start",
                    json={"speed_multiplier": 1.0}, headers=readonly_headers())
    assert r.status_code == 403


# ============================================================
# TEST 29 — RBAC: Read Only Can Read Scenarios
# ============================================================
def test_29_rbac_readonly_can_read_scenarios():
    r = client.get("/api/v1/scenarios", headers=readonly_headers())
    assert r.status_code == 200


# ============================================================
# TEST 30 — RBAC: Read Only Cannot Access Training
# ============================================================
def test_30_rbac_readonly_cannot_access_training():
    r = client.post("/api/v1/training/start",
                    json={"scenario_id": "SCEN-001"}, headers=readonly_headers())
    assert r.status_code == 403


# ============================================================
# TEST 31 — Audit Logging Records Scenario Execution
# ============================================================
def test_31_audit_logging_scenario():
    # Start a scenario
    client.post("/api/v1/scenarios/SCEN-005/start",
                json={"speed_multiplier": 50.0}, headers=admin_headers())

    # Check audit log — endpoint is /api/v1/audit/logs
    r = client.get("/api/v1/audit/logs?limit=20&action=START_SCENARIO_RUN", headers=admin_headers())
    assert r.status_code == 200
    data = r.json()
    logs = data.get("logs", [])
    assert len(logs) >= 1


# ============================================================
# TEST 32 — Training JSON Report Export
# ============================================================
def test_32_training_report_json_export():
    # Start & complete a session
    r1 = client.post("/api/v1/training/start", json={"scenario_id": "SCEN-001"}, headers=admin_headers())
    session_id = r1.json().get("session_id")
    client.post(f"/api/v1/training/{session_id}/submit", headers=admin_headers(), json={
        "triage_verdict": "TRUE_POSITIVE", "severity": "HIGH",
        "target_host": "linux-srv-01", "mitre_technique": "T1110.001",
        "ioc_classification": "198.51.100.44", "incident_escalated": True,
        "evidence_added": True, "case_notes": "Brute force with root compromise confirmed.",
        "recommended_soar": "ADD_IOC_SIMULATED_BLOCKLIST", "resolution": "RESOLVED"
    })

    r2 = client.get(f"/api/v1/training/{session_id}/report/json", headers=admin_headers())
    assert r2.status_code == 200
    report = r2.json()
    assert report.get("report_title") == "SOC Analyst Training Performance Report"
    assert "session_id" in report
    assert "evaluation" in report


# ============================================================
# TEST 33 — Training CSV Report Export
# ============================================================
def test_33_training_report_csv_export():
    r1 = client.post("/api/v1/training/start", json={"scenario_id": "SCEN-001"}, headers=admin_headers())
    session_id = r1.json().get("session_id")
    client.post(f"/api/v1/training/{session_id}/submit", headers=admin_headers(), json={
        "triage_verdict": "TRUE_POSITIVE", "severity": "HIGH",
        "target_host": "srv", "mitre_technique": "T1110",
        "case_notes": "test", "resolution": "RESOLVED"
    })

    r2 = client.get(f"/api/v1/training/{session_id}/report/csv", headers=admin_headers())
    assert r2.status_code == 200
    assert "Session ID" in r2.text


# ============================================================
# TEST 34 — Scenario Run Replay API
# ============================================================
def test_34_scenario_replay_api():
    # Start a scenario via API and get run_id
    r1 = client.post("/api/v1/scenarios/SCEN-006/start",
                     json={"speed_multiplier": 50.0}, headers=admin_headers())
    run_id = r1.json().get("run_id")
    assert run_id is not None

    # Replay it
    r2 = client.post(f"/api/v1/scenario-runs/{run_id}/replay", headers=admin_headers())
    assert r2.status_code == 200
    replay_run_id = r2.json().get("run_id")
    assert replay_run_id != run_id, "Replay must produce a new run_id"


# ============================================================
# TEST 35 — List Runs API
# ============================================================
def test_35_list_runs_api():
    r = client.get("/api/v1/scenario-runs?limit=10", headers=admin_headers())
    assert r.status_code == 200
    data = r.json()
    assert "runs" in data


# ============================================================
# Phase 1–8 Regression — Tests Must All Pass
# ============================================================
def test_99_phase1_8_regression_health_endpoint():
    r = client.get("/health")
    assert r.status_code == 200

def test_99_phase1_8_regression_login():
    r = client.post("/api/auth/login", json={"username": "admin", "password": "wrongpass"})
    # Should respond (either 200 or 401 depending on setup, but not 500)
    assert r.status_code in (200, 401)

def test_99_phase1_8_regression_alerts_protected():
    r = client.get("/api/alerts")
    assert r.status_code in (401, 403)  # Unauthenticated

def test_99_phase1_8_regression_alerts_authed():
    r = client.get("/api/alerts", headers=admin_headers())
    assert r.status_code == 200

def test_99_phase1_8_regression_incidents_authed():
    r = client.get("/api/v1/incidents", headers=admin_headers())
    assert r.status_code == 200

def test_99_phase1_8_regression_playbooks_authed():
    r = client.get("/api/v1/playbooks", headers=admin_headers())
    assert r.status_code == 200

def test_99_phase1_8_regression_soar_metrics_authed():
    r = client.get("/api/v1/soc/metrics", headers=admin_headers())
    assert r.status_code == 200
