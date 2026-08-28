import pytest
import os
import json
import uuid
from datetime import datetime
from fastapi.testclient import TestClient

from src.database import Database
from src.security import create_access_token
from src.detection_engine import DetectionEngine
from src.correlation_engine import CorrelationEngine
from src.risk_engine import RiskEngine
from src.mitre_coverage import MITRECoverageAnalyzer
from src.telemetry.pipeline import TelemetryPipeline
from src.api import app

os.environ["JWT_SECRET"] = "phase5-test-secret-key-12345"

@pytest.fixture
def test_db(tmp_path):
    db_file = os.path.join(tmp_path, "phase5_test.db")
    db = Database(db_path=db_file)
    yield db
    db.close()

@pytest.fixture
def auth_headers():
    admin_token = create_access_token(data={"sub": "admin_test", "role": "Administrator"})
    analyst_token = create_access_token(data={"sub": "analyst_test", "role": "SOC Analyst L1"})
    engineer_token = create_access_token(data={"sub": "engineer_test", "role": "Detection Engineer"})
    readonly_token = create_access_token(data={"sub": "readonly_test", "role": "Read Only"})
    return {
        "admin": {"Authorization": f"Bearer {admin_token}"},
        "analyst": {"Authorization": f"Bearer {analyst_token}"},
        "engineer": {"Authorization": f"Bearer {engineer_token}"},
        "readonly": {"Authorization": f"Bearer {readonly_token}"}
    }

# 1. Detection Engine Unit Tests
def test_detection_engine_windows_events(test_db):
    engine = DetectionEngine(db=test_db)
    
    # PowerShell Suspicious Execution
    ps_event = {
        "event_id": "EVT-PS-01",
        "timestamp": datetime.now().isoformat(),
        "source_type": "windows",
        "event_type": "Process Creation",
        "hostname": "WIN-SRV-01",
        "username": "Administrator",
        "process_name": "powershell.exe",
        "raw_event": "powershell.exe -Enc QmFzaDY0RW5jb2RlZENvbW1hbmQ="
    }
    matches = engine.evaluate_event(ps_event)
    assert len(matches) >= 1
    assert matches[0]["rule_id"] == "WIN-PS-001"
    assert "Execution" in matches[0]["mitre_tactic"]

    # Mimikatz Execution
    mimi_event = {
        "event_id": "EVT-MIMI-01",
        "timestamp": datetime.now().isoformat(),
        "source_type": "windows",
        "event_type": "Process Creation",
        "hostname": "WIN-SRV-01",
        "username": "SYSTEM",
        "process_name": "mimikatz.exe",
        "raw_event": "mimikatz.exe privilege::debug sekurlsa::logonpasswords"
    }
    matches_mimi = engine.evaluate_event(mimi_event)
    assert len(matches_mimi) >= 1
    assert matches_mimi[0]["rule_id"] == "WIN-PROC-001"

def test_detection_engine_threshold_brute_force(test_db):
    engine = DetectionEngine(db=test_db)
    
    # 4 Failed Logins -> Should NOT trigger threshold rule yet
    for i in range(4):
        event = {
            "event_id": f"EVT-FAIL-{i}",
            "timestamp": datetime.now().isoformat(),
            "source_type": "windows",
            "event_type": "Failed Login",
            "hostname": "WIN-DC-01",
            "username": "target_user",
            "source_ip": "192.168.1.100"
        }
        res = engine.evaluate_event(event)
        assert len(res) == 0

    # 5th Failed Login -> Should trigger WIN-AUTH-001 threshold rule!
    event_5 = {
        "event_id": "EVT-FAIL-4",
        "timestamp": datetime.now().isoformat(),
        "source_type": "windows",
        "event_type": "Failed Login",
        "hostname": "WIN-DC-01",
        "username": "target_user",
        "source_ip": "192.168.1.100"
    }
    res_5 = engine.evaluate_event(event_5)
    assert len(res_5) == 1
    assert res_5[0]["rule_id"] == "WIN-AUTH-001"
    assert len(res_5[0]["triggering_event_ids"]) == 5

def test_detection_engine_linux_and_network_events(test_db):
    engine = DetectionEngine(db=test_db)
    
    # Linux Sudo Command
    sudo_evt = {
        "event_id": "EVT-SUDO-01",
        "timestamp": datetime.now().isoformat(),
        "source_type": "linux",
        "event_type": "Sudo Execution",
        "hostname": "ubuntu-srv",
        "username": "user1",
        "process_name": "sudo",
        "raw_event": "sudo COMMAND=/bin/bash"
    }
    m_sudo = engine.evaluate_event(sudo_evt)
    assert len(m_sudo) >= 1
    assert m_sudo[0]["rule_id"] == "LIN-SUDO-001"

    # Network DNS Tunneling
    dns_evt = {
        "event_id": "EVT-DNS-01",
        "timestamp": datetime.now().isoformat(),
        "source_type": "syslog",
        "event_type": "DNS Tunneling Alert",
        "hostname": "dns-gateway",
        "source_ip": "10.0.0.50",
        "raw_event": "Suspicious high entropy DNS query for c2.exfil-domain.com"
    }
    m_dns = engine.evaluate_event(dns_evt)
    assert len(m_dns) >= 1
    assert m_dns[0]["rule_id"] == "NET-DNS-001"

# 2. Multi-Entity Correlation Unit Tests
def test_correlation_engine_account_compromise(test_db):
    corr = CorrelationEngine(db=test_db)
    source_ip = "198.51.100.45"
    username = "victim_admin"

    # Send 2 failed logins
    for i in range(2):
        f_evt = {
            "event_id": f"EVT-FAIL-CORR-{i}",
            "timestamp": datetime.now().isoformat(),
            "source_type": "windows",
            "event_type": "Failed Login",
            "hostname": "CORP-HOST-01",
            "username": username,
            "source_ip": source_ip
        }
        res = corr.process_event(f_evt)
        assert len(res) == 0

    # Followed by 1 successful login from SAME IP & User -> Account Compromise!
    s_evt = {
        "event_id": "EVT-SUCCESS-CORR",
        "timestamp": datetime.now().isoformat(),
        "source_type": "windows",
        "event_type": "Successful Login",
        "hostname": "CORP-HOST-01",
        "username": username,
        "source_ip": source_ip
    }
    alerts = corr.process_event(s_evt)
    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "CORR-ACCOUNT-COMPROMISE"
    assert alerts[0]["severity"] == "critical"
    assert alerts[0]["confidence"] == 95

# 3. Transparent Risk Engine Unit Tests
def test_risk_engine_breakdown():
    risk_eng = RiskEngine()
    alert_sample = {
        "severity": "critical",
        "confidence": 90,
        "affected_asset": "PROD-DC-01",
        "affected_user": "Administrator",
        "rule_id": "CORR-ACCOUNT-COMPROMISE",
        "triggering_event_ids": ["E1", "E2", "E3"],
        "threat_intel_matched": True
    }
    res = risk_eng.calculate_risk(alert_sample)
    assert res["risk_score"] >= 80
    assert res["risk_level"] == "CRITICAL"
    assert "base_severity" in res["breakdown"]
    assert res["breakdown"]["base_severity"] == 40
    assert res["breakdown"]["account_sensitivity"] == 15
    assert "Risk Score" in res["explanation"]

# 4. Pipeline Integration & Deduplication Test
def test_telemetry_pipeline_deduplication(test_db):
    pipeline = TelemetryPipeline(db=test_db)
    
    raw_event = {
        "event_id": "SYS-MIMI-101",
        "timestamp": datetime.now().isoformat(),
        "source_type": "windows",
        "hostname": "WIN-ENDPOINT-99",
        "username": "Administrator",
        "event_type": "Process Creation",
        "process_name": "mimikatz.exe",
        "raw": "mimikatz sekurlsa::logonpasswords"
    }

    # 1st execution -> Creates 1 alert
    res1 = pipeline.process_event(raw_event, source_type="windows")
    assert res1.stored is True
    assert res1.alerts_triggered >= 1

    # Check alert in DB
    alerts_1 = test_db.get_alerts()
    assert len(alerts_1) == 1
    alert_id = alerts_1[0]["id"]
    assert alerts_1[0]["occurrence_count"] == 1

    # 2nd execution of distinct event triggering same alert -> Deduplicates & increments occurrence count!
    raw_event_2 = dict(raw_event)
    raw_event_2["event_id"] = "SYS-MIMI-102"
    res2 = pipeline.process_event(raw_event_2, source_type="windows")
    alerts_2 = test_db.get_alerts()
    assert len(alerts_2) == 1
    assert alerts_2[0]["id"] == alert_id
    assert alerts_2[0]["occurrence_count"] == 2

# 5. REST API & Lifecycle Status Tests
def test_alert_lifecycle_status_and_false_positive_api(test_db, auth_headers):
    client = TestClient(app)
    from src.api import db as api_db
    
    # Save dummy alert in API's database
    dummy_alert = {
        "id": "ALT-TEST-999",
        "rule_id": "WIN-PS-001",
        "title": "Test Alert Lifecycle",
        "severity": "high",
        "status": "NEW",
        "source": "192.168.1.50"
    }
    api_db.save_alert(dummy_alert, deduplicate=False)

    # 1. Update status to ACKNOWLEDGED
    res_ack = client.patch(
        "/api/v1/alerts/ALT-TEST-999/status",
        json={"status": "ACKNOWLEDGED"},
        headers=auth_headers["analyst"]
    )
    assert res_ack.status_code == 200
    assert res_ack.json()["new_status"] == "ACKNOWLEDGED"

    # 2. Update status to FALSE_POSITIVE with rationale
    res_fp = client.patch(
        "/api/v1/alerts/ALT-TEST-999/status",
        json={"status": "FALSE_POSITIVE", "fp_reason": "Authorized IT admin deployment"},
        headers=auth_headers["analyst"]
    )
    assert res_fp.status_code == 200
    assert res_fp.json()["new_status"] == "FALSE_POSITIVE"

    # Verify evidence API endpoint
    res_ev = client.get("/api/v1/alerts/ALT-TEST-999/evidence", headers=auth_headers["analyst"])
    assert res_ev.status_code == 200
    data = res_ev.json()
    assert data["alert"]["fp_reason"] == "Authorized IT admin deployment"

# 6. Detection Rules CRUD & RBAC Tests
def test_detection_rules_rbac_and_crud(test_db, auth_headers):
    client = TestClient(app)

    unique_rule_id = f"CUSTOM-TEST-{uuid.uuid4().hex[:6]}"
    new_rule = {
        "rule_id": unique_rule_id,
        "name": f"Custom Test Rule {unique_rule_id}",
        "description": "Test rule creation",
        "severity": "high",
        "confidence": 85,
        "enabled": True,
        "event_conditions": [{"field": "event_type", "operator": "eq", "value": "CustomEvent"}],
        "threshold": 1,
        "time_window": 60,
        "mitre_tactic": "Execution",
        "mitre_technique_id": "T1059",
        "mitre_technique_name": "Custom Script"
    }

    # Read-Only analyst trying to create rule -> 403 Forbidden!
    res_ro = client.post("/api/v1/detections/rules", json=new_rule, headers=auth_headers["readonly"])
    assert res_ro.status_code == 403

    # Detection Engineer creating rule -> 200 OK
    res_eng = client.post("/api/v1/detections/rules", json=new_rule, headers=auth_headers["engineer"])
    assert res_eng.status_code == 200
    assert res_eng.json()["rule_id"] == unique_rule_id

    # Disable rule
    res_dis = client.patch(f"/api/v1/detections/rules/{unique_rule_id}/enable", json={"enabled": False}, headers=auth_headers["engineer"])
    assert res_dis.status_code == 200
    assert res_dis.json()["enabled"] is False

# 7. MITRE ATT&CK Matrix Coverage API Test
def test_mitre_coverage_api(test_db, auth_headers):
    client = TestClient(app)
    res = client.get("/api/mitre/coverage", headers=auth_headers["analyst"])
    assert res.status_code == 200
    data = res.json()
    assert "matrix" in data
    assert "Execution" in data["matrix"]
