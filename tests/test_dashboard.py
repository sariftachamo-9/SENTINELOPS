import pytest
import os
from fastapi.testclient import TestClient

# Ensure secret environment variable for JWT token generation
os.environ["JWT_SECRET"] = "soc-lab-test-secret-key-12345"

from src.api import app
from src.web_ui import app as web_app
from src.security import create_access_token

client = TestClient(app)
web_client = TestClient(web_app)

@pytest.fixture
def admin_token():
    return create_access_token({"sub": "admin", "role": "Administrator"})

@pytest.fixture
def l1_token():
    return create_access_token({"sub": "analyst_l1", "role": "L1 Threat Analyst"})

@pytest.fixture
def auth_headers(admin_token):
    return {"Authorization": f"Bearer {admin_token}"}

@pytest.fixture
def l1_auth_headers(l1_token):
    return {"Authorization": f"Bearer {l1_token}"}

def test_web_ui_html_structure():
    """Verify that Web UI portal serves the single page app with all 11 tab containers."""
    response = web_client.get("/")
    assert response.status_code == 200
    html = response.text
    
    # Check all tab container IDs
    expected_tabs = [
        "tab-dashboard",
        "tab-alerts",
        "tab-rules",
        "tab-incidents",
        "tab-investigations",
        "tab-hunting",
        "tab-assets",
        "tab-mitre",
        "tab-health",
        "tab-playbooks",
        "tab-reports"
    ]
    for tab_id in expected_tabs:
        assert f'id="{tab_id}"' in html, f"Missing tab container {tab_id} in web UI"
        
    # Check switchTab JS handlers for all tabs
    assert "switchTab('dashboard'" in html
    assert "switchTab('alerts'" in html
    assert "switchTab('rules'" in html
    assert "switchTab('incidents'" in html
    assert "switchTab('investigations'" in html
    assert "switchTab('hunting'" in html
    assert "switchTab('assets'" in html
    assert "switchTab('mitre'" in html
    assert "switchTab('health'" in html
    assert "switchTab('playbooks'" in html
    assert "switchTab('reports'" in html

def test_executive_overview_endpoints(auth_headers):
    """Test API endpoints backing the Executive Overview tab."""
    res_stats = client.get("/api/stats", headers=auth_headers)
    assert res_stats.status_code == 200
    data_stats = res_stats.json()
    assert "total_alerts" in data_stats
    assert "active_incidents" in data_stats
    assert "total_assets" in data_stats

    res_alerts = client.get("/api/alerts?limit=10", headers=auth_headers)
    assert res_alerts.status_code == 200
    assert isinstance(res_alerts.json(), list)

def test_alert_triage_workspace_endpoint(auth_headers):
    """Test API endpoint backing Alert Stream & Triage workspace."""
    res = client.get("/api/alerts?limit=100", headers=auth_headers)
    assert res.status_code == 200
    assert isinstance(res.json(), list)

def test_detection_rules_workspace_endpoint(auth_headers):
    """Test API endpoint backing Detection Rules workspace."""
    res = client.get("/api/v1/detections/rules", headers=auth_headers)
    assert res.status_code == 200
    data = res.json()
    assert "rules" in data
    assert isinstance(data["rules"], list)

def test_incidents_workspace_endpoint(auth_headers):
    """Test API endpoint backing Incidents & Cases workspace."""
    res = client.get("/api/incidents", headers=auth_headers)
    assert res.status_code == 200
    assert isinstance(res.json(), list)

def test_investigation_workspace_endpoint(auth_headers):
    """Test API endpoint backing Investigation Graph workspace."""
    res = client.get("/api/investigation/graph", headers=auth_headers)
    assert res.status_code == 200
    data = res.json()
    assert "nodes" in data
    assert "edges" in data

def test_threat_hunting_workspace_endpoint(auth_headers):
    """Test API endpoint backing Threat Hunting workspace."""
    res = client.get("/api/v1/telemetry/events?limit=50", headers=auth_headers)
    assert res.status_code == 200
    data = res.json()
    assert "events" in data
    assert isinstance(data["events"], list)

def test_asset_inventory_workspace_endpoint(auth_headers):
    """Test API endpoint backing Asset Inventory workspace."""
    res = client.get("/api/assets", headers=auth_headers)
    assert res.status_code == 200
    assert isinstance(res.json(), list)

def test_mitre_workspace_endpoint(auth_headers):
    """Test API endpoint backing MITRE ATT&CK Matrix workspace."""
    res = client.get("/api/mitre/coverage", headers=auth_headers)
    assert res.status_code == 200
    data = res.json()
    assert "matrix" in data
    assert "coverage_percentage" in data

def test_soc_health_workspace_endpoints(auth_headers):
    """Test API endpoints backing SOC Health Monitor workspace."""
    res = client.get("/api/soc/health", headers=auth_headers)
    assert res.status_code == 200
    data = res.json()
    assert "services" in data

    res_integ = client.get("/api/v1/integrations/health", headers=auth_headers)
    assert res_integ.status_code == 200
    assert "integrations" in res_integ.json()

def test_soar_playbooks_workspace_endpoints(auth_headers):
    """Test API endpoints backing SOAR Playbooks workspace."""
    res_pb = client.get("/api/v1/playbooks", headers=auth_headers)
    assert res_pb.status_code == 200
    assert isinstance(res_pb.json(), list)

    res_exec = client.get("/api/v1/playbook-executions", headers=auth_headers)
    assert res_exec.status_code == 200
    assert "executions" in res_exec.json()

def test_reports_and_audit_workspace_endpoints(auth_headers, l1_auth_headers):
    """Test API endpoints backing Reports & Audit workspace and check RBAC."""
    # Download endpoint with admin token
    res_dl = client.get("/api/reports/download?fmt=json", headers=auth_headers)
    assert res_dl.status_code == 200

    # Audit logs endpoint with admin token (has audit.read)
    res_audit = client.get("/api/v1/audit/logs?limit=50", headers=auth_headers)
    assert res_audit.status_code == 200
    assert "logs" in res_audit.json()

    # RBAC check: L1 analyst should receive 403 Forbidden for audit logs
    res_l1_audit = client.get("/api/v1/audit/logs?limit=50", headers=l1_auth_headers)
    assert res_l1_audit.status_code == 403

def test_unauthenticated_access_denied():
    """Verify that unauthenticated requests to protected API endpoints return 401 Unauthorized."""
    protected_endpoints = [
        "/api/stats",
        "/api/alerts",
        "/api/incidents",
        "/api/assets",
        "/api/mitre/coverage",
        "/api/soc/health",
        "/api/v1/detections/rules",
        "/api/v1/telemetry/events",
        "/api/v1/playbooks",
        "/api/v1/audit/logs"
    ]
    for ep in protected_endpoints:
        res = client.get(ep)
        assert res.status_code in [401, 403], f"Endpoint {ep} allowed unauthenticated access!"
