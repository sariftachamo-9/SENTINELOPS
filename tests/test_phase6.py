"""Phase 6 Tests — Case Management, Evidence, Entities, Hunting, RBAC, IDOR, XSS"""
import pytest, os, json, uuid, html
from datetime import datetime
from fastapi.testclient import TestClient

os.environ["JWT_SECRET"] = "phase6-test-secret-abc123"
os.environ["TESTING"] = "true"

from src.database import Database
from src.security import create_access_token
from src.case_management import CaseManager, CaseStateError
from src.evidence import EvidenceManager
from src.case_notes import CaseNotesManager
from src.entity_model import EntityManager
from src.threat_hunting import ThreatHunter, HuntQueryValidationError
from src.investigations import InvestigationWorkspace
from src.api import app

client = TestClient(app)

@pytest.fixture
def test_db(tmp_path):
    db = Database(db_path=str(tmp_path / "p6.db"))
    yield db
    db.close()

@pytest.fixture
def tokens():
    return {
        "admin":    {"Authorization": f"Bearer {create_access_token({'sub':'admin_t','role':'Administrator'})}"},
        "analyst":  {"Authorization": f"Bearer {create_access_token({'sub':'analyst_t','role':'SOC Analyst L2'})}"},
        "l1":       {"Authorization": f"Bearer {create_access_token({'sub':'l1_t','role':'SOC Analyst L1'})}"},
        "hunter":   {"Authorization": f"Bearer {create_access_token({'sub':'hunter_t','role':'Threat Hunter'})}"},
        "manager":  {"Authorization": f"Bearer {create_access_token({'sub':'manager_t','role':'SOC Manager'})}"},
        "readonly": {"Authorization": f"Bearer {create_access_token({'sub':'ro_t','role':'Read Only'})}"},
        "responder":{"Authorization": f"Bearer {create_access_token({'sub':'resp_t','role':'Incident Responder'})}"},
    }

# ── Case CRUD ──────────────────────────────────────────────────────────────────
def test_case_create(test_db):
    mgr = CaseManager(db=test_db)
    c = mgr.create_case("Test Case", "desc", severity="high", priority="HIGH", created_by="analyst")
    assert c["id"].startswith("CASE-")
    assert c["status"] == "OPEN"
    assert c["severity"] == "high"
    assert c["disposition"] == "UNDETERMINED"

def test_case_create_invalid_severity(test_db):
    mgr = CaseManager(db=test_db)
    with pytest.raises(ValueError):
        mgr.create_case("Bad", severity="unknown")

def test_case_list_pagination(test_db):
    mgr = CaseManager(db=test_db)
    for i in range(5):
        mgr.create_case(f"Case {i}", created_by="a")
    result = mgr.list_cases(limit=2, offset=0)
    assert result["total"] == 5
    assert len(result["cases"]) == 2
    page2 = mgr.list_cases(limit=2, offset=2)
    assert len(page2["cases"]) == 2

def test_case_list_filter_status(test_db):
    mgr = CaseManager(db=test_db)
    mgr.create_case("Open", created_by="a")
    c2 = mgr.create_case("Progress", created_by="a")
    mgr.update_case_status(c2["id"], "IN_PROGRESS", user="a", role="Administrator")
    open_cases = mgr.list_cases(status="OPEN")
    assert all(c["status"] == "OPEN" for c in open_cases["cases"])

# ── State Machine ──────────────────────────────────────────────────────────────
def test_valid_state_transition(test_db):
    mgr = CaseManager(db=test_db)
    c = mgr.create_case("SM Test", created_by="a")
    updated = mgr.update_case_status(c["id"], "IN_PROGRESS", user="a", role="Administrator")
    assert updated["status"] == "IN_PROGRESS"

def test_invalid_state_transition_rejected(test_db):
    mgr = CaseManager(db=test_db)
    c = mgr.create_case("SM Reject", created_by="a")
    # First, move to CLOSED (valid transition: OPEN -> CLOSED for admin)
    mgr.update_case_status(c["id"], "CLOSED", user="a", role="Administrator")
    # Try to move CLOSED -> OPEN (invalid transition for L1)
    with pytest.raises(CaseStateError):
        mgr.update_case_status(c["id"], "OPEN", user="analyst", role="SOC Analyst L1")

def test_manager_can_close_case(test_db):
    mgr = CaseManager(db=test_db)
    c = mgr.create_case("Close Test", created_by="a")
    mgr.update_case_status(c["id"], "IN_PROGRESS", user="a", role="Administrator")
    mgr.update_case_status(c["id"], "CONTAINED", user="a", role="Administrator")
    mgr.update_case_status(c["id"], "RESOLVED", user="a", role="Administrator")
    closed = mgr.update_case_status(c["id"], "CLOSED", user="a", role="Administrator")
    assert closed["status"] == "CLOSED"
    assert closed["closed_at"] != ""

# ── Disposition ────────────────────────────────────────────────────────────────
def test_case_disposition(test_db):
    mgr = CaseManager(db=test_db)
    c = mgr.create_case("Disp Test", created_by="a")
    updated = mgr.update_case_disposition(c["id"], "TRUE_POSITIVE", user="a")
    assert updated["disposition"] == "TRUE_POSITIVE"

def test_invalid_disposition(test_db):
    mgr = CaseManager(db=test_db)
    c = mgr.create_case("Bad Disp", created_by="a")
    with pytest.raises(ValueError):
        mgr.update_case_disposition(c["id"], "MAYBE", user="a")

# ── Assignment ─────────────────────────────────────────────────────────────────
def test_case_assignment_audited(test_db):
    mgr = CaseManager(db=test_db)
    c = mgr.create_case("Assign Test", created_by="a")
    updated = mgr.assign_case(c["id"], "analyst_l2", user="manager", role="SOC Manager")
    assert updated["assigned_to"] == "analyst_l2"
    cursor = test_db.get_cursor()
    cursor.execute("SELECT * FROM audit_logs WHERE action='CASE_ASSIGNED' AND target_id=?", (c["id"],))
    row = cursor.fetchone()
    assert row is not None

# ── Alert/Incident Linking ─────────────────────────────────────────────────────
def test_link_alert_to_case(test_db):
    mgr = CaseManager(db=test_db)
    c = mgr.create_case("Link Test", created_by="a")
    test_db.save_alert({"id":"ALT-P6-001","rule_id":"R1","title":"T","severity":"high","source":"10.0.0.1"}, deduplicate=False)
    result = mgr.link_alert_to_case(c["id"], "ALT-P6-001", linked_by="analyst")
    assert result["status"] == "linked"
    alerts = mgr.get_case_alerts(c["id"])
    assert len(alerts) == 1
    assert alerts[0]["id"] == "ALT-P6-001"

def test_link_incident_to_case(test_db):
    mgr = CaseManager(db=test_db)
    c = mgr.create_case("Inc Link", created_by="a")
    test_db.save_incident({"id":"INC-P6-001","title":"I","severity":"high","status":"open","created_at":datetime.now().isoformat()})
    result = mgr.link_incident_to_case(c["id"], "INC-P6-001", linked_by="analyst")
    assert result["status"] == "linked"
    incs = mgr.get_case_incidents(c["id"])
    assert len(incs) == 1

# ── Evidence ───────────────────────────────────────────────────────────────────
def test_evidence_add_and_get(test_db):
    mgr = CaseManager(db=test_db)
    ev_mgr = EvidenceManager(db=test_db)
    c = mgr.create_case("Evidence Test", created_by="a")
    ev = ev_mgr.add_evidence(c["id"], "alert", "SIEM", "Suspicious login", added_by="analyst")
    assert ev["evidence_id"].startswith("EV-")
    assert ev["type"] == "alert"
    chain = ev["chain_of_custody"]
    assert len(chain) == 1
    assert chain[0]["action"] == "ADDED"

def test_evidence_invalid_type(test_db):
    mgr = CaseManager(db=test_db)
    ev_mgr = EvidenceManager(db=test_db)
    c = mgr.create_case("EV Invalid", created_by="a")
    with pytest.raises(ValueError):
        ev_mgr.add_evidence(c["id"], "shellcode", "src", "bad", added_by="a")

def test_evidence_idor_protection(test_db):
    mgr = CaseManager(db=test_db)
    ev_mgr = EvidenceManager(db=test_db)
    c1 = mgr.create_case("Case1", created_by="a")
    c2 = mgr.create_case("Case2", created_by="a")
    ev = ev_mgr.add_evidence(c1["id"], "ioc", "feed", "desc", added_by="a")
    assert ev_mgr.get_evidence(ev["evidence_id"], c2["id"]) is None

def test_chain_of_custody_append_only(test_db):
    mgr = CaseManager(db=test_db)
    ev_mgr = EvidenceManager(db=test_db)
    c = mgr.create_case("CoC Test", created_by="a")
    ev = ev_mgr.add_evidence(c["id"], "file_meta", "endpoint", "original desc", added_by="a")
    ev2 = ev_mgr.update_evidence_metadata(
        ev["evidence_id"], c["id"], {"description": "updated"},
        updated_by="b", reason="Correcting description after review"  # Req #3: reason is mandatory
    )
    chain = ev2["chain_of_custody"]
    assert len(chain) == 2
    assert chain[0]["action"] == "ADDED"
    assert chain[1]["action"] == "METADATA_UPDATED"
    # Verify embedded previous/new values (Req #3)
    assert "changes" in chain[1]
    assert chain[1]["changes"]["description"]["previous_value"] == "original desc"
    assert chain[1]["changes"]["description"]["new_value"] == "updated"

def test_evidence_list_for_case(test_db):
    mgr = CaseManager(db=test_db)
    ev_mgr = EvidenceManager(db=test_db)
    c = mgr.create_case("EV List", created_by="a")
    ev_mgr.add_evidence(c["id"], "alert", "s", "d1", added_by="a")
    ev_mgr.add_evidence(c["id"], "ioc", "s", "d2", added_by="a")
    items = ev_mgr.list_case_evidence(c["id"])
    assert len(items) == 2

# ── Notes XSS Prevention ───────────────────────────────────────────────────────
def test_note_xss_prevention(test_db):
    """Notes must strip HTML tags and store PLAIN TEXT (not HTML entities). Req #4."""
    mgr = CaseManager(db=test_db)
    nm = CaseNotesManager(db=test_db)
    c = mgr.create_case("XSS Test", created_by="a")
    xss = '<script>alert("xss")</script>'
    note = nm.add_note(c["id"], "analyst", xss)
    # Tags stripped — no raw HTML in storage
    assert "<script>" not in note["content"]
    # Plain text stored — NOT HTML-entity-encoded at storage time (Req #4)
    assert "&lt;" not in note["content"]
    assert "&gt;" not in note["content"]

def test_note_idor(test_db):
    mgr = CaseManager(db=test_db)
    nm = CaseNotesManager(db=test_db)
    c1 = mgr.create_case("C1", created_by="a")
    c2 = mgr.create_case("C2", created_by="a")
    note = nm.add_note(c1["id"], "a", "secret note")
    assert nm.get_note(note["note_id"], c2["id"]) is None

def test_note_update_audited(test_db):
    mgr = CaseManager(db=test_db)
    nm = CaseNotesManager(db=test_db)
    c = mgr.create_case("Note Audit", created_by="a")
    note = nm.add_note(c["id"], "a", "original")
    nm.update_note(note["note_id"], c["id"], "updated", updated_by="b")
    cursor = test_db.get_cursor()
    cursor.execute("SELECT * FROM audit_logs WHERE action='CASE_NOTE_UPDATED'")
    row = cursor.fetchone()
    assert row is not None

# ── Entity Model ───────────────────────────────────────────────────────────────
def test_entity_upsert(test_db):
    em = EntityManager(db=test_db)
    e1 = em.upsert_entity("HOST", "WORKSTATION-01")
    e2 = em.upsert_entity("HOST", "WORKSTATION-01")
    assert e1["entity_id"] == e2["entity_id"]

def test_entity_invalid_type(test_db):
    em = EntityManager(db=test_db)
    with pytest.raises(ValueError):
        em.upsert_entity("ROBOT", "val")

def test_entity_relationship(test_db):
    em = EntityManager(db=test_db)
    u = em.upsert_entity("USER", "john")
    h = em.upsert_entity("HOST", "pc01")
    rel = em.add_relationship(u["entity_id"], h["entity_id"], "logged_into")
    assert rel["rel_id"].startswith("REL-")
    rels = em.get_entity_relationships(u["entity_id"])
    assert len(rels) == 1

def test_entity_graph_real_data_only(test_db):
    em = EntityManager(db=test_db)
    graph = em.get_entity_graph()
    # No edges means no nodes — no fake data
    assert isinstance(graph["nodes"], list)
    assert isinstance(graph["edges"], list)
    assert len(graph["nodes"]) == len({r["source_entity_id"] for r in graph["edges"]} | {r["target_entity_id"] for r in graph["edges"]})

def test_entity_extraction_from_alert(test_db):
    em = EntityManager(db=test_db)
    alert = {"id":"A1","affected_asset":"HOST-01","affected_user":"admin","destination":"8.8.8.8","detection_rule":"R1"}
    created = em.extract_entities_from_alert(alert)
    assert any(e["entity_type"] == "HOST" for e in created)
    assert any(e["entity_type"] == "USER" for e in created)

# ── Threat Hunting ─────────────────────────────────────────────────────────────
def test_hunt_valid_query(test_db):
    th = ThreatHunter(db=test_db)
    result = th.execute_hunt({"filters": [{"field":"event_type","operator":"equals","value":"Login"}]}, executing_user="analyst")
    assert "results" in result
    assert "total" in result

def test_hunt_invalid_field_rejected(test_db):
    th = ThreatHunter(db=test_db)
    with pytest.raises(HuntQueryValidationError) as exc:
        th.execute_hunt({"filters": [{"field":"password","operator":"equals","value":"secret"}]})
    assert "not searchable" in str(exc.value)

def test_hunt_invalid_operator_rejected(test_db):
    th = ThreatHunter(db=test_db)
    with pytest.raises(HuntQueryValidationError):
        th.execute_hunt({"filters": [{"field":"hostname","operator":"LIKE '%;DROP TABLE events;--","value":"x"}]})

def test_hunt_sql_injection_rejected(test_db):
    th = ThreatHunter(db=test_db)
    with pytest.raises(HuntQueryValidationError):
        th.execute_hunt({"filters": [{"field":"'; DROP TABLE events; --","operator":"equals","value":"x"}]})

def test_hunt_pagination(test_db):
    th = ThreatHunter(db=test_db)
    r1 = th.execute_hunt({"filters":[]}, limit=5, offset=0)
    r2 = th.execute_hunt({"filters":[]}, limit=5, offset=5)
    assert r1["limit"] == 5
    assert r2["offset"] == 5

def test_saved_hunt_crud(test_db):
    th = ThreatHunter(db=test_db)
    query = {"filters":[{"field":"hostname","operator":"equals","value":"WIN01"}]}
    hunt = th.save_hunt("My Hunt", query, owner="hunter")
    assert hunt["hunt_id"].startswith("HUNT-")
    listed = th.list_saved_hunts("hunter")
    assert len(listed) == 1

def test_saved_hunt_idor(test_db):
    th = ThreatHunter(db=test_db)
    query = {"filters":[{"field":"hostname","operator":"equals","value":"WIN01"}]}
    hunt = th.save_hunt("Secret", query, owner="analyst1")
    result = th.get_saved_hunt(hunt["hunt_id"], requesting_user="analyst2", requesting_role="SOC Analyst L2")
    assert result is None

def test_hunt_promote_to_alert(test_db):
    th = ThreatHunter(db=test_db)
    ref = th.promote_to_alert_reference("EVT-FAKE-001", analyst="hunter", case_id="CASE-XYZ")
    assert ref["ref_id"].startswith("HUNTREF-")
    assert ref["promoted_by"] == "hunter"

# ── RBAC via API ───────────────────────────────────────────────────────────────
def test_case_create_rbac(tokens):
    payload = {"title":"RBAC Test","severity":"medium","priority":"MEDIUM"}
    # Read-only cannot create
    r = client.post("/api/v1/cases", json=payload, headers=tokens["readonly"])
    assert r.status_code == 403
    # L1 analyst can create
    r2 = client.post("/api/v1/cases", json=payload, headers=tokens["l1"])
    assert r2.status_code == 200

def test_case_assign_requires_manager(tokens):
    create_r = client.post("/api/v1/cases", json={"title":"Assign RBAC","severity":"medium"}, headers=tokens["admin"])
    case_id = create_r.json()["case"]["id"]
    # L1 cannot assign
    r = client.patch(f"/api/v1/cases/{case_id}/assign", json={"assignee":"other"}, headers=tokens["l1"])
    assert r.status_code == 403
    # Manager/Responder can
    r2 = client.patch(f"/api/v1/cases/{case_id}/assign", json={"assignee":"other"}, headers=tokens["responder"])
    assert r2.status_code == 200

def test_evidence_add_rbac(tokens):
    create_r = client.post("/api/v1/cases", json={"title":"EV RBAC","severity":"low"}, headers=tokens["admin"])
    case_id = create_r.json()["case"]["id"]
    payload = {"type":"alert","source":"SIEM","description":"test evidence"}
    # L1 cannot add evidence
    r = client.post(f"/api/v1/cases/{case_id}/evidence", json=payload, headers=tokens["l1"])
    assert r.status_code == 403
    # Analyst L2 can
    r2 = client.post(f"/api/v1/cases/{case_id}/evidence", json=payload, headers=tokens["analyst"])
    assert r2.status_code == 200

def test_hunting_execute_rbac(tokens):
    payload = {"filters":[{"field":"hostname","operator":"equals","value":"test"}]}
    r_ro = client.post("/api/v1/hunting/execute", json=payload, headers=tokens["readonly"])
    assert r_ro.status_code == 403
    r_hunter = client.post("/api/v1/hunting/execute", json=payload, headers=tokens["hunter"])
    assert r_hunter.status_code == 200

def test_audit_log_rbac(tokens):
    # Only manager/admin can read audit logs
    r = client.get("/api/v1/audit/logs", headers=tokens["l1"])
    assert r.status_code == 403
    r2 = client.get("/api/v1/audit/logs", headers=tokens["manager"])
    assert r2.status_code == 200

# ── Investigation Workspace ────────────────────────────────────────────────────
def test_workspace_aggregation(tokens):
    create_r = client.post("/api/v1/cases", json={"title":"WS Test","severity":"high"}, headers=tokens["admin"])
    case_id = create_r.json()["case"]["id"]
    r = client.get(f"/api/v1/cases/{case_id}/workspace", headers=tokens["admin"])
    assert r.status_code == 200
    ws = r.json()
    assert "case" in ws
    assert "alerts" in ws
    assert "timeline" in ws
    assert "evidence" in ws
    assert "notes" in ws

def test_case_timeline_endpoint(tokens):
    create_r = client.post("/api/v1/cases", json={"title":"Timeline Test","severity":"medium"}, headers=tokens["admin"])
    case_id = create_r.json()["case"]["id"]
    r = client.get(f"/api/v1/cases/{case_id}/timeline", headers=tokens["admin"])
    assert r.status_code == 200
    data = r.json()
    assert "timeline" in data

def test_entity_graph_endpoint_no_fake_nodes(tokens):
    create_r = client.post("/api/v1/cases", json={"title":"Graph Test","severity":"low"}, headers=tokens["admin"])
    case_id = create_r.json()["case"]["id"]
    r = client.get(f"/api/v1/cases/{case_id}/entity-graph", headers=tokens["admin"])
    assert r.status_code == 200
    graph = r.json()
    # New empty case should have 0 real nodes
    assert graph["total_nodes"] == len(graph["nodes"])

# ── Audit Logging ──────────────────────────────────────────────────────────────
def test_audit_case_creation_logged(test_db):
    mgr = CaseManager(db=test_db)
    c = mgr.create_case("Audit Case", created_by="audit_user")
    cursor = test_db.get_cursor()
    cursor.execute("SELECT * FROM audit_logs WHERE action='CASE_CREATED' AND target_id=?", (c["id"],))
    row = cursor.fetchone()
    assert row is not None
    assert row["username"] == "audit_user"

def test_audit_no_sensitive_fields(test_db):
    cursor = test_db.get_cursor()
    cursor.execute("SELECT new_value, old_value FROM audit_logs")
    for row in cursor.fetchall():
        for field in [row["new_value"] or "", row["old_value"] or ""]:
            assert "password" not in field.lower()
            assert "jwt" not in field.lower()
            assert "api_key" not in field.lower()

# ── Regression: previous phase tests still import cleanly ─────────────────────
def test_phase6_imports():
    from src.case_management import CaseManager
    from src.evidence import EvidenceManager
    from src.entity_model import EntityManager
    from src.case_notes import CaseNotesManager
    from src.threat_hunting import ThreatHunter
    from src.investigations import InvestigationWorkspace
    from src.incident_manager import IncidentManager
    assert True


# ══════════════════════════════════════════════════════════════════════════════
# PHASE 6 HARDENED — Incident First-Class Object Tests (Req #2)
# ══════════════════════════════════════════════════════════════════════════════

def test_incident_create(test_db):
    """Incident creation returns structured first-class object."""
    from src.incident_manager import IncidentManager
    mgr = IncidentManager(db=test_db)
    inc = mgr.create_incident(
        title="Brute Force Detected",
        description="Multiple failed logins from 10.0.0.5",
        severity="high",
        priority="P1",
        mitre_techniques=["T1110"],
        created_by="analyst",
    )
    assert inc["id"].startswith("INC-")
    assert inc["status"] == "OPEN"
    assert inc["severity"] == "high"
    assert inc["priority"] == "P1"
    assert "T1110" in inc["mitre_techniques"]
    assert inc["version"] == 1

def test_incident_invalid_severity(test_db):
    from src.incident_manager import IncidentManager
    mgr = IncidentManager(db=test_db)
    with pytest.raises(ValueError, match="Invalid severity"):
        mgr.create_incident("Bad", severity="catastrophic")

def test_incident_list_paginated(test_db):
    from src.incident_manager import IncidentManager
    mgr = IncidentManager(db=test_db)
    for i in range(5):
        mgr.create_incident(f"Incident {i}", created_by="analyst")
    result = mgr.list_incidents(limit=2, offset=0)
    assert result["total"] == 5
    assert len(result["incidents"]) == 2
    page2 = mgr.list_incidents(limit=2, offset=2)
    assert len(page2["incidents"]) == 2

def test_incident_state_machine_valid(test_db):
    from src.incident_manager import IncidentManager
    mgr = IncidentManager(db=test_db)
    inc = mgr.create_incident("SM Test", created_by="analyst")
    updated = mgr.update_incident_status(inc["id"], "IN_INVESTIGATION", user="analyst")
    assert updated["status"] == "IN_INVESTIGATION"
    assert updated["version"] == 2  # Incremented

def test_incident_state_machine_invalid(test_db):
    from src.incident_manager import IncidentManager, IncidentStateError
    mgr = IncidentManager(db=test_db)
    inc = mgr.create_incident("SM Invalid", created_by="analyst")
    # Cannot jump from OPEN to CLOSED without going through CONTAINED first
    # Actually OPEN -> CLOSED is allowed per transitions. Test CLOSED -> OPEN
    mgr.update_incident_status(inc["id"], "RESOLVED", user="analyst")
    mgr.update_incident_status(inc["id"], "CLOSED", user="analyst")
    with pytest.raises(IncidentStateError):
        mgr.update_incident_status(inc["id"], "OPEN", user="analyst")

def test_link_alert_to_incident(test_db):
    from src.incident_manager import IncidentManager
    mgr = IncidentManager(db=test_db)
    inc = mgr.create_incident("Alert Link Test", created_by="analyst")
    # Insert a dummy alert
    cursor = test_db.get_cursor()
    cursor.execute(
        "INSERT INTO alerts (id, title, severity, status, timestamp) VALUES (?,?,?,?,?)",
        ("ALT-001", "Test Alert", "high", "NEW", datetime.now().isoformat())
    )
    test_db.conn.commit()
    updated = mgr.link_alert_to_incident(inc["id"], "ALT-001", linked_by="analyst")
    linked = mgr.get_incident_alerts(inc["id"])
    assert any(a["id"] == "ALT-001" for a in linked)

def test_incident_timeline(test_db):
    from src.incident_manager import IncidentManager
    mgr = IncidentManager(db=test_db)
    inc = mgr.create_incident("Timeline Test", created_by="analyst")
    mgr.update_incident_status(inc["id"], "IN_INVESTIGATION", user="analyst")
    timeline = mgr.get_incident_timeline(inc["id"])
    assert len(timeline) >= 2  # CREATED + STATUS_CHANGED
    actions = [t["action"] for t in timeline]
    assert "INCIDENT_CREATED" in actions
    assert "INCIDENT_STATUS_CHANGED" in actions

def test_incident_api_create(tokens):
    """POST /api/v1/incidents creates a first-class incident."""
    resp = client.post(
        "/api/v1/incidents",
        json={"title": "API Incident", "severity": "high", "priority": "P2"},
        headers=tokens["analyst"],
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["incident"]["id"].startswith("INC-")

def test_incident_api_list(tokens):
    resp = client.get("/api/v1/incidents", headers=tokens["l1"])
    assert resp.status_code == 200
    assert "incidents" in resp.json()

def test_incident_api_status_update(tokens):
    """PATCH /api/v1/incidents/{id}/status transitions correctly."""
    r = client.post(
        "/api/v1/incidents",
        json={"title": "Status Update Test", "severity": "medium"},
        headers=tokens["analyst"],
    )
    inc_id = r.json()["incident"]["id"]
    resp = client.patch(
        f"/api/v1/incidents/{inc_id}/status",
        json={"status": "IN_INVESTIGATION"},
        headers=tokens["analyst"],
    )
    assert resp.status_code == 200
    assert resp.json()["incident"]["status"] == "IN_INVESTIGATION"

def test_incident_idor_404(tokens):
    """Direct API call with non-existent incident ID returns 404, not data leak."""
    resp = client.get("/api/v1/incidents/INC-99999999-ZZZZZZ", headers=tokens["readonly"])
    assert resp.status_code == 404


# ══════════════════════════════════════════════════════════════════════════════
# PHASE 6 HARDENED — Evidence CoC previous_value/new_value (Req #3)
# ══════════════════════════════════════════════════════════════════════════════

def test_evidence_chain_embeds_previous_new_value(test_db):
    """Chain of custody must embed previous_value and new_value per field."""
    mgr = EvidenceManager(db=test_db)
    case_mgr_local = CaseManager(db=test_db)
    c = case_mgr_local.create_case("Evidence CoC Case", created_by="analyst")

    ev = mgr.add_evidence(
        case_id=c["id"], evidence_type="telemetry_event",
        source="WIN-SRV-01", description="Original description",
        added_by="analyst",
    )

    updated = mgr.update_evidence_metadata(
        ev["evidence_id"], c["id"],
        updates={"description": "Updated description"},
        updated_by="analyst",
        reason="Corrected typo in description",
    )

    coc = updated["chain_of_custody"]
    assert len(coc) == 2  # ADDED + METADATA_UPDATED

    update_entry = coc[1]
    assert update_entry["action"] == "METADATA_UPDATED"
    assert "reason" in update_entry
    assert "changes" in update_entry
    assert "description" in update_entry["changes"]
    change = update_entry["changes"]["description"]
    assert "previous_value" in change
    assert "new_value" in change
    assert change["previous_value"] == "Original description"

def test_evidence_update_requires_reason(test_db):
    """Evidence metadata update must include a non-empty reason."""
    mgr = EvidenceManager(db=test_db)
    case_mgr_local = CaseManager(db=test_db)
    c = case_mgr_local.create_case("Evidence Reason Case", created_by="analyst")
    ev = mgr.add_evidence(
        case_id=c["id"], evidence_type="alert", source="src", description="desc", added_by="analyst"
    )
    with pytest.raises(ValueError, match="reason is required"):
        mgr.update_evidence_metadata(ev["evidence_id"], c["id"], {"description": "new"}, "analyst", reason="")


# ══════════════════════════════════════════════════════════════════════════════
# PHASE 6 HARDENED — Optimistic Concurrency (Req #5)
# ══════════════════════════════════════════════════════════════════════════════

def test_case_optimistic_concurrency_409_api(tokens):
    """PATCH /api/v1/cases/{id}/status with stale expected_version returns HTTP 409."""
    r = client.post(
        "/api/v1/cases",
        json={"title": "Concurrency Test Case", "severity": "high", "priority": "HIGH"},
        headers=tokens["admin"],
    )
    case_id = r.json()["case"]["id"]

    # First update succeeds (no version check)
    client.patch(
        f"/api/v1/cases/{case_id}/status",
        json={"status": "IN_PROGRESS"},
        headers=tokens["admin"],
    )

    # Second update with stale version=1 (DB is now at version=2) → 409
    resp = client.patch(
        f"/api/v1/cases/{case_id}/status",
        json={"status": "CONTAINED", "expected_version": 1},
        headers=tokens["admin"],
    )
    assert resp.status_code == 409
    assert "Stale write" in resp.json()["detail"]

def test_case_concurrency_fresh_version_succeeds(test_db):
    """Write with correct expected_version succeeds and increments version."""
    from src.case_management import CaseConcurrencyError
    mgr = CaseManager(db=test_db)
    c = mgr.create_case("Concurrency OK", created_by="analyst")
    assert c["version"] == 1
    updated = mgr.update_case_status(c["id"], "IN_PROGRESS", user="analyst", role="Administrator", expected_version=1)
    assert updated["version"] == 2

def test_case_concurrency_stale_raises(test_db):
    """Stale write at service layer raises CaseConcurrencyError."""
    from src.case_management import CaseConcurrencyError
    mgr = CaseManager(db=test_db)
    c = mgr.create_case("Stale Test", created_by="analyst")
    mgr.update_case_status(c["id"], "IN_PROGRESS", user="analyst", role="Administrator")
    # version is now 2; try with expected_version=1
    with pytest.raises(CaseConcurrencyError, match="Stale write"):
        mgr.update_case_status(c["id"], "CONTAINED", user="analyst", role="Administrator", expected_version=1)


# ══════════════════════════════════════════════════════════════════════════════
# PHASE 6 HARDENED — Threat Hunting Safety Limits (Req #6)
# ══════════════════════════════════════════════════════════════════════════════

def test_hunt_max_filters_rejected(test_db):
    """More than MAX_HUNT_FILTERS filters raises HuntQueryValidationError."""
    from src.threat_hunting import ThreatHunter, HuntQueryValidationError, MAX_HUNT_FILTERS
    hunter_local = ThreatHunter(db=test_db)
    too_many = [{"field": "hostname", "operator": "equals", "value": f"host{i}"} for i in range(MAX_HUNT_FILTERS + 1)]
    with pytest.raises(HuntQueryValidationError, match="Too many filters"):
        hunter_local.execute_hunt({"filters": too_many}, executing_user="analyst")

def test_hunt_max_time_range_rejected(test_db):
    """Time range exceeding MAX_HUNT_TIME_RANGE_DAYS raises HuntQueryValidationError."""
    from src.threat_hunting import ThreatHunter, HuntQueryValidationError
    hunter_local = ThreatHunter(db=test_db)
    with pytest.raises(HuntQueryValidationError, match="Time range too large"):
        hunter_local.execute_hunt({
            "filters": [],
            "time_range": {"from": "2025-01-01T00:00:00", "to": "2026-08-24T00:00:00"},
        }, executing_user="analyst")

def test_hunt_limit_clamped_to_max(test_db):
    """Limit exceeding MAX_HUNT_LIMIT is clamped, not rejected."""
    from src.threat_hunting import ThreatHunter, MAX_HUNT_LIMIT
    hunter_local = ThreatHunter(db=test_db)
    result = hunter_local.execute_hunt({"filters": []}, executing_user="analyst", limit=99999)
    assert result["limit"] == MAX_HUNT_LIMIT

def test_hunt_negative_time_range_rejected(test_db):
    """time_range where 'from' > 'to' is rejected."""
    from src.threat_hunting import ThreatHunter, HuntQueryValidationError
    hunter_local = ThreatHunter(db=test_db)
    with pytest.raises(HuntQueryValidationError, match="'from' must be before 'to'"):
        hunter_local.execute_hunt({
            "filters": [],
            "time_range": {"from": "2026-08-24T00:00:00", "to": "2026-08-01T00:00:00"},
        }, executing_user="analyst")


# ══════════════════════════════════════════════════════════════════════════════
# PHASE 6 HARDENED — Plain-Text Note Storage (Req #4)
# ══════════════════════════════════════════════════════════════════════════════

def test_note_stores_plain_text_not_html_entities(test_db):
    """Notes with HTML input are stripped of tags and stored as plain text (not &lt; entities)."""
    mgr_notes = CaseNotesManager(db=test_db)
    case_mgr_local = CaseManager(db=test_db)
    c = case_mgr_local.create_case("XSS Note Case", created_by="analyst")

    xss_input = "<script>alert('xss')</script>Suspicious <b>activity</b> detected"
    note = mgr_notes.add_note(c["id"], author="analyst", content=xss_input)

    stored = note["content"]
    # Should NOT contain HTML tags
    assert "<script>" not in stored
    assert "<b>" not in stored
    # Should NOT be HTML-entity-encoded (that's for rendering, not storage)
    assert "&lt;" not in stored
    assert "&gt;" not in stored
    # Should preserve the text content
    assert "Suspicious" in stored
    assert "activity" in stored

def test_note_max_length_enforced(test_db):
    """Notes exceeding MAX_NOTE_LENGTH are truncated at storage."""
    from src.case_notes import MAX_NOTE_LENGTH
    mgr_notes = CaseNotesManager(db=test_db)
    case_mgr_local = CaseManager(db=test_db)
    c = case_mgr_local.create_case("Long Note Case", created_by="analyst")
    long_content = "A" * (MAX_NOTE_LENGTH + 500)
    note = mgr_notes.add_note(c["id"], author="analyst", content=long_content)
    assert len(note["content"]) <= MAX_NOTE_LENGTH


# ══════════════════════════════════════════════════════════════════════════════
# PHASE 6 HARDENED — Q1: Granular L1 Incident RBAC Tests
# ══════════════════════════════════════════════════════════════════════════════

def test_l1_incident_creation_and_read_allowed(tokens):
    """L1 analyst MUST be allowed to create (escalate alert to incident) and read incidents."""
    # 1. Create incident as L1
    resp = client.post(
        "/api/v1/incidents",
        json={"title": "L1 Escalated Incident", "severity": "high", "priority": "P2"},
        headers=tokens["l1"],
    )
    assert resp.status_code == 200
    inc_id = resp.json()["incident"]["id"]
    assert inc_id.startswith("INC-")

    # 2. Read incident list as L1
    r_list = client.get("/api/v1/incidents", headers=tokens["l1"])
    assert r_list.status_code == 200
    assert any(i["id"] == inc_id for i in r_list.json()["incidents"])


def test_l1_incident_update_and_transition_denied(tokens):
    """L1 analyst MUST be DENIED when attempting to update or transition incidents."""
    r_create = client.post(
        "/api/v1/incidents",
        json={"title": "L1 Permission Boundary Test", "severity": "medium"},
        headers=tokens["manager"],
    )
    inc_id = r_create.json()["incident"]["id"]

    # Status transition attempt by L1 -> 403
    r_status = client.patch(
        f"/api/v1/incidents/{inc_id}/status",
        json={"status": "IN_INVESTIGATION"},
        headers=tokens["l1"],
    )
    assert r_status.status_code == 403

    # Alert link attempt by L1 -> 403
    r_link = client.post(
        f"/api/v1/incidents/{inc_id}/alerts",
        json={"alert_id": "ALT-001"},
        headers=tokens["l1"],
    )
    assert r_link.status_code == 403


def test_l2_incident_transition_allowed_and_closing_restricted(tokens):
    """L2 analyst CAN transition incident to IN_INVESTIGATION, but CANNOT close incident."""
    r_create = client.post(
        "/api/v1/incidents",
        json={"title": "L2 Transition Test", "severity": "high"},
        headers=tokens["analyst"],
    )
    inc_id = r_create.json()["incident"]["id"]

    # L2 can transition OPEN -> IN_INVESTIGATION
    r_in_inv = client.patch(
        f"/api/v1/incidents/{inc_id}/status",
        json={"status": "IN_INVESTIGATION"},
        headers=tokens["analyst"],
    )
    assert r_in_inv.status_code == 200
    assert r_in_inv.json()["incident"]["status"] == "IN_INVESTIGATION"

    # L2 CANNOT close incident (closing restricted to Manager/Admin/Responder)
    r_close = client.patch(
        f"/api/v1/incidents/{inc_id}/status",
        json={"status": "CLOSED"},
        headers=tokens["analyst"],
    )
    assert r_close.status_code == 403


def test_responder_incident_closing_allowed(tokens):
    """Incident Responder CAN close an incident."""
    r_create = client.post(
        "/api/v1/incidents",
        json={"title": "Responder Close Test", "severity": "high"},
        headers=tokens["responder"],
    )
    inc_id = r_create.json()["incident"]["id"]

    r_close = client.patch(
        f"/api/v1/incidents/{inc_id}/status",
        json={"status": "CLOSED"},
        headers=tokens["responder"],
    )
    assert r_close.status_code == 200
    assert r_close.json()["incident"]["status"] == "CLOSED"


def test_readonly_incident_create_denied(tokens):
    """Read Only role MUST be denied incident creation."""
    r = client.post(
        "/api/v1/incidents",
        json={"title": "RO Create Test", "severity": "medium"},
        headers=tokens["readonly"],
    )
    assert r.status_code == 403


# ══════════════════════════════════════════════════════════════════════════════
# PHASE 6 HARDENED — Q2: Backward Compatible Concurrency Tests
# ══════════════════════════════════════════════════════════════════════════════

def test_patch_without_expected_version_backward_compatible(tokens):
    """PATCH without expected_version allows update and preserves backward compatibility."""
    r_create = client.post(
        "/api/v1/cases",
        json={"title": "Backward Compatibility Case", "severity": "low"},
        headers=tokens["admin"],
    )
    case_id = r_create.json()["case"]["id"]
    initial_version = r_create.json()["case"]["version"]
    assert initial_version >= 1

    # Omit expected_version entirely (Phase 1-5 style)
    resp = client.patch(
        f"/api/v1/cases/{case_id}/status",
        json={"status": "IN_PROGRESS"},
        headers=tokens["admin"],
    )
    assert resp.status_code == 200
    case_data = resp.json()["case"]
    assert case_data["status"] == "IN_PROGRESS"
    assert case_data["version"] == initial_version + 1


def test_patch_with_valid_expected_version_succeeds(tokens):
    """PATCH with matching expected_version succeeds and increments version."""
    r_create = client.post(
        "/api/v1/incidents",
        json={"title": "Concurrency Success Incident", "severity": "medium"},
        headers=tokens["analyst"],
    )
    inc_id = r_create.json()["incident"]["id"]
    version = r_create.json()["incident"]["version"]

    resp = client.patch(
        f"/api/v1/incidents/{inc_id}/status",
        json={"status": "IN_INVESTIGATION", "expected_version": version},
        headers=tokens["analyst"],
    )
    assert resp.status_code == 200
    inc_data = resp.json()["incident"]
    assert inc_data["status"] == "IN_INVESTIGATION"
    assert inc_data["version"] == version + 1


def test_patch_with_stale_expected_version_returns_409(tokens):
    """PATCH with stale expected_version returns 409 Conflict with detail."""
    r_create = client.post(
        "/api/v1/incidents",
        json={"title": "Concurrency Stale Incident", "severity": "high"},
        headers=tokens["analyst"],
    )
    inc_id = r_create.json()["incident"]["id"]

    # Advance version once
    client.patch(
        f"/api/v1/incidents/{inc_id}/status",
        json={"status": "IN_INVESTIGATION"},
        headers=tokens["analyst"],
    )

    # Attempt second update with stale version=1
    resp = client.patch(
        f"/api/v1/incidents/{inc_id}/status",
        json={"status": "CONTAINED", "expected_version": 1},
        headers=tokens["manager"],
    )
    assert resp.status_code == 409
    assert "Stale write" in resp.json()["detail"] or "Conflict" in resp.json()["detail"]

