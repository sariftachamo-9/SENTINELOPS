import os
import json
import uuid
import ipaddress
import re
import collections
import time
from datetime import datetime
from typing import List, Dict, Any, Optional
from fastapi import FastAPI, HTTPException, Header, Depends, Query, BackgroundTasks, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from src.database import Database
from src.telemetry_normalizer import TelemetryNormalizer
from src.alert_rules import AlertRulesEngine
from src.ml_detector import MLAnomalyDetector
from src.risk_engine import RiskEngine
from src.investigations import InvestigationWorkspace
from src.case_management import CaseManager, CaseStateError
from src.assets import AssetManager
from src.soc_health import SOCHealthMonitor
from src.threat_intel import ThreatIntel
from src.mitre_coverage import MITRECoverageAnalyzer
from src.playbooks import PlaybookEngine
from src.reports import SOCReportGenerator
from src.security import generate_token, verify_token, revoke_token, has_permission, hash_password, verify_password
from src.audit import AuditLogger
from src.telemetry.pipeline import TelemetryPipeline
from src.telemetry.search import EventSearchService, SearchFilter
from src.telemetry.schema import TelemetryIngestRequest, TelemetryBatchRequest
from src.telemetry.health import TelemetryHealthMonitor
from src.telemetry.storage import SQLiteEventStore
# Phase 6 imports
from src.evidence import EvidenceManager, VALID_EVIDENCE_TYPES
from src.entity_model import EntityManager, VALID_ENTITY_TYPES
from src.case_notes import CaseNotesManager
from src.threat_hunting import ThreatHunter, HuntQueryValidationError
# Phase 6 hardened — first-class Incident model
from src.incident_manager import IncidentManager, IncidentStateError, IncidentConcurrencyError
from src.case_management import CaseConcurrencyError
# Phase 7 imports
from src.threat_intel.manager import EnrichmentManager

class CreateIOCRequest(BaseModel):
    type: str
    value: str
    confidence: Optional[int] = 80
    severity: Optional[str] = "medium"
    reputation: Optional[str] = "UNKNOWN"
    source: Optional[str] = "Analyst Manual Add"
    tags: Optional[List[str]] = []
    description: Optional[str] = ""

class ClassifyIOCRequest(BaseModel):
    classification: str
    reason: str

app = FastAPI(
    title="SENTINELOPS REST API",
    description="Modular API engine powering real-time security operations, telemetry ingestion, incident triage, threat hunting, and SOAR playbooks.",
    version="2.5.0"
)

# CORS configuration from environment variable or safe defaults
allowed_origins_env = os.getenv("ALLOWED_ORIGINS", "")
if allowed_origins_env:
    origins = [o.strip() for o in allowed_origins_env.split(",")]
else:
    origins = [
        "http://localhost:8002",
        "http://127.0.0.1:8002",
        "http://localhost:8001",
        "http://127.0.0.1:8001"
    ]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Custom sliding window rate limiter
class InMemoryRateLimiter:
    def __init__(self):
        self.requests = collections.defaultdict(list)
    
    def is_rate_limited(self, key: str, limit: int, window: int) -> bool:
        now = time.time()
        cutoff = now - window
        timestamps = self.requests[key]
        self.requests[key] = [t for t in timestamps if t > cutoff]
        if len(self.requests[key]) >= limit:
            return True
        self.requests[key].append(now)
        return False

rate_limiter = InMemoryRateLimiter()

def check_rate_limit(endpoint_type: str):
    def dependency(request: Request):
        if request.headers.get("X-Bypass-RateLimit") == "true" and os.getenv("TESTING", "").lower() == "true":
            return

        is_testing = os.getenv("TESTING", "").lower() == "true"
        force_limit = request.headers.get("X-Test-Force-RateLimit") == "true"

        limit_str = os.getenv(f"RATE_LIMIT_{endpoint_type.upper()}", "")
        if is_testing and not force_limit:
            limit, window = 10000, 60
        elif not limit_str:
            if endpoint_type == "login":
                limit, window = 5, 60
            elif endpoint_type == "ingest":
                limit, window = 120, 60
            else:
                limit, window = 60, 60
        else:
            try:
                parts = limit_str.split("/")
                limit = int(parts[0])
                window = int(parts[1])
            except Exception:
                limit, window = 60, 60

        client_ip = request.client.host if request.client else "127.0.0.1"
        key = f"{endpoint_type}:{client_ip}"
        if rate_limiter.is_rate_limited(key, limit, window):
            raise HTTPException(status_code=429, detail="Too Many Requests. Rate limit exceeded.")
    return dependency

@app.post("/api/test/reset_rate_limits")
@app.post("/api/test/clear_rate_limits")
def reset_rate_limits():
    if os.getenv("TESTING", "").lower() == "true":
        rate_limiter.requests.clear()
        return {"status": "success", "message": "Rate limits reset"}
    raise HTTPException(status_code=403, detail="Forbidden")

# Security headers middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net https://unpkg.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "connect-src 'self' http://localhost:8001 http://127.0.0.1:8001 http://localhost:8002 http://127.0.0.1:8002;"
    )
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    if os.getenv("HSTS_ENABLED", "false").lower() == "true":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response

# Core Instances
db = Database()
normalizer = TelemetryNormalizer()
rules_engine = AlertRulesEngine()
ml_detector = MLAnomalyDetector()
risk_engine = RiskEngine()
investigation_ws = InvestigationWorkspace(db)
case_mgr = CaseManager(db)
asset_mgr = AssetManager(db)
soc_health_mon = SOCHealthMonitor(db)
threat_intel = ThreatIntel()
mitre_analyzer = MITRECoverageAnalyzer()
playbook_engine = PlaybookEngine()
report_gen = SOCReportGenerator(db)
audit_logger = AuditLogger(db)
# Phase 6 instances
evidence_mgr = EvidenceManager(db)
entity_mgr = EntityManager(db)
notes_mgr = CaseNotesManager(db)
hunter = ThreatHunter(db)
incident_mgr = IncidentManager(db)  # Phase 6 hardened — first-class incident model
enrichment_mgr = EnrichmentManager(db)  # Phase 7 modular enrichment manager
# Phase 9 instances
from src.simulation.engine import ScenarioEngine
from src.simulation.training import TrainingManager
from src.soc_metrics import SOCMetricsEngine
scenario_engine = ScenarioEngine(db=db)
training_mgr = TrainingManager(db=db)
soc_metrics = SOCMetricsEngine(db=db)


# Phase 3 Telemetry Instances
telemetry_store = SQLiteEventStore(db_path=db.db_path)
telemetry_pipeline = TelemetryPipeline(storage=telemetry_store, db=db, alert_engine=rules_engine)
telemetry_search = EventSearchService(storage=telemetry_store)
telemetry_health_mon = TelemetryHealthMonitor()

# Data Schemas
def is_valid_ip(ip_str: str) -> bool:
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False

class AlertItem(BaseModel):
    title: str = Field(..., min_length=1, max_length=200)
    severity: str
    description: Optional[str] = ""
    source: Optional[str] = "system"
    destination: Optional[str] = "0.0.0.0"
    indicators: Optional[List[str]] = []
    environment: Optional[str] = "lab"

    @field_validator("severity")
    @classmethod
    def check_severity(cls, v):
        valid = {"low", "medium", "high", "critical"}
        if v.lower() not in valid:
            raise ValueError("Severity must be one of low, medium, high, critical")
        return v.lower()

    @field_validator("source", "destination")
    @classmethod
    def check_ip_or_host(cls, v):
        if not v or v in ("system", "localhost", "Unassigned"):
            return v
        if not any(char.isalpha() for char in v):
            if not is_valid_ip(v):
                raise ValueError("Invalid IP address format")
        return v

class IncidentItem(BaseModel):
    title: str = Field(..., min_length=1, max_length=200)
    severity: str
    description: Optional[str] = ""
    alert_id: Optional[str] = ""
    priority: Optional[str] = "P2"
    category: Optional[str] = "Security Incident"

    @field_validator("severity")
    @classmethod
    def check_severity(cls, v):
        valid = {"low", "medium", "high", "critical"}
        if v.lower() not in valid:
            raise ValueError("Severity must be one of low, medium, high, critical")
        return v.lower()

    @field_validator("priority")
    @classmethod
    def check_priority(cls, v):
        valid = {"P1", "P2", "P3", "P4"}
        if v.upper() not in valid:
            raise ValueError("Priority must be one of P1, P2, P3, P4")
        return v.upper()

class TelemetryPayload(BaseModel):
    source_type: Optional[str] = "auto"
    raw_event: Dict[str, Any]

class LoginRequest(BaseModel):
    username: str
    password: str

class PlaybookExecRequest(BaseModel):
    playbook_id: Optional[str] = None
    target: Optional[str] = "127.0.0.1"
    approved: Optional[bool] = False
    execution_mode: Optional[str] = None
    idempotency_key: Optional[str] = None
    alert_id: Optional[str] = None
    incident_id: Optional[str] = None
    case_id: Optional[str] = None

    @field_validator("target")
    @classmethod
    def check_target(cls, v):
        if v and not any(char.isalpha() for char in v):
            if not is_valid_ip(v):
                raise ValueError("Target must be a valid IP address or hostname")
        return v

class PlaybookPreviewRequest(BaseModel):
    target: Optional[str] = "127.0.0.1"
    context: Optional[Dict[str, Any]] = None

class PlaybookCreateRequest(BaseModel):
    playbook_id: Optional[str] = None
    name: str = Field(..., min_length=1, max_length=200)
    description: Optional[str] = ""
    trigger: Optional[Dict[str, Any]] = {}
    conditions: Optional[List[str]] = []
    actions: Optional[List[Dict[str, Any]]] = []
    required_permission: Optional[str] = "playbook.execute"
    approval_required: Optional[bool] = False
    risk_level: Optional[str] = "LOW"
    enabled: Optional[bool] = True
    execution_mode: Optional[str] = "SIMULATION"

class PlaybookUpdateRequest(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    trigger: Optional[Dict[str, Any]] = None
    conditions: Optional[List[str]] = None
    actions: Optional[List[Dict[str, Any]]] = None
    required_permission: Optional[str] = None
    approval_required: Optional[bool] = None
    risk_level: Optional[str] = None
    enabled: Optional[bool] = None
    execution_mode: Optional[str] = None

class PlaybookApprovalRequest(BaseModel):
    reason: Optional[str] = ""


class UserCreateRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=8, max_length=100)
    role: str
    email: str

    @field_validator("username")
    @classmethod
    def check_username(cls, v):
        if not re.match(r"^[a-zA-Z0-9_-]+$", v):
            raise ValueError("Username can only contain alphanumeric characters, underscores, and dashes")
        return v

    @field_validator("role")
    @classmethod
    def check_role(cls, v):
        from src.security import ROLES_PERMISSIONS
        if v not in ROLES_PERMISSIONS:
            raise ValueError("Invalid role specified")
        return v

class UserRoleUpdateRequest(BaseModel):
    role: str

    @field_validator("role")
    @classmethod
    def check_role(cls, v):
        from src.security import ROLES_PERMISSIONS
        if v not in ROLES_PERMISSIONS:
            raise ValueError("Invalid role specified")
        return v

# Authentication and Authorization Dependencies
security_scheme = HTTPBearer(auto_error=False)

def get_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_scheme),
    token_param: Optional[str] = Query(None, alias="token")
):
    token = None
    if credentials:
        token = credentials.credentials
    elif token_param:
        token = token_param
        
    if not token:
        raise HTTPException(status_code=401, detail="Authentication credentials missing")
        
    payload = verify_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid token or token expired")
        
    return payload

def require_permission(required_perm: str):
    def dependency(request: Request, user: dict = Depends(get_current_user)):
        role = user.get("role", "Read Only")
        if not has_permission(role, required_perm):
            client_ip = request.client.host if request.client else "127.0.0.1"
            audit_logger.log(
                username=user.get("sub", "unknown"),
                role=role,
                action="UNAUTHORIZED_ACCESS_ATTEMPT",
                target_type="endpoint",
                target_id=required_perm,
                status="FAILED",
                ip_address=client_ip
            )
            raise HTTPException(
                status_code=403,
                detail=f"Permission denied. Required permission: {required_perm}"
            )
        return user
    return dependency

# Routes

@app.get("/")
def read_root():
    return {
        "service": "SENTINELOPS API",
        "status": "online",
        "version": "2.5.0",
        "documentation": "/docs"
    }

@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "soc-platform",
        "timestamp": datetime.now().isoformat()
    }

@app.post("/api/auth/login", dependencies=[Depends(check_rate_limit("login"))])
def login(request: Request, req: LoginRequest):
    """
    Authentication endpoint with generic failures and rate limiting.
    """
    client_ip = request.client.host if request.client else "127.0.0.1"
    lab_admin_pass = os.getenv("LAB_ADMIN_PASSWORD", "")
    
    # Generic error message to prevent enumeration
    generic_error = HTTPException(status_code=401, detail="Invalid username or password")
    
    if req.username == "admin":
        if lab_admin_pass and req.password == lab_admin_pass:
            token = generate_token("admin", "Administrator")
            audit_logger.log("admin", "Administrator", "LOGIN_SUCCESS", "auth", "admin", ip_address=client_ip)
            return {"access_token": token, "token_type": "bearer", "role": "Administrator"}
        else:
            audit_logger.log("admin", "Administrator", "LOGIN_FAILED", "auth", "admin", status="FAILED", ip_address=client_ip)
            raise generic_error
            
    cursor = db.get_cursor()
    cursor.execute("SELECT password_hash, role FROM users WHERE username = ? AND is_active = 1", (req.username,))
    row = cursor.fetchone()
    
    if row and verify_password(req.password, row["password_hash"]):
        token = generate_token(req.username, row["role"])
        audit_logger.log(req.username, row["role"], "LOGIN_SUCCESS", "auth", req.username, ip_address=client_ip)
        return {"access_token": token, "token_type": "bearer", "role": row["role"]}
        
    audit_logger.log(req.username, "unknown", "LOGIN_FAILED", "auth", req.username, status="FAILED", ip_address=client_ip)
    raise generic_error

@app.post("/api/auth/logout")
def logout(user: dict = Depends(get_current_user)):
    jti = user.get("jti")
    if jti:
        revoke_token(jti)
    audit_logger.log(user.get("sub", "unknown"), user.get("role", "unknown"), "LOGOUT", "auth", user.get("sub", "unknown"))
    return {"status": "success", "message": "Successfully logged out"}

@app.get("/api/stats", dependencies=[Depends(require_permission("alerts.read"))])
def get_stats():
    stats = db.get_stats()
    stats["uptime"] = "running"
    stats["start_time"] = datetime.now().isoformat()
    return stats

# Telemetry Ingestion & Query APIs (Phase 3)
@app.post("/api/v1/telemetry/ingest", dependencies=[Depends(require_permission("telemetry.ingest")), Depends(check_rate_limit("ingest"))])
def ingest_telemetry(
    req: TelemetryIngestRequest,
    user: dict = Depends(get_current_user)
):
    """
    Authenticated telemetry ingestion endpoint (single event).
    Executes: Validation -> Normalization -> Deduplication -> Storage -> Detection -> Alerting.
    """
    res = telemetry_pipeline.process_event(
        raw_event=req.raw_event,
        source_type=req.source_type,
        environment=req.environment,
        sensor_id=req.sensor_id
    )
    if res.status == "rejected":
        raise HTTPException(
            status_code=400,
            detail={"message": "Telemetry validation failed", "errors": res.validation_errors}
        )
    elif res.status == "error":
        raise HTTPException(
            status_code=500,
            detail={"message": "Telemetry processing error", "errors": res.pipeline_errors}
        )

    return {
        "status": "success",
        "event_id": res.event_id,
        "deduplicated": res.deduplicated,
        "alerts_triggered": res.alerts_triggered
    }

@app.post("/api/v1/telemetry/ingest/batch", dependencies=[Depends(require_permission("telemetry.ingest")), Depends(check_rate_limit("ingest_batch"))])
def ingest_telemetry_batch(
    req: TelemetryBatchRequest,
    user: dict = Depends(get_current_user)
):
    """
    Authenticated batch telemetry ingestion endpoint.
    Supports up to 500 events per request with partial failure handling.
    """
    summary = telemetry_pipeline.process_batch(
        raw_events=req.events,
        source_type=req.source_type,
        environment=req.environment,
        sensor_id=req.sensor_id
    )
    return {
        "status": "success",
        "batch_summary": summary
    }

@app.get("/api/v1/telemetry/events", dependencies=[Depends(require_permission("telemetry.read"))])
def search_telemetry_events(
    time_from: Optional[str] = Query(None),
    time_to: Optional[str] = Query(None),
    source_type: Optional[str] = Query(None),
    hostname: Optional[str] = Query(None),
    source_ip: Optional[str] = Query(None),
    destination_ip: Optional[str] = Query(None),
    username: Optional[str] = Query(None),
    event_type: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    process_name: Optional[str] = Query(None),
    asset_id: Optional[str] = Query(None),
    environment: Optional[str] = Query(None),
    search_query: Optional[str] = Query(None),
    simulation: Optional[bool] = Query(None),
    source_mode: Optional[str] = Query(None, description="Filter mode: live | simulation | all"),
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0)
):
    """
    Search normalized telemetry events using secure, parameterized filters.
    """
    search_filter = SearchFilter(
        time_from=time_from,
        time_to=time_to,
        source_type=source_type,
        hostname=hostname,
        source_ip=source_ip,
        destination_ip=destination_ip,
        username=username,
        event_type=event_type,
        severity=severity,
        process_name=process_name,
        asset_id=asset_id,
        environment=environment,
        search_query=search_query,
        simulation=simulation,
        source_mode=source_mode,
        limit=limit,
        offset=offset
    )
    res = telemetry_search.search(search_filter)
    return res.model_dump()

@app.get("/api/v1/telemetry/events/{event_id}", dependencies=[Depends(require_permission("telemetry.read"))])
def get_telemetry_event(event_id: str):
    """
    Retrieve single event details by event_id, including raw_event and normalized fields.
    """
    ev = telemetry_search.get_event_details(event_id)
    if not ev:
        raise HTTPException(status_code=404, detail=f"Telemetry event '{event_id}' not found")
    return ev.model_dump()

@app.get("/api/v1/telemetry/timeline/{entity_type}/{entity_value}", dependencies=[Depends(require_permission("telemetry.read"))])
def get_telemetry_timeline(entity_type: str, entity_value: str, limit: int = Query(100, ge=1, le=500)):
    """
    Retrieve chronological event timeline for host, user, IP, or asset.
    """
    res = telemetry_search.get_timeline(entity_type, entity_value, limit=limit)
    return res.model_dump()

@app.get("/api/v1/telemetry/health")
def get_telemetry_health():
    """
    Returns telemetry ingestion engine health, metrics, EPS, and adapter status.
    """
    total_stored = telemetry_store.count_events()
    return telemetry_health_mon.get_health_summary(storage_count=total_stored)

@app.get("/api/v1/telemetry/adapters")
def list_telemetry_adapters():
    """
    List telemetry source adapters and configuration status.
    """
    from src.telemetry.normalizer import EnhancedTelemetryNormalizer
    normalizer_inst = EnhancedTelemetryNormalizer()
    return {
        "adapters": normalizer_inst.get_adapter_statuses()
    }

# Phase 4 Vendor Integration Webhooks & Integration Health API
@app.get("/api/v1/integrations/health", dependencies=[Depends(require_permission("telemetry.read"))])
def get_integrations_health():
    """
    Returns integration status (ONLINE, OFFLINE, SIMULATION, NOT_CONFIGURED), reachability, metrics, and error rates.
    """
    from src.telemetry.integration_health import IntegrationHealthManager
    mgr = IntegrationHealthManager()
    return {
        "status": "success",
        "integrations": mgr.get_all_health()
    }

@app.post("/api/v1/integrations/wazuh/ingest", dependencies=[Depends(require_permission("telemetry.ingest"))])
def ingest_wazuh_alert(raw_event: dict, user: dict = Depends(get_current_user)):
    """Wazuh Manager Webhook Ingestion Endpoint."""
    res = telemetry_pipeline.process_event(raw_event=raw_event, source_type="wazuh", environment="lab")
    return {"status": "success", "event_id": res.event_id, "alerts_triggered": res.alerts_triggered}

@app.post("/api/v1/integrations/suricata/ingest", dependencies=[Depends(require_permission("telemetry.ingest"))])
def ingest_suricata_eve(raw_event: dict, user: dict = Depends(get_current_user)):
    """Suricata EVE JSON Webhook Ingestion Endpoint."""
    res = telemetry_pipeline.process_event(raw_event=raw_event, source_type="suricata", environment="lab")
    return {"status": "success", "event_id": res.event_id, "alerts_triggered": res.alerts_triggered}

@app.post("/api/v1/integrations/zeek/ingest", dependencies=[Depends(require_permission("telemetry.ingest"))])
def ingest_zeek_log(raw_event: dict, user: dict = Depends(get_current_user)):
    """Zeek NSM Webhook Ingestion Endpoint."""
    res = telemetry_pipeline.process_event(raw_event=raw_event, source_type="zeek", environment="lab")
    return {"status": "success", "event_id": res.event_id, "alerts_triggered": res.alerts_triggered}

# Phase 5 Data Schemas
class AlertStatusUpdateRequest(BaseModel):
    status: str
    fp_reason: Optional[str] = ""

    @field_validator("status")
    @classmethod
    def check_status(cls, v):
        valid = {"NEW", "ACKNOWLEDGED", "INVESTIGATING", "CONFIRMED", "RESOLVED", "FALSE_POSITIVE"}
        if v.upper() not in valid:
            raise ValueError(f"Status must be one of {', '.join(valid)}")
        return v.upper()

class RuleToggleRequest(BaseModel):
    enabled: bool

class RuleCreateUpdateRequest(BaseModel):
    rule_id: str
    name: str
    description: Optional[str] = ""
    severity: Optional[str] = "medium"
    confidence: Optional[int] = 80
    enabled: Optional[bool] = True
    event_conditions: List[Dict[str, Any]]
    threshold: Optional[int] = 1
    time_window: Optional[int] = 60
    mitre_tactic: Optional[str] = "Execution"
    mitre_technique_id: Optional[str] = "T1059"
    mitre_technique_name: Optional[str] = "Command and Scripting Interpreter"
    references: Optional[List[str]] = []
    false_positive_guidance: Optional[str] = ""

# Alerts API
@app.get("/api/alerts", dependencies=[Depends(require_permission("alerts.read"))])
def get_alerts(limit: int = 100):
    return db.get_alerts(limit=limit)

@app.get("/api/v1/alerts/{alert_id}/evidence", dependencies=[Depends(require_permission("alerts.read"))])
def get_alert_evidence(alert_id: str):
    """
    Retrieve structured evidence, triggering events, risk breakdown, and entity timeline for an alert.
    """
    cursor = db.get_cursor()
    cursor.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,))
    row = cursor.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found")
    
    alert = dict(row)
    for col in ['indicators', 'evidence', 'triggering_event_ids', 'analyst_notes']:
        try:
            alert[col] = json.loads(alert[col]) if alert.get(col) else []
        except Exception:
            alert[col] = []
    try:
        alert['risk_breakdown'] = json.loads(alert['risk_breakdown']) if alert.get('risk_breakdown') else {}
    except Exception:
        alert['risk_breakdown'] = {}

    # Fetch triggering event payloads
    evt_ids = alert.get("triggering_event_ids", [])
    raw_events = []
    if evt_ids:
        placeholders = ','.join('?' for _ in evt_ids)
        cursor.execute(f"SELECT * FROM events WHERE event_id IN ({placeholders}) ORDER BY timestamp ASC", evt_ids)
        raw_events = [dict(r) for r in cursor.fetchall()]

    # Fetch entity timeline (host/user/ip)
    entity_value = alert.get("affected_asset") or alert.get("source")
    timeline_res = telemetry_search.get_timeline("host", entity_value, limit=50) if entity_value else {"events": []}

    return {
        "alert": alert,
        "triggering_events": raw_events,
        "entity_timeline": timeline_res.model_dump().get("events", [])
    }

@app.patch("/api/v1/alerts/{alert_id}/status", dependencies=[Depends(require_permission("alerts.update"))])
@app.put("/api/v1/alerts/{alert_id}/status", dependencies=[Depends(require_permission("alerts.update"))])
def update_alert_status(alert_id: str, req: AlertStatusUpdateRequest, user: dict = Depends(get_current_user)):
    """
    Update alert lifecycle status (NEW, ACKNOWLEDGED, INVESTIGATING, CONFIRMED, RESOLVED, FALSE_POSITIVE).
    Audits status transition and records analyst rationale if marked FALSE_POSITIVE.
    """
    cursor = db.get_cursor()
    cursor.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,))
    row = cursor.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found")
    
    old_status = row["status"]
    now_str = datetime.now().isoformat()
    username = user.get("sub", "analyst")

    if req.status == "FALSE_POSITIVE":
        cursor.execute('''
            UPDATE alerts 
            SET status = ?, fp_reason = ?, fp_analyst = ?, fp_timestamp = ?
            WHERE id = ?
        ''', (req.status, req.fp_reason or "Marked false positive by analyst", username, now_str, alert_id))
    else:
        cursor.execute("UPDATE alerts SET status = ? WHERE id = ?", (req.status, alert_id))

    db.conn.commit()

    audit_logger.log(
        username=username,
        role=user.get("role", "SOC Analyst"),
        action="ALERT_STATUS_CHANGE",
        target_type="alert",
        target_id=alert_id,
        old_value={"status": old_status},
        new_value={"status": req.status, "fp_reason": req.fp_reason}
    )

    return {
        "status": "success",
        "alert_id": alert_id,
        "old_status": old_status,
        "new_status": req.status,
        "updated_at": now_str
    }

@app.post("/api/alerts", dependencies=[Depends(require_permission("alerts.update"))])
def create_alert(alert: AlertItem, user: dict = Depends(get_current_user)):
    alert_id = f"ALERT-{datetime.now().strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:4]}"
    alert_dict = alert.dict()
    alert_dict["id"] = alert_id
    alert_dict["timestamp"] = datetime.now().isoformat()
    
    ml_res = ml_detector.detect(alert_dict)
    alert_dict["anomaly_score"] = ml_res["anomaly_score"]
    alert_dict["confidence"] = int(ml_res["confidence"] * 100)
    
    enriched = threat_intel.enrich_alert(alert_dict)
    risk_res = risk_engine.calculate_risk(enriched)
    enriched["risk_score"] = risk_res["risk_score"]

    db.save_alert(enriched)

    audit_logger.log(user.get("sub", "system"), user.get("role", "system"), "ALERT_CREATED", "alert", alert_id, new_value=enriched)

    if alert.severity.lower() == "critical":
        inc_id = f"INC-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        db.save_incident({
            "id": inc_id,
            "title": f"Incident: {alert.title}",
            "severity": "critical",
            "priority": "P1",
            "status": "open",
            "alert_id": alert_id,
            "description": alert.description,
            "category": "Critical Threat Auto-Escalation"
        })
        audit_logger.log("system", "System", "INCIDENT_CREATED", "incident", inc_id)

    return {"status": "success", "alert_id": alert_id, "alert": enriched}

@app.delete("/api/alerts/{alert_id}")
def delete_alert(alert_id: str, user: dict = Depends(get_current_user)):
    # Restrict alert deletion strictly to Administrator
    if user.get("role") != "Administrator":
        audit_logger.log(user.get("sub"), user.get("role"), "UNAUTHORIZED_ALERT_DELETE", "alert", alert_id, status="FAILED")
        raise HTTPException(status_code=403, detail="Permission denied. Only Administrators can delete alerts.")
        
    cursor = db.get_cursor()
    # Get current alert state for audit log
    cursor.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,))
    row = cursor.fetchone()
    old_val = dict(row) if row else None
    
    cursor.execute("DELETE FROM alerts WHERE id = ?", (alert_id,))
    db.conn.commit()
    
    audit_logger.log(user.get("sub"), user.get("role"), "ALERT_DELETED", "alert", alert_id, old_value=old_val)
    return {"status": "success", "message": f"Alert {alert_id} deleted"}

# Detection Engine Management APIs (Phase 5)
@app.get("/api/v1/detections/rules", dependencies=[Depends(require_permission("detections.read"))])
def list_detection_rules():
    """
    List all detection rules and their configuration status.
    """
    from src.detection_engine import DetectionEngine
    engine = DetectionEngine(db=db)
    return {"rules": engine.get_all_rules()}

@app.get("/api/v1/detections/rules/{rule_id}", dependencies=[Depends(require_permission("detections.read"))])
def get_detection_rule(rule_id: str):
    """
    Retrieve single detection rule details.
    """
    from src.detection_engine import DetectionEngine
    engine = DetectionEngine(db=db)
    rules = engine.get_all_rules()
    for r in rules:
        if r.get("rule_id") == rule_id:
            return r
    raise HTTPException(status_code=404, detail=f"Detection rule '{rule_id}' not found")

@app.post("/api/v1/detections/rules", dependencies=[Depends(require_permission("detections.manage"))])
def create_detection_rule(req: RuleCreateUpdateRequest, user: dict = Depends(get_current_user)):
    """
    Create a new data-driven detection rule. Audited and restricted to Detection Engineers / Administrators.
    """
    cursor = db.get_cursor()
    cursor.execute("SELECT id FROM detection_rules WHERE id = ?", (req.rule_id,))
    if cursor.fetchone():
        raise HTTPException(status_code=400, detail=f"Rule ID '{req.rule_id}' already exists")

    rule_dict = req.dict()
    now_str = datetime.now().isoformat()
    username = user.get("sub", "engineer")

    cursor.execute('''
        INSERT INTO detection_rules 
        (id, rule_name, description, severity, category, mitre_tactic, mitre_technique_id, 
         mitre_technique_name, rule_type, rule_logic, enabled, created_by, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        req.rule_id,
        req.name,
        req.description,
        req.severity,
        req.mitre_tactic,
        req.mitre_tactic,
        req.mitre_technique_id,
        req.mitre_technique_name,
        "threshold" if req.threshold > 1 else "signature",
        json.dumps(rule_dict),
        1 if req.enabled else 0,
        username,
        now_str
    ))
    db.conn.commit()

    audit_logger.log(
        username=username,
        role=user.get("role", "Detection Engineer"),
        action="DETECTION_RULE_CREATED",
        target_type="detection_rule",
        target_id=req.rule_id,
        new_value=rule_dict
    )

    return {"status": "success", "rule_id": req.rule_id, "rule": rule_dict}

@app.put("/api/v1/detections/rules/{rule_id}", dependencies=[Depends(require_permission("detections.manage"))])
def update_detection_rule(rule_id: str, req: RuleCreateUpdateRequest, user: dict = Depends(get_current_user)):
    """
    Update an existing detection rule. Audited.
    """
    cursor = db.get_cursor()
    cursor.execute("SELECT * FROM detection_rules WHERE id = ?", (rule_id,))
    row = cursor.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail=f"Detection rule '{rule_id}' not found")

    old_val = dict(row)
    rule_dict = req.dict()
    username = user.get("sub", "engineer")

    cursor.execute('''
        UPDATE detection_rules 
        SET rule_name = ?, description = ?, severity = ?, category = ?, mitre_tactic = ?, 
            mitre_technique_id = ?, mitre_technique_name = ?, rule_type = ?, rule_logic = ?, enabled = ?
        WHERE id = ?
    ''', (
        req.name,
        req.description,
        req.severity,
        req.mitre_tactic,
        req.mitre_tactic,
        req.mitre_technique_id,
        req.mitre_technique_name,
        "threshold" if req.threshold > 1 else "signature",
        json.dumps(rule_dict),
        1 if req.enabled else 0,
        rule_id
    ))
    db.conn.commit()

    audit_logger.log(
        username=username,
        role=user.get("role", "Detection Engineer"),
        action="DETECTION_RULE_UPDATED",
        target_type="detection_rule",
        target_id=rule_id,
        old_value=old_val,
        new_value=rule_dict
    )

    return {"status": "success", "rule_id": rule_id, "rule": rule_dict}

@app.patch("/api/v1/detections/rules/{rule_id}/enable", dependencies=[Depends(require_permission("detections.manage"))])
def toggle_detection_rule(rule_id: str, req: RuleToggleRequest, user: dict = Depends(get_current_user)):
    """
    Enable or disable a detection rule. Audited.
    """
    cursor = db.get_cursor()
    cursor.execute("SELECT enabled FROM detection_rules WHERE id = ?", (rule_id,))
    row = cursor.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail=f"Detection rule '{rule_id}' not found")

    old_enabled = bool(row["enabled"])
    cursor.execute("UPDATE detection_rules SET enabled = ? WHERE id = ?", (1 if req.enabled else 0, rule_id))
    db.conn.commit()

    username = user.get("sub", "engineer")
    audit_logger.log(
        username=username,
        role=user.get("role", "Detection Engineer"),
        action="DETECTION_RULE_TOGGLED",
        target_type="detection_rule",
        target_id=rule_id,
        old_value={"enabled": old_enabled},
        new_value={"enabled": req.enabled}
    )

    return {"status": "success", "rule_id": rule_id, "enabled": req.enabled}

# Incidents API
@app.get("/api/incidents", dependencies=[Depends(require_permission("incidents.read"))])
def get_incidents(limit: int = 50):
    return db.get_incidents(limit=limit)

@app.post("/api/incidents", dependencies=[Depends(require_permission("incidents.create"))])
def create_incident(incident: IncidentItem, user: dict = Depends(get_current_user)):
    inc_id = f"INC-{datetime.now().strftime('%Y%m%d%H%M%S')}"
    inc_dict = incident.dict()
    inc_dict["id"] = inc_id
    inc_dict["created_at"] = datetime.now().isoformat()
    inc_dict["status"] = "open"
    db.save_incident(inc_dict)
    
    audit_logger.log(user.get("sub"), user.get("role"), "INCIDENT_CREATED", "incident", inc_id, new_value=inc_dict)
    return {"status": "success", "incident_id": inc_id}

@app.post("/api/incidents/{incident_id}/resolve", dependencies=[Depends(require_permission("incidents.update"))])
def resolve_incident(incident_id: str, user: dict = Depends(get_current_user)):
    cursor = db.get_cursor()
    cursor.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,))
    row = cursor.fetchone()
    old_val = dict(row) if row else None
    
    now_str = datetime.now().isoformat()
    cursor.execute(
        "UPDATE incidents SET status = 'resolved', resolved_at = ? WHERE id = ?",
        (now_str, incident_id)
    )
    db.conn.commit()
    
    audit_logger.log(user.get("sub"), user.get("role"), "INCIDENT_CLOSED", "incident", incident_id, old_value=old_val, new_value={"status": "resolved"})
    return {"status": "success", "message": f"Incident {incident_id} marked as resolved"}

# Case Management
@app.get("/api/cases", dependencies=[Depends(require_permission("cases.read"))])
def list_cases():
    return case_mgr.list_cases()

# Investigation Workspace
@app.get("/api/investigation/graph", dependencies=[Depends(require_permission("cases.read"))])
def get_entity_graph():
    return investigation_ws.get_entity_graph()

@app.get("/api/investigation/timeline", dependencies=[Depends(require_permission("cases.read"))])
def get_timeline():
    return investigation_ws.get_timeline()

# Threat Hunting
@app.get("/api/hunting/events", dependencies=[Depends(require_permission("hunting.read"))])
def hunt_events(q: str = Query("", description="Search term")):
    cursor = db.get_cursor()
    if q:
        search_pattern = f"%{q}%"
        cursor.execute('''
            SELECT * FROM events 
            WHERE source_ip LIKE ? OR destination_ip LIKE ? OR username LIKE ? OR hostname LIKE ? OR event_type LIKE ? OR process_name LIKE ?
            ORDER BY timestamp DESC LIMIT 100
        ''', (search_pattern, search_pattern, search_pattern, search_pattern, search_pattern, search_pattern))
    else:
        cursor.execute("SELECT * FROM events ORDER BY timestamp DESC LIMIT 100")
    
    rows = cursor.fetchall()
    return [dict(r) for r in rows]

# Assets API
@app.get("/api/assets", dependencies=[Depends(require_permission("assets.read"))])
def get_assets():
    return asset_mgr.get_assets()

# MITRE Coverage API
@app.get("/api/mitre/coverage", dependencies=[Depends(require_permission("mitre.read"))])
def get_mitre_coverage():
    return mitre_analyzer.get_coverage_matrix()

# Threat Intelligence Check
@app.get("/api/threat_intel/check", dependencies=[Depends(require_permission("threat_intel.read"))])
def check_threat_intel(indicator: str):
    return threat_intel.check_ip(indicator)

# Phase 7 — Threat Intelligence & IOC Management APIs
@app.get("/api/v1/threat_intel/enrich", dependencies=[Depends(require_permission("ioc.enrich"))])
def enrich_indicator_v1(indicator: str, ioc_type: Optional[str] = None, force_refresh: bool = False):
    """Enrich an indicator across all configured threat intelligence providers."""
    return enrichment_mgr.enrich_indicator(indicator, hint_type=ioc_type, force_refresh=force_refresh)

@app.get("/api/v1/iocs", dependencies=[Depends(require_permission("ioc.read"))])
def list_iocs_v1(type: Optional[str] = None, reputation: Optional[str] = None, search: Optional[str] = None, limit: int = 50, offset: int = 0):
    """List and search IOC records with filtering and pagination."""
    return enrichment_mgr.list_iocs(type_=type, reputation=reputation, search=search, limit=min(limit, 200), offset=offset)

@app.post("/api/v1/iocs", dependencies=[Depends(require_permission("ioc.create"))])
def create_ioc_v1(req: CreateIOCRequest, user: dict = Depends(get_current_user)):
    """Create a new IOC record manually."""
    try:
        ioc = enrichment_mgr.add_ioc(
            type_=req.type,
            value=req.value,
            confidence=req.confidence or 80,
            severity=req.severity or "medium",
            reputation=req.reputation or "UNKNOWN",
            source=req.source or "Analyst Manual Add",
            tags=req.tags or [],
            description=req.description or "",
            created_by=user.get("sub", "analyst")
        )
        return {"status": "success", "ioc": ioc}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/api/v1/iocs/{ioc_id}", dependencies=[Depends(require_permission("ioc.read"))])
def get_ioc_v1(ioc_id: str):
    """Get a detailed IOC record by ID or normalized value."""
    ioc = enrichment_mgr.get_ioc(ioc_id)
    if not ioc:
        raise HTTPException(status_code=404, detail=f"IOC '{ioc_id}' not found")
    return {"status": "success", "ioc": ioc}

@app.patch("/api/v1/iocs/{ioc_id}/classification", dependencies=[Depends(require_permission("ioc.classify"))])
def classify_ioc_v1(ioc_id: str, req: ClassifyIOCRequest, user: dict = Depends(get_current_user)):
    """Override IOC classification with mandatory analyst reason and audit trail."""
    try:
        updated = enrichment_mgr.update_analyst_classification(
            ioc_id=ioc_id,
            classification=req.classification,
            reason=req.reason,
            analyst=user.get("sub", "analyst"),
            role=user.get("role", "")
        )
        return {"status": "success", "ioc": updated}
    except ValueError as e:
        status_code = 404 if "not found" in str(e).lower() else 400
        raise HTTPException(status_code=status_code, detail=str(e))

@app.delete("/api/v1/iocs/{ioc_id}", dependencies=[Depends(require_permission("ioc.delete"))])
def delete_ioc_v1(ioc_id: str, user: dict = Depends(get_current_user)):
    """Archive/Delete an IOC record."""
    ioc = enrichment_mgr.get_ioc(ioc_id)
    if not ioc:
        raise HTTPException(status_code=404, detail=f"IOC '{ioc_id}' not found")
    cursor = db.get_cursor()
    cursor.execute("DELETE FROM iocs WHERE id = ?", (ioc["id"],))
    db.conn.commit()
    audit_logger.log(user.get("sub"), user.get("role"), "IOC_DELETED", "ioc", ioc["id"], old_value=ioc)
    return {"status": "success", "deleted_id": ioc["id"]}

# Playbooks API (Phase 8 SOAR Integration)

@app.get("/api/playbooks", dependencies=[Depends(require_permission("playbooks.read"))])
@app.get("/api/v1/playbooks", dependencies=[Depends(require_permission("playbook.read"))])
def get_playbooks_v1(enabled_only: bool = False):
    """Retrieve catalog of SOAR automation playbooks."""
    return playbook_engine.get_playbooks(enabled_only=enabled_only)

@app.post("/api/v1/playbooks", dependencies=[Depends(require_permission("playbook.create"))])
def create_playbook_v1(req: PlaybookCreateRequest, user: dict = Depends(get_current_user)):
    """Create a new custom SOAR playbook."""
    try:
        created = playbook_engine.create_playbook(req.model_dump(), created_by=user.get("sub", "system"))
        return {"status": "success", "playbook": created}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/api/v1/playbooks/{playbook_id}", dependencies=[Depends(require_permission("playbook.read"))])
def get_playbook_by_id_v1(playbook_id: str):
    """Get playbook details by ID."""
    pb = playbook_engine.get_playbook(playbook_id)
    if not pb:
        raise HTTPException(status_code=404, detail=f"Playbook '{playbook_id}' not found.")
    return {"status": "success", "playbook": pb}

@app.patch("/api/v1/playbooks/{playbook_id}", dependencies=[Depends(require_permission("playbook.update"))])
def update_playbook_v1(playbook_id: str, req: PlaybookUpdateRequest, user: dict = Depends(get_current_user)):
    """Update playbook configuration, triggers, or actions."""
    try:
        updates = {k: v for k, v in req.model_dump().items() if v is not None}
        updated = playbook_engine.update_playbook(playbook_id, updates, updated_by=user.get("sub", "system"))
        return {"status": "success", "playbook": updated}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.delete("/api/v1/playbooks/{playbook_id}", dependencies=[Depends(require_permission("playbook.delete"))])
def delete_playbook_v1(playbook_id: str, user: dict = Depends(get_current_user)):
    """Delete a playbook definition."""
    deleted = playbook_engine.delete_playbook(playbook_id, deleted_by=user.get("sub", "system"))
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Playbook '{playbook_id}' not found.")
    return {"status": "success", "deleted_id": playbook_id}

@app.post("/api/v1/playbooks/{playbook_id}/preview", dependencies=[Depends(require_permission("playbook.read"))])
def preview_playbook_v1(playbook_id: str, req: PlaybookPreviewRequest, user: dict = Depends(get_current_user)):
    """Non-mutating playbook dry-run preview."""
    res = playbook_engine.preview_playbook(
        playbook_id=playbook_id,
        target=req.target or "127.0.0.1",
        context=req.context or {},
        requested_by=user.get("sub", "analyst")
    )
    if res.get("status") == "FAILED":
        raise HTTPException(status_code=404, detail=res.get("reason"))
    return res

@app.post("/api/playbooks/execute", dependencies=[Depends(require_permission("playbooks.execute"))])
@app.post("/api/v1/playbooks/execute", dependencies=[Depends(require_permission("playbook.execute"))])
@app.post("/api/v1/playbooks/{playbook_id}/execute", dependencies=[Depends(require_permission("playbook.execute"))])
def execute_playbook_v1(req: PlaybookExecRequest, playbook_id: Optional[str] = None, user: dict = Depends(get_current_user)):
    """Trigger playbook execution with context, mode control, and approval check."""
    pb_id = playbook_id or req.playbook_id
    if not pb_id:
        raise HTTPException(status_code=400, detail="playbook_id is required.")
    
    ctx = {
        "alert_id": req.alert_id,
        "incident_id": req.incident_id,
        "case_id": req.case_id,
        "enrichment_mgr": enrichment_mgr
    }

    res = playbook_engine.execute_playbook(
        playbook_id=pb_id,
        target=req.target or "127.0.0.1",
        context=ctx,
        executed_by=user.get("sub", "analyst"),
        approved=req.approved or False,
        execution_mode=req.execution_mode,
        idempotency_key=req.idempotency_key,
        user_role=user.get("role", "")
    )

    st = res.get("status")
    if st in ["LIVE_MODE_DISABLED", "LAB_MODE_DISABLED", "SIMULATION_MODE_DISABLED"]:
        raise HTTPException(status_code=403, detail=res.get("reason") or f"Execution mode disabled ({st}).")
    if st == "LAB_TARGET_NOT_AUTHORIZED":
        raise HTTPException(status_code=400, detail=res.get("reason") or "Target not in authorized lab allowlist.")
    if st == "ALREADY_EXECUTING":
        raise HTTPException(status_code=409, detail=res.get("reason") or "Playbook execution is already in progress.")

    return res

@app.get("/api/v1/playbook-executions", dependencies=[Depends(require_permission("playbook.read"))])
def list_playbook_executions_v1(status: Optional[str] = None, limit: int = 50):
    """Retrieve immutable log of playbook executions."""
    executions = playbook_engine.list_executions(status=status, limit=limit)
    return {"status": "success", "count": len(executions), "executions": executions}

@app.get("/api/v1/playbook-executions/{execution_id}", dependencies=[Depends(require_permission("playbook.read"))])
def get_playbook_execution_v1(execution_id: str):
    """Get single execution record and detailed action outputs."""
    record = playbook_engine.get_execution(execution_id)
    if not record:
        raise HTTPException(status_code=404, detail=f"Execution '{execution_id}' not found.")
    return {"status": "success", "execution": record}

@app.post("/api/v1/playbook-executions/{execution_id}/approve", dependencies=[Depends(require_permission("playbook.approve"))])
def approve_execution_v1(execution_id: str, req: PlaybookApprovalRequest, user: dict = Depends(get_current_user)):
    """Approve a pending high-risk playbook execution."""
    res = playbook_engine.approve_execution(
        execution_id=execution_id,
        approved_by=user.get("sub", "approver"),
        reason=req.reason or "Analyst approval granted via API",
        user_role=user.get("role", "")
    )
    if res.get("status") == "FAILED":
        reason_msg = res.get("reason") or "Approval failed."
        if "Separation of duties" in reason_msg or "authorized" in reason_msg:
            raise HTTPException(status_code=403, detail=reason_msg)
        raise HTTPException(status_code=400, detail=reason_msg)
    return res

@app.post("/api/v1/playbook-executions/{execution_id}/reject", dependencies=[Depends(require_permission("playbook.approve"))])
def reject_execution_v1(execution_id: str, req: PlaybookApprovalRequest, user: dict = Depends(get_current_user)):
    """Reject a pending playbook execution."""
    res = playbook_engine.reject_execution(
        execution_id=execution_id,
        rejected_by=user.get("sub", "analyst"),
        reason=req.reason or "Execution rejected by analyst"
    )
    if res.get("status") == "FAILED":
        raise HTTPException(status_code=400, detail=res.get("reason") or "Rejection failed.")
    return res

@app.post("/api/v1/playbook-executions/{execution_id}/cancel", dependencies=[Depends(require_permission("playbook.execute"))])
def cancel_execution_v1(execution_id: str, req: PlaybookApprovalRequest, user: dict = Depends(get_current_user)):
    """Cancel an active or pending playbook execution."""
    res = playbook_engine.cancel_execution(
        execution_id=execution_id,
        cancelled_by=user.get("sub", "analyst"),
        reason=req.reason or "Cancelled by analyst"
    )
    if res.get("status") == "FAILED":
        raise HTTPException(status_code=400, detail=res.get("reason") or "Cancellation failed.")
    return res

@app.post("/api/v1/playbook-executions/{execution_id}/rollback", dependencies=[Depends(require_permission("playbook.execute"))])
def rollback_execution_v1(execution_id: str, user: dict = Depends(get_current_user)):
    """Roll back executed reversible playbook actions."""
    res = playbook_engine.rollback_execution(
        execution_id=execution_id,
        requested_by=user.get("sub", "analyst")
    )
    if res.get("status") == "FAILED":
        raise HTTPException(status_code=400, detail=res.get("reason") or "Rollback failed.")
    return res

# SOC Health API
@app.get("/api/soc/health", dependencies=[Depends(require_permission("alerts.read"))])
def get_soc_health():
    return soc_health_mon.get_system_health()

# Reports API
@app.get("/api/reports/download", dependencies=[Depends(require_permission("reports.read"))])
def download_report(fmt: str = "json", report_type: str = "daily_soc"):
    if fmt == "csv":
        return report_gen.generate_csv_report(report_type)
    return report_gen.generate_json_report(report_type)

# User and RBAC Management APIs
@app.get("/api/users", dependencies=[Depends(require_permission("users.manage"))])
def list_users():
    cursor = db.get_cursor()
    cursor.execute("SELECT id, username, email, role, is_active, created_at, last_login FROM users")
    rows = cursor.fetchall()
    return [dict(r) for r in rows]

@app.post("/api/users", dependencies=[Depends(require_permission("users.manage"))])
def create_user(req: UserCreateRequest, user: dict = Depends(get_current_user)):
    cursor = db.get_cursor()
    cursor.execute("SELECT 1 FROM users WHERE username = ?", (req.username,))
    if cursor.fetchone():
        raise HTTPException(status_code=400, detail="Username already exists")
        
    uid = str(uuid.uuid4())
    pwd_hash = hash_password(req.password)
    now_str = datetime.now().isoformat()
    
    cursor.execute('''
        INSERT INTO users (id, username, password_hash, email, role, is_active, created_at)
        VALUES (?, ?, ?, ?, ?, 1, ?)
    ''', (uid, req.username, pwd_hash, req.email, req.role, now_str))
    db.conn.commit()
    
    audit_logger.log(user.get("sub"), user.get("role"), "USER_CREATED", "user", req.username, new_value={"role": req.role, "email": req.email})
    return {"status": "success", "user_id": uid, "username": req.username}

@app.put("/api/users/{username}/role", dependencies=[Depends(require_permission("users.manage"))])
def update_user_role(username: str, req: UserRoleUpdateRequest, user: dict = Depends(get_current_user)):
    cursor = db.get_cursor()
    cursor.execute("SELECT role FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="User not found")
    
    old_role = row["role"]
    cursor.execute("UPDATE users SET role = ? WHERE username = ?", (req.role, username))
    db.conn.commit()
    
    audit_logger.log(user.get("sub"), user.get("role"), "ROLE_CHANGED", "user", username, old_value={"role": old_role}, new_value={"role": req.role})
    return {"status": "success", "message": f"User {username} role updated to {req.role}"}

@app.delete("/api/users/{username}", dependencies=[Depends(require_permission("users.manage"))])
def delete_user(username: str, user: dict = Depends(get_current_user)):
    if username == "admin":
        raise HTTPException(status_code=400, detail="Cannot delete default admin user")
        
    cursor = db.get_cursor()
    cursor.execute("SELECT 1 FROM users WHERE username = ?", (username,))
    if not cursor.fetchone():
        raise HTTPException(status_code=404, detail="User not found")
        
    cursor.execute("DELETE FROM users WHERE username = ?", (username,))
    db.conn.commit()
    
    audit_logger.log(user.get("sub"), user.get("role"), "USER_DELETED", "user", username)
    return {"status": "success", "message": f"User {username} deleted"}

# ============================================================
# PHASE 6 — Schemas
# ============================================================

class CaseCreateRequest(BaseModel):
    title: str = Field(..., min_length=1, max_length=200)
    description: Optional[str] = ""
    severity: Optional[str] = "medium"
    priority: Optional[str] = "MEDIUM"
    assigned_to: Optional[str] = "Unassigned"
    tags: Optional[List[str]] = []
    due_date: Optional[str] = ""

    @field_validator("severity")
    @classmethod
    def check_severity(cls, v):
        if v.lower() not in {"low","medium","high","critical"}:
            raise ValueError("Invalid severity")
        return v.lower()

    @field_validator("priority")
    @classmethod
    def check_priority(cls, v):
        if v.upper() not in {"LOW","MEDIUM","HIGH","CRITICAL"}:
            raise ValueError("Invalid priority")
        return v.upper()

class CaseStatusRequest(BaseModel):
    status: str
    expected_version: Optional[int] = None  # Optimistic concurrency (Req #5)

    @field_validator("status")
    @classmethod
    def check_status(cls, v):
        valid = {"OPEN","IN_PROGRESS","CONTAINED","RESOLVED","CLOSED"}
        if v.upper() not in valid:
            raise ValueError(f"Status must be one of {valid}")
        return v.upper()

class CaseDispositionRequest(BaseModel):
    disposition: str
    @field_validator("disposition")
    @classmethod
    def check_disposition(cls, v):
        valid = {"TRUE_POSITIVE","FALSE_POSITIVE","BENIGN","UNDETERMINED"}
        if v.upper() not in valid:
            raise ValueError(f"Disposition must be one of {valid}")
        return v.upper()

class CaseAssignRequest(BaseModel):
    assignee: str = Field(..., min_length=1, max_length=100)

class CaseLinkAlertRequest(BaseModel):
    alert_id: str = Field(..., min_length=1)

class CaseLinkIncidentRequest(BaseModel):
    incident_id: str = Field(..., min_length=1)

class EvidenceAddRequest(BaseModel):
    type: str
    source: str = Field(..., min_length=1, max_length=500)
    description: str = Field(..., min_length=1, max_length=2000)
    hash: Optional[str] = ""
    content_ref: Optional[str] = ""

    @field_validator("type")
    @classmethod
    def check_type(cls, v):
        if v not in VALID_EVIDENCE_TYPES:
            raise ValueError(f"Invalid evidence type. Must be one of: {sorted(VALID_EVIDENCE_TYPES)}")
        return v

class EvidenceUpdateRequest(BaseModel):
    description: Optional[str] = None
    hash: Optional[str] = None
    content_ref: Optional[str] = None
    reason: str = Field(..., min_length=1, max_length=500, description="Required audit reason for change")

# Phase 6 hardened — Incident Pydantic schemas
class IncidentCreateRequest(BaseModel):
    title: str = Field(..., min_length=1, max_length=500)
    description: str = Field("", max_length=5000)
    severity: str = Field("medium")
    priority: str = Field("P2")
    category: str = Field("Security Incident", max_length=200)
    related_alert_ids: List[str] = []
    mitre_techniques: List[str] = []
    assigned_to: str = Field("Unassigned", max_length=200)

    @field_validator("severity")
    @classmethod
    def check_severity(cls, v):
        valid = {"critical", "high", "medium", "low"}
        if v.lower() not in valid:
            raise ValueError(f"severity must be one of {valid}")
        return v.lower()

    @field_validator("priority")
    @classmethod
    def check_priority(cls, v):
        valid = {"P1", "P2", "P3", "P4"}
        if v.upper() not in valid:
            raise ValueError(f"priority must be one of {valid}")
        return v.upper()

class IncidentStatusRequest(BaseModel):
    status: str
    expected_version: Optional[int] = None

    @field_validator("status")
    @classmethod
    def check_status(cls, v):
        valid = {"OPEN","IN_INVESTIGATION","CONTAINED","RESOLVED","CLOSED"}
        if v.upper() not in valid:
            raise ValueError(f"Status must be one of {valid}")
        return v.upper()

class IncidentLinkAlertRequest(BaseModel):
    alert_id: str = Field(..., min_length=1)

class NoteRequest(BaseModel):
    content: str = Field(..., min_length=1, max_length=10000)

class HuntQueryRequest(BaseModel):
    time_range: Optional[Dict[str, str]] = {}
    filters: List[Dict[str, Any]] = []
    limit: Optional[int] = Field(100, ge=1, le=1000)
    offset: Optional[int] = Field(0, ge=0)

class HuntSaveRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    query: Dict[str, Any]

class HuntPromoteRequest(BaseModel):
    event_id: str
    case_id: Optional[str] = ""
    note: Optional[str] = ""

# ============================================================
# PHASE 6 — Case Management Endpoints
# ============================================================

@app.get("/api/v1/cases", dependencies=[Depends(require_permission("cases.read"))])
def list_cases_v1(
    status: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    assigned_to: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
):
    return case_mgr.list_cases(status=status, severity=severity,
                               assigned_to=assigned_to, limit=limit, offset=offset)

@app.post("/api/v1/cases", dependencies=[Depends(require_permission("cases.create"))])
def create_case_v1(req: CaseCreateRequest, user: dict = Depends(get_current_user)):
    try:
        case = case_mgr.create_case(
            title=req.title, description=req.description, severity=req.severity,
            priority=req.priority, created_by=user.get("sub","system"),
            tags=req.tags, due_date=req.due_date, assigned_to=req.assigned_to,
        )
        return {"status": "success", "case": case}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/api/v1/cases/{case_id}", dependencies=[Depends(require_permission("cases.read"))])
def get_case_v1(case_id: str):
    case = case_mgr.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found")
    return case

@app.patch("/api/v1/cases/{case_id}/status", dependencies=[Depends(require_permission("cases.read"))])
def update_case_status_v1(case_id: str, req: CaseStatusRequest, user: dict = Depends(get_current_user)):
    try:
        updated = case_mgr.update_case_status(
            case_id, req.status,
            user=user.get("sub","analyst"),
            role=user.get("role",""),
            expected_version=req.expected_version,
        )
        return {"status": "success", "case": updated}
    except CaseConcurrencyError as e:
        raise HTTPException(status_code=409, detail=str(e))
    except CaseStateError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

@app.patch("/api/v1/cases/{case_id}/disposition", dependencies=[Depends(require_permission("cases.read"))])
def update_case_disposition_v1(case_id: str, req: CaseDispositionRequest, user: dict = Depends(get_current_user)):
    try:
        updated = case_mgr.update_case_disposition(
            case_id, req.disposition, user=user.get("sub","analyst"), role=user.get("role","")
        )
        return {"status": "success", "case": updated}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.patch("/api/v1/cases/{case_id}/assign", dependencies=[Depends(require_permission("cases.manage"))])
def assign_case_v1(case_id: str, req: CaseAssignRequest, user: dict = Depends(get_current_user)):
    try:
        updated = case_mgr.assign_case(
            case_id, req.assignee, user=user.get("sub","analyst"), role=user.get("role","")
        )
        return {"status": "success", "case": updated}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

@app.post("/api/v1/cases/{case_id}/alerts", dependencies=[Depends(require_permission("cases.create"))])
def link_alert_to_case_v1(case_id: str, req: CaseLinkAlertRequest, user: dict = Depends(get_current_user)):
    try:
        result = case_mgr.link_alert_to_case(case_id, req.alert_id, linked_by=user.get("sub","analyst"))
        # Auto-extract entities from the alert
        cursor = db.get_cursor()
        cursor.execute("SELECT * FROM alerts WHERE id = ?", (req.alert_id,))
        row = cursor.fetchone()
        if row:
            entity_mgr.extract_entities_from_alert(dict(row), case_id=case_id)
        return result
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

@app.post("/api/v1/cases/{case_id}/incidents", dependencies=[Depends(require_permission("cases.create"))])
def link_incident_to_case_v1(case_id: str, req: CaseLinkIncidentRequest, user: dict = Depends(get_current_user)):
    try:
        result = case_mgr.link_incident_to_case(case_id, req.incident_id, linked_by=user.get("sub","analyst"))
        return result
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

@app.get("/api/v1/cases/{case_id}/workspace", dependencies=[Depends(require_permission("cases.read"))])
def get_case_workspace_v1(case_id: str):
    ws = investigation_ws.get_case_workspace(case_id)
    if not ws:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found")
    return ws

@app.get("/api/v1/cases/{case_id}/timeline", dependencies=[Depends(require_permission("cases.read"))])
def get_case_timeline_v1(
    case_id: str,
    time_from: Optional[str] = Query(None),
    time_to: Optional[str] = Query(None),
    hostname: Optional[str] = Query(None),
    username: Optional[str] = Query(None),
    source_ip: Optional[str] = Query(None),
    event_type: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    limit: int = Query(200, ge=1, le=1000),
):
    timeline = investigation_ws.get_investigation_timeline(
        case_id=case_id, time_from=time_from, time_to=time_to,
        hostname=hostname, username=username, source_ip=source_ip,
        event_type=event_type, severity=severity, limit=limit,
    )
    return {"case_id": case_id, "timeline": timeline, "total": len(timeline)}

@app.get("/api/v1/cases/{case_id}/entity-graph", dependencies=[Depends(require_permission("cases.read"))])
def get_case_entity_graph_v1(case_id: str):
    graph = investigation_ws.get_entity_graph(case_id=case_id)
    return graph

@app.get("/api/v1/cases/{case_id}/mitre", dependencies=[Depends(require_permission("cases.read"))])
def get_case_mitre_v1(case_id: str):
    return investigation_ws.get_case_mitre_coverage(case_id)

# ============================================================
# PHASE 6 HARDENED — First-Class Incident Endpoints
# ============================================================

@app.post("/api/v1/incidents", dependencies=[Depends(require_permission("incidents.create"))])
def create_incident_v1(req: IncidentCreateRequest, user: dict = Depends(get_current_user)):
    """Create a first-class Incident (Alert → Incident → Case workflow)."""
    try:
        inc = incident_mgr.create_incident(
            title=req.title,
            description=req.description,
            severity=req.severity,
            priority=req.priority,
            category=req.category,
            related_alert_ids=req.related_alert_ids,
            mitre_techniques=req.mitre_techniques,
            assigned_to=req.assigned_to,
            created_by=user.get("sub", "analyst"),
        )
        return {"status": "success", "incident": inc}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/api/v1/incidents", dependencies=[Depends(require_permission("incidents.read"))])
def list_incidents_v1(
    status: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    assigned_to: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
):
    """List all incidents with optional filters."""
    return incident_mgr.list_incidents(
        status=status, severity=severity, assigned_to=assigned_to,
        limit=limit, offset=offset,
    )

@app.get("/api/v1/incidents/{incident_id}", dependencies=[Depends(require_permission("incidents.read"))])
def get_incident_v1(incident_id: str):
    """Get a single incident by ID."""
    inc = incident_mgr.get_incident(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found")
    return inc

@app.patch("/api/v1/incidents/{incident_id}/status", dependencies=[Depends(require_permission("incidents.transition"))])
def update_incident_status_v1(
    incident_id: str, req: IncidentStatusRequest, user: dict = Depends(get_current_user)
):
    """Update incident status with optional optimistic concurrency check."""
    if req.status.upper() == "CLOSED":
        role = user.get("role", "")
        if not has_permission(role, "incidents.close"):
            raise HTTPException(
                status_code=403,
                detail="Permission denied: closing an incident requires 'incidents.close'"
            )
    try:
        inc = incident_mgr.update_incident_status(
            incident_id, req.status,
            user=user.get("sub", "analyst"),
            role=user.get("role", ""),
            expected_version=req.expected_version,
        )
        return {"status": "success", "incident": inc}
    except IncidentConcurrencyError as e:
        raise HTTPException(status_code=409, detail=str(e))
    except IncidentStateError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

@app.post("/api/v1/incidents/{incident_id}/alerts", dependencies=[Depends(require_permission("incidents.update"))])
def link_alert_to_incident_v1(
    incident_id: str, req: IncidentLinkAlertRequest, user: dict = Depends(get_current_user)
):
    """Link an alert to an incident (Alert → Incident linkage)."""
    try:
        inc = incident_mgr.link_alert_to_incident(
            incident_id, req.alert_id, linked_by=user.get("sub", "analyst")
        )
        return {"status": "success", "incident": inc}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

@app.get("/api/v1/incidents/{incident_id}/timeline", dependencies=[Depends(require_permission("incidents.read"))])
def get_incident_timeline_v1(incident_id: str):
    """Get unified timeline for an incident."""
    inc = incident_mgr.get_incident(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found")
    timeline = incident_mgr.get_incident_timeline(incident_id)
    return {"incident_id": incident_id, "timeline": timeline, "total": len(timeline)}

# ============================================================
# PHASE 6 — Evidence Endpoints
# ============================================================

@app.get("/api/v1/cases/{case_id}/evidence", dependencies=[Depends(require_permission("cases.read"))])
def list_evidence_v1(case_id: str):
    if not case_mgr.get_case(case_id):
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found")
    return {"evidence": evidence_mgr.list_case_evidence(case_id)}

@app.post("/api/v1/cases/{case_id}/evidence", dependencies=[Depends(require_permission("evidence.add"))])
def add_evidence_v1(case_id: str, req: EvidenceAddRequest, user: dict = Depends(get_current_user)):
    if not case_mgr.get_case(case_id):
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found")
    try:
        ev = evidence_mgr.add_evidence(
            case_id=case_id, evidence_type=req.type, source=req.source,
            description=req.description, added_by=user.get("sub","analyst"),
            hash_value=req.hash or "", content_ref=req.content_ref or "",
        )
        return {"status": "success", "evidence": ev}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/api/v1/cases/{case_id}/evidence/{evidence_id}", dependencies=[Depends(require_permission("cases.read"))])
def get_evidence_v1(case_id: str, evidence_id: str):
    ev = evidence_mgr.get_evidence(evidence_id, case_id)
    if not ev:
        raise HTTPException(status_code=404, detail="Evidence not found")
    return ev

@app.patch("/api/v1/cases/{case_id}/evidence/{evidence_id}", dependencies=[Depends(require_permission("evidence.modify"))])
def update_evidence_v1(case_id: str, evidence_id: str, req: EvidenceUpdateRequest, user: dict = Depends(get_current_user)):
    updates = {}
    if req.description is not None:
        updates["description"] = req.description
    if req.hash is not None:
        updates["hash"] = req.hash
    if req.content_ref is not None:
        updates["content_ref"] = req.content_ref
    if not updates:
        raise HTTPException(status_code=400, detail="No fields to update")
    try:
        ev = evidence_mgr.update_evidence_metadata(
            evidence_id, case_id, updates, updated_by=user.get("sub","analyst"),
            reason=req.reason,
        )
        return {"status": "success", "evidence": ev}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

# ============================================================
# PHASE 6 — Case Notes Endpoints
# ============================================================

@app.get("/api/v1/cases/{case_id}/notes", dependencies=[Depends(require_permission("cases.read"))])
def list_notes_v1(case_id: str):
    if not case_mgr.get_case(case_id):
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found")
    return {"notes": notes_mgr.list_case_notes(case_id)}

@app.post("/api/v1/cases/{case_id}/notes", dependencies=[Depends(require_permission("notes.write"))])
def add_note_v1(case_id: str, req: NoteRequest, user: dict = Depends(get_current_user)):
    if not case_mgr.get_case(case_id):
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found")
    note = notes_mgr.add_note(case_id=case_id, author=user.get("sub","analyst"), content=req.content)
    return {"status": "success", "note": note}

@app.patch("/api/v1/cases/{case_id}/notes/{note_id}", dependencies=[Depends(require_permission("notes.write"))])
def update_note_v1(case_id: str, note_id: str, req: NoteRequest, user: dict = Depends(get_current_user)):
    try:
        note = notes_mgr.update_note(note_id, case_id, req.content, updated_by=user.get("sub","analyst"))
        return {"status": "success", "note": note}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

# ============================================================
# PHASE 6 — Entity Endpoints
# ============================================================

@app.get("/api/v1/entities", dependencies=[Depends(require_permission("cases.read"))])
def search_entities_v1(
    entity_type: Optional[str] = Query(None),
    value: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
):
    if entity_type and entity_type not in VALID_ENTITY_TYPES:
        raise HTTPException(status_code=400, detail=f"Invalid entity_type. Must be one of: {sorted(VALID_ENTITY_TYPES)}")
    results = entity_mgr.query_entities(entity_type=entity_type, value_pattern=value, limit=limit, offset=offset)
    return {"entities": results, "total": len(results)}

@app.get("/api/v1/entities/{entity_id}", dependencies=[Depends(require_permission("cases.read"))])
def get_entity_v1(entity_id: str):
    ent = entity_mgr.get_entity(entity_id)
    if not ent:
        raise HTTPException(status_code=404, detail=f"Entity '{entity_id}' not found")
    rels = entity_mgr.get_entity_relationships(entity_id)
    return {"entity": ent, "relationships": rels}

@app.get("/api/v1/entities/{entity_id}/relationships", dependencies=[Depends(require_permission("cases.read"))])
def get_entity_relationships_v1(entity_id: str):
    rels = entity_mgr.get_entity_relationships(entity_id)
    return {"entity_id": entity_id, "relationships": rels, "total": len(rels)}

# ============================================================
# PHASE 6 — Threat Hunting Endpoints
# ============================================================

@app.post("/api/v1/hunting/execute", dependencies=[Depends(require_permission("hunting.execute"))])
def execute_hunt_v1(req: HuntQueryRequest, user: dict = Depends(get_current_user)):
    try:
        results = hunter.execute_hunt(
            query={"time_range": req.time_range, "filters": req.filters},
            executing_user=user.get("sub","analyst"),
            limit=req.limit or 100,
            offset=req.offset or 0,
        )
        return results
    except HuntQueryValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/api/v1/hunting/saved", dependencies=[Depends(require_permission("hunting.read"))])
def list_saved_hunts_v1(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    user: dict = Depends(get_current_user),
):
    return {"hunts": hunter.list_saved_hunts(
        requesting_user=user.get("sub","analyst"),
        requesting_role=user.get("role",""),
        limit=limit, offset=offset,
    )}

@app.post("/api/v1/hunting/saved", dependencies=[Depends(require_permission("hunting.save"))])
def save_hunt_v1(req: HuntSaveRequest, user: dict = Depends(get_current_user)):
    try:
        hunt = hunter.save_hunt(name=req.name, query=req.query, owner=user.get("sub","analyst"))
        return {"status": "success", "hunt": hunt}
    except HuntQueryValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/api/v1/hunting/saved/{hunt_id}", dependencies=[Depends(require_permission("hunting.read"))])
def get_saved_hunt_v1(hunt_id: str, user: dict = Depends(get_current_user)):
    hunt = hunter.get_saved_hunt(hunt_id, requesting_user=user.get("sub","analyst"), requesting_role=user.get("role",""))
    if not hunt:
        raise HTTPException(status_code=404, detail=f"Hunt '{hunt_id}' not found or access denied")
    return hunt

@app.delete("/api/v1/hunting/saved/{hunt_id}", dependencies=[Depends(require_permission("hunting.save"))])
def delete_saved_hunt_v1(hunt_id: str, user: dict = Depends(get_current_user)):
    deleted = hunter.delete_saved_hunt(hunt_id, requesting_user=user.get("sub","analyst"), requesting_role=user.get("role",""))
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Hunt '{hunt_id}' not found or access denied")
    return {"status": "success", "hunt_id": hunt_id}

@app.post("/api/v1/hunting/promote", dependencies=[Depends(require_permission("hunting.promote"))])
def promote_hunt_result_v1(req: HuntPromoteRequest, user: dict = Depends(get_current_user)):
    ref = hunter.promote_to_alert_reference(
        event_id=req.event_id,
        analyst=user.get("sub","analyst"),
        case_id=req.case_id or "",
        note=req.note or "",
    )
    return {"status": "success", "reference": ref}

# ============================================================
# PHASE 6 — Audit Log Endpoint
# ============================================================

@app.get("/api/v1/audit/logs", dependencies=[Depends(require_permission("audit.read"))])
def get_audit_logs_v1(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    action: Optional[str] = Query(None),
    target_type: Optional[str] = Query(None),
    username: Optional[str] = Query(None),
):
    cursor = db.get_cursor()
    conditions, params = [], []
    if action:
        conditions.append("action = ?")
        params.append(action)
    if target_type:
        conditions.append("target_type = ?")
        params.append(target_type)
    if username:
        conditions.append("username = ?")
        params.append(username)
    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    count_params = list(params)
    params.extend([limit, offset])
    cursor.execute(f"SELECT COUNT(*) FROM audit_logs {where}", count_params)
    total = cursor.fetchone()[0]
    cursor.execute(f"SELECT * FROM audit_logs {where} ORDER BY timestamp DESC LIMIT ? OFFSET ?", params)
    logs = [dict(r) for r in cursor.fetchall()]
    return {"logs": logs, "total": total, "limit": limit, "offset": offset}

# Legacy endpoints preserved
@app.get("/api/cases", dependencies=[Depends(require_permission("cases.read"))])
def list_cases():
    result = case_mgr.list_cases()
    return result.get("cases", [])

@app.get("/api/investigation/graph", dependencies=[Depends(require_permission("cases.read"))])
def get_entity_graph():
    return investigation_ws.get_entity_graph()

@app.get("/api/investigation/timeline", dependencies=[Depends(require_permission("cases.read"))])
def get_timeline():
    return investigation_ws.get_investigation_timeline()

@app.get("/api/hunting/events", dependencies=[Depends(require_permission("hunting.read"))])
def hunt_events(q: str = Query("", description="Search term")):
    cursor = db.get_cursor()
    if q:
        search_pattern = f"%{q}%"
        cursor.execute(
            "SELECT * FROM events WHERE source_ip LIKE ? OR destination_ip LIKE ? "
            "OR username LIKE ? OR hostname LIKE ? OR event_type LIKE ? OR process_name LIKE ? "
            "ORDER BY timestamp DESC LIMIT 100",
            (search_pattern,) * 6,
        )
    else:
        cursor.execute("SELECT * FROM events ORDER BY timestamp DESC LIMIT 100")
    return [dict(r) for r in cursor.fetchall()]

if os.getenv("TESTING", "false").lower() == "true":
    @app.post("/api/test/clear_rate_limits")
    def clear_rate_limits():
        rate_limiter.requests.clear()
        return {"status": "success"}


# ============================================================
# PHASE 9 — Scenario, Training, Metrics & Demo Endpoints
# ============================================================

class ScenarioStartRequest(BaseModel):
    speed_multiplier: Optional[float] = Field(1.0, ge=0.1, le=50.0)

class ScenarioResetRequest(BaseModel):
    reason: Optional[str] = "User cancelled"

class TrainingStartRequest(BaseModel):
    scenario_id: str = Field(..., min_length=1, max_length=50)

class TrainingAnswerRequest(BaseModel):
    triage_verdict: Optional[str] = ""
    severity: Optional[str] = ""
    target_host: Optional[str] = ""
    mitre_technique: Optional[str] = ""
    ioc_classification: Optional[str] = ""
    attacker_ip: Optional[str] = ""
    malicious_ioc: Optional[str] = ""
    incident_escalated: Optional[bool] = False
    evidence_added: Optional[bool] = False
    case_notes: Optional[str] = ""
    recommended_soar: Optional[str] = ""
    soar_action: Optional[str] = ""
    resolution: Optional[str] = ""
    disposition: Optional[str] = ""

class DemoStartRequest(BaseModel):
    scenario_id: str = Field("SCEN-001", min_length=1, max_length=50)
    speed_multiplier: Optional[float] = Field(10.0, ge=0.1, le=50.0)


# -- Scenario Endpoints --

@app.get("/api/v1/scenarios", dependencies=[Depends(require_permission("scenarios.read"))])
def list_scenarios_api(user: dict = Depends(get_current_user)):
    """List all available simulation scenarios."""
    return {"scenarios": scenario_engine.list_scenarios()}


@app.get("/api/v1/scenarios/{scenario_id}", dependencies=[Depends(require_permission("scenarios.read"))])
def get_scenario_api(scenario_id: str, user: dict = Depends(get_current_user)):
    """Get a specific scenario definition."""
    scen = scenario_engine.get_scenario(scenario_id)
    if not scen:
        raise HTTPException(status_code=404, detail=f"Scenario '{scenario_id}' not found.")
    return scen


@app.post("/api/v1/scenarios/{scenario_id}/start", dependencies=[Depends(require_permission("scenarios.execute"))])
def start_scenario_api(scenario_id: str, req: ScenarioStartRequest, user: dict = Depends(get_current_user)):
    """Start a new scenario run."""
    analyst = user.get("sub", "system")
    result = scenario_engine.start_scenario(
        scenario_id=scenario_id,
        requested_by=analyst,
        speed_multiplier=req.speed_multiplier,
        sync_execute=True
    )
    if result.get("status") == "CONCURRENCY_LOCK_ERROR":
        raise HTTPException(status_code=409, detail=result.get("error", "Concurrent scenario already running."))
    if result.get("status") == "ERROR":
        raise HTTPException(status_code=400, detail=result.get("error", "Scenario start failed."))
    return result


@app.post("/api/v1/scenario-runs/{run_id}/pause", dependencies=[Depends(require_permission("scenarios.execute"))])
def pause_run_api(run_id: str, user: dict = Depends(get_current_user)):
    """Pause a running scenario."""
    result = scenario_engine.pause_run(run_id, requested_by=user.get("sub", "system"))
    if isinstance(result, dict) and result.get("status") == "ERROR":
        raise HTTPException(status_code=400, detail=result.get("error"))
    return result


@app.post("/api/v1/scenario-runs/{run_id}/resume", dependencies=[Depends(require_permission("scenarios.execute"))])
def resume_run_api(run_id: str, user: dict = Depends(get_current_user)):
    """Resume a paused scenario."""
    result = scenario_engine.resume_run(run_id, requested_by=user.get("sub", "system"))
    if isinstance(result, dict) and result.get("status") == "ERROR":
        raise HTTPException(status_code=400, detail=result.get("error"))
    return result


@app.post("/api/v1/scenario-runs/{run_id}/cancel", dependencies=[Depends(require_permission("scenarios.execute"))])
def cancel_run_api(run_id: str, req: ScenarioResetRequest = None, user: dict = Depends(get_current_user)):
    """Cancel a scenario run."""
    reason = (req.reason if req else None) or "User cancelled"
    result = scenario_engine.cancel_run(run_id, requested_by=user.get("sub", "system"), reason=reason)
    if isinstance(result, dict) and result.get("status") == "ERROR":
        raise HTTPException(status_code=400, detail=result.get("error"))
    return result


@app.post("/api/v1/scenario-runs/{run_id}/replay", dependencies=[Depends(require_permission("scenarios.execute"))])
def replay_run_api(run_id: str, user: dict = Depends(get_current_user)):
    """Replay a scenario by creating a new run. Historical run remains immutable."""
    result = scenario_engine.replay_run(run_id, requested_by=user.get("sub", "system"))
    if isinstance(result, dict) and result.get("status") == "ERROR":
        raise HTTPException(status_code=400, detail=result.get("error"))
    return result


@app.get("/api/v1/scenario-runs/{run_id}", dependencies=[Depends(require_permission("scenarios.read"))])
def get_run_api(run_id: str, user: dict = Depends(get_current_user)):
    """Get the current state of a scenario run."""
    run = scenario_engine.get_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail=f"Scenario run '{run_id}' not found.")
    return run


@app.get("/api/v1/scenario-runs/{run_id}/timeline", dependencies=[Depends(require_permission("scenarios.read"))])
def get_run_timeline_api(run_id: str, user: dict = Depends(get_current_user)):
    """Get the ordered event timeline for a scenario run."""
    run = scenario_engine.get_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail=f"Scenario run '{run_id}' not found.")
    timeline = scenario_engine.get_run_timeline(run_id)
    return {"run_id": run_id, "scenario_id": run.get("scenario_id"), "events": timeline}


@app.get("/api/v1/scenario-runs", dependencies=[Depends(require_permission("scenarios.read"))])
def list_runs_api(limit: int = Query(50, ge=1, le=200), user: dict = Depends(get_current_user)):
    """List all scenario runs."""
    return {"runs": scenario_engine.list_runs(limit=limit)}


# -- Training Endpoints --

@app.post("/api/v1/training/start", dependencies=[Depends(require_permission("training.access"))])
def start_training_api(req: TrainingStartRequest, user: dict = Depends(get_current_user)):
    """Start an analyst training session."""
    analyst = user.get("sub", "analyst")
    result = training_mgr.start_session(analyst_username=analyst, scenario_id=req.scenario_id)
    if result and result.get("status") == "ERROR":
        raise HTTPException(status_code=400, detail=result.get("error"))
    return result


@app.get("/api/v1/training/{session_id}", dependencies=[Depends(require_permission("training.access"))])
def get_training_api(session_id: str, user: dict = Depends(get_current_user)):
    """Get training session state and current prompt."""
    sess = training_mgr.get_session(session_id)
    if not sess:
        raise HTTPException(status_code=404, detail=f"Training session '{session_id}' not found.")
    # IDOR: Only analyst who owns session or admin/manager may view
    analyst = user.get("sub", "")
    role = user.get("role", "")
    if sess["analyst_username"] != analyst and role not in ("SOC Manager", "Administrator"):
        raise HTTPException(status_code=403, detail="Access denied: not your training session.")
    return sess


@app.post("/api/v1/training/{session_id}/hint", dependencies=[Depends(require_permission("training.access"))])
def get_hint_api(session_id: str, user: dict = Depends(get_current_user)):
    """Request an optional hint for the current training session."""
    sess = training_mgr.get_session(session_id)
    if not sess:
        raise HTTPException(status_code=404, detail=f"Training session '{session_id}' not found.")
    if sess["analyst_username"] != user.get("sub", "") and user.get("role") not in ("SOC Manager", "Administrator"):
        raise HTTPException(status_code=403, detail="Access denied.")
    return training_mgr.request_hint(session_id, analyst_username=user.get("sub", "analyst"))


@app.post("/api/v1/training/{session_id}/answer", dependencies=[Depends(require_permission("training.access"))])
def submit_answer_api(session_id: str, req: TrainingAnswerRequest, user: dict = Depends(get_current_user)):
    """Submit step answers for a training session."""
    sess = training_mgr.get_session(session_id)
    if not sess:
        raise HTTPException(status_code=404, detail=f"Training session '{session_id}' not found.")
    if sess["analyst_username"] != user.get("sub", "") and user.get("role") not in ("SOC Manager", "Administrator"):
        raise HTTPException(status_code=403, detail="Access denied.")
    if sess["status"] == "COMPLETED":
        raise HTTPException(status_code=400, detail="Training session already completed.")
    answers = req.model_dump()
    return training_mgr.submit_answers(session_id=session_id, answers=answers, analyst_username=user.get("sub", "analyst"))


@app.post("/api/v1/training/{session_id}/submit", dependencies=[Depends(require_permission("training.access"))])
def submit_training_api(session_id: str, req: TrainingAnswerRequest, user: dict = Depends(get_current_user)):
    """Submit training session for final scoring (alias for /answer)."""
    sess = training_mgr.get_session(session_id)
    if not sess:
        raise HTTPException(status_code=404, detail=f"Training session '{session_id}' not found.")
    if sess["analyst_username"] != user.get("sub", "") and user.get("role") not in ("SOC Manager", "Administrator"):
        raise HTTPException(status_code=403, detail="Access denied.")
    if sess["status"] == "COMPLETED":
        raise HTTPException(status_code=400, detail="Training session already submitted.")
    answers = req.model_dump()
    return training_mgr.submit_answers(session_id=session_id, answers=answers, analyst_username=user.get("sub", "analyst"))


@app.get("/api/v1/training/{session_id}/score", dependencies=[Depends(require_permission("training.access"))])
def get_training_score_api(session_id: str, user: dict = Depends(get_current_user)):
    """Get the scorecard for a completed training session."""
    sess = training_mgr.get_session(session_id)
    if not sess:
        raise HTTPException(status_code=404, detail=f"Training session '{session_id}' not found.")
    if sess["analyst_username"] != user.get("sub", "") and user.get("role") not in ("SOC Manager", "Administrator"):
        raise HTTPException(status_code=403, detail="Access denied.")
    if sess.get("status") != "COMPLETED":
        raise HTTPException(status_code=400, detail="Training session not yet submitted.")
    return sess.get("scorecard", {"status": "NO_SCORE_DATA"})


@app.get("/api/v1/training/{session_id}/report/json", dependencies=[Depends(require_permission("training.access"))])
def get_training_report_json(session_id: str, user: dict = Depends(get_current_user)):
    """Export training session report as JSON."""
    from src.reports import TrainingReportGenerator
    return TrainingReportGenerator(db=db).generate_training_json_report(session_id)


@app.get("/api/v1/training/{session_id}/report/csv", dependencies=[Depends(require_permission("training.access"))])
def get_training_report_csv(session_id: str, user: dict = Depends(get_current_user)):
    """Export training session report as CSV."""
    from fastapi.responses import PlainTextResponse
    from src.reports import TrainingReportGenerator
    csv_data = TrainingReportGenerator(db=db).generate_training_csv_report(session_id)
    return PlainTextResponse(content=csv_data, media_type="text/csv",
                             headers={"Content-Disposition": f"attachment; filename=training_{session_id}.csv"})


# -- SOC Metrics Endpoints --

@app.get("/api/v1/soc/metrics", dependencies=[Depends(require_permission("metrics.read"))])
def get_soc_metrics_api(user: dict = Depends(get_current_user)):
    """Get real-time calculated SOC operational metrics from stored platform data."""
    return soc_metrics.get_metrics()


@app.get("/api/v1/soc/metrics/timeline", dependencies=[Depends(require_permission("metrics.read"))])
def get_soc_metrics_timeline_api(days: int = Query(7, ge=1, le=30), user: dict = Depends(get_current_user)):
    """Get historical SOC metrics trend timeline."""
    return {"timeline": soc_metrics.get_metrics_timeline(days=days)}


# -- Demo Mode Endpoint --

@app.post("/api/v1/demo/start", dependencies=[Depends(require_permission("demo.execute"))])
def start_demo_api(req: DemoStartRequest, user: dict = Depends(get_current_user)):
    """
    Execute an end-to-end SOC demo simulation workflow.
    Runs chosen scenario through full pipeline: Telemetry → Detection → Correlation → Risk Score → Alert → Incident → Case → SOAR.
    Strictly simulation mode. No physical endpoints contacted.
    """
    analyst = user.get("sub", "demo_user")
    audit_logger.log(
        analyst, user.get("role", "SOC Analyst L1"),
        "DEMO_MODE_START", "demo", req.scenario_id,
        new_value={"scenario_id": req.scenario_id, "speed_multiplier": req.speed_multiplier, "source_mode": "simulation"}
    )

    # Run the selected scenario
    scen_result = scenario_engine.start_scenario(
        scenario_id=req.scenario_id,
        requested_by=analyst,
        speed_multiplier=req.speed_multiplier,
        sync_execute=True
    )
    if scen_result.get("status") == "CONCURRENCY_LOCK_ERROR":
        raise HTTPException(status_code=409, detail=scen_result.get("error"))

    # Automatically execute first available playbook in SIMULATION mode as part of demo
    cursor = db.get_cursor()
    cursor.execute("SELECT id FROM playbooks WHERE enabled = 1 LIMIT 1")
    pb_row = cursor.fetchone()
    playbook_result = None
    if pb_row:
        pb_id = pb_row[0]
        playbook_result = playbook_engine.execute_playbook(
            playbook_id=pb_id,
            executed_by=analyst,
            context={"execution_mode": "SIMULATION", "demo_mode": True}
        )

    # Retrieve metrics snapshot
    metrics_snap = soc_metrics.get_metrics()

    return {
        "demo_status": "COMPLETED",
        "source_mode": "simulation",
        "simulation_safety_notice": "SOC LAB — SIMULATION MODE. No physical endpoints were contacted. No real-world actions were performed.",
        "scenario_run": scen_result,
        "playbook_result": playbook_result,
        "metrics_snapshot": metrics_snap
    }
