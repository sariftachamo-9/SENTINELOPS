import os
import hashlib
import hmac
import time
import json
import base64
import sqlite3

if not os.getenv("JWT_SECRET") and os.path.exists(".env"):
    with open(".env", "r") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())

SECRET_KEY = os.getenv("JWT_SECRET", "")
if not SECRET_KEY:
    raise RuntimeError(
        "JWT_SECRET environment variable is not set. "
        "Generate one with: python3 -c \"import secrets; print(secrets.token_hex(32))\" "
        "and set it in your .env file."
    )

ROLES_PERMISSIONS = {
    "Read Only": [
        "alerts.read", "incidents.read", "cases.read", "detections.read", "mitre.read",
        "threat_intel.read", "ioc.read", "hunting.read", "playbooks.read", "playbook.read", "reports.read", "assets.read",
        "telemetry.read", "scenarios.read", "metrics.read"
    ],
    "SOC Analyst L1": [
        "alerts.read", "alerts.update", "alerts.assign",
        "incidents.read", "incidents.create",
        "cases.read", "cases.create",
        "detections.read", "threat_intel.read", "ioc.read", "ioc.enrich",
        "hunting.read",
        "notes.write",
        "playbooks.read", "playbook.read", "playbooks.execute", "playbook.execute", "assets.read",
        "telemetry.read", "telemetry.ingest",
        "mitre.read", "scenarios.read", "scenarios.execute", "training.access", "metrics.read", "demo.execute"
    ],
    "SOC Analyst L2": [
        "alerts.read", "alerts.update", "alerts.assign",
        "incidents.read", "incidents.create", "incidents.update", "incidents.transition", "mitre.read",
        "cases.read", "cases.create",
        "detections.read",
        "threat_intel.read", "threat_intel.write",
        "ioc.read", "ioc.create", "ioc.update", "ioc.classify", "ioc.enrich",
        "hunting.read", "hunting.execute", "hunting.save", "hunting.promote",
        "evidence.add",
        "notes.write",
        "playbooks.read", "playbook.read", "playbooks.execute", "playbook.execute", "playbook.approve", "assets.read",
        "telemetry.read", "telemetry.ingest", "scenarios.read", "scenarios.execute", "training.access", "metrics.read", "demo.execute"
    ],
    "Threat Hunter": [
        "alerts.read", "incidents.read", "incidents.create", "incidents.update", "incidents.transition",
        "detections.read", "threat_intel.read", "threat_intel.write", "mitre.read",
        "ioc.read", "ioc.create", "ioc.update", "ioc.classify", "ioc.enrich",
        "hunting.read", "hunting.execute", "hunting.save", "hunting.promote",
        "evidence.add",
        "notes.write",
        "cases.read",
        "playbooks.read", "playbook.read", "playbook.execute",
        "assets.read", "telemetry.read", "telemetry.ingest", "scenarios.read", "scenarios.execute", "training.access", "metrics.read", "demo.execute"
    ],
    "Incident Responder": [
        "alerts.read",
        "incidents.read", "incidents.create", "incidents.update", "incidents.transition", "incidents.close", "mitre.read",
        "cases.read", "cases.create", "cases.manage", "cases.close",
        "evidence.add", "evidence.modify",
        "notes.write",
        "playbooks.read", "playbook.read", "playbooks.execute", "playbook.execute", "playbook.approve",
        "assets.read", "telemetry.read", "telemetry.ingest",
        "threat_intel.read", "threat_intel.write",
        "ioc.read", "ioc.create", "ioc.update", "ioc.classify", "ioc.enrich", "scenarios.read", "scenarios.execute", "training.access", "metrics.read", "demo.execute"
    ],
    "Detection Engineer": [
        "alerts.read",
        "detections.read", "detections.manage",
        "cases.read",
        "hunting.read", "hunting.execute",
        "playbooks.read", "playbook.read", "playbook.create", "playbook.update",
        "mitre.read", "telemetry.read", "telemetry.ingest",
        "threat_intel.read", "ioc.read", "ioc.enrich", "scenarios.read", "scenarios.execute", "training.access", "metrics.read", "demo.execute"
    ],
    "SOC Manager": [
        "alerts.read",
        "incidents.read", "incidents.create", "incidents.update", "incidents.transition", "incidents.close", "mitre.read",
        "cases.read", "cases.create", "cases.manage", "cases.close",
        "detections.read",
        "threat_intel.read", "threat_intel.write", "threat_intel.manage",
        "ioc.read", "ioc.create", "ioc.update", "ioc.classify", "ioc.enrich", "ioc.delete",
        "hunting.read",
        "evidence.add",
        "notes.write",
        "playbooks.read", "playbook.read", "playbook.create", "playbook.update", "playbook.execute", "playbook.approve", "playbook.disable", "playbook.delete", "reports.read", "reports.generate",
        "assets.read", "audit.read",
        "telemetry.read", "scenarios.read", "scenarios.execute", "training.access", "metrics.read", "demo.execute"
    ],
    "Administrator": ["*"]
}

def get_db_connection():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    db_path = os.path.join(base_dir, "soc_data.db")
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.execute("CREATE TABLE IF NOT EXISTS revoked_tokens (jti TEXT PRIMARY KEY, revoked_at TEXT)")
    conn.commit()
    return conn

def hash_password(password: str, salt: str = None) -> str:
    if not salt:
        salt = os.urandom(16).hex()
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100000)
    return f"{salt}${key.hex()}"

def verify_password(password: str, stored_hash: str) -> bool:
    try:
        salt, key_hex = stored_hash.split('$')
        recalculated = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100000)
        return hmac.compare_digest(recalculated.hex(), key_hex)
    except Exception:
        return False

def generate_token(username: str, role: str, expires_in_seconds: int = 900, token_type: str = "access", jti: str = None) -> str:
    """
    Generate JWT Token. Access tokens default to 15 minutes (900s).
    """
    if not jti:
        jti = hashlib.sha256(os.urandom(32)).hexdigest()
        
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "sub": username,
        "role": role,
        "type": token_type,
        "jti": jti,
        "iat": int(time.time()),
        "exp": int(time.time()) + expires_in_seconds
    }
    
    header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    
    signature_input = f"{header_b64}.{payload_b64}".encode()
    signature = hmac.new(SECRET_KEY.encode(), signature_input, hashlib.sha256).digest()
    sig_b64 = base64.urlsafe_b64encode(signature).decode().rstrip("=")
    
    return f"{header_b64}.{payload_b64}.{sig_b64}"

def create_access_token(data: dict, expires_delta: int = 900) -> str:
    """Convenience wrapper for generate_token."""
    username = data.get("sub", "user")
    role = data.get("role", "Read Only")
    return generate_token(username, role, expires_in_seconds=expires_delta)

def revoke_token(jti: str):
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        now_str = datetime_str = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        cursor.execute("INSERT OR REPLACE INTO revoked_tokens (jti, revoked_at) VALUES (?, ?)", (jti, now_str))
        conn.commit()
    finally:
        conn.close()

def is_token_revoked(jti: str) -> bool:
    if not jti:
        return False
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM revoked_tokens WHERE jti = ?", (jti,))
        return cursor.fetchone() is not None
    finally:
        conn.close()

def verify_token(token: str):
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        header_b64, payload_b64, sig_b64 = parts
        
        # Verify signature
        signature_input = f"{header_b64}.{payload_b64}".encode()
        expected_sig = hmac.new(SECRET_KEY.encode(), signature_input, hashlib.sha256).digest()
        actual_sig = base64.urlsafe_b64decode(sig_b64 + "==")
        
        if not hmac.compare_digest(expected_sig, actual_sig):
            return None
        
        payload_json = base64.urlsafe_b64decode(payload_b64 + "==").decode()
        payload = json.loads(payload_json)
        
        if payload.get("exp", 0) < time.time():
            return None
            
        if is_token_revoked(payload.get("jti")):
            return None
            
        return payload
    except Exception:
        return None

def has_permission(role: str, required_permission: str) -> bool:
    role_perms = ROLES_PERMISSIONS.get(role, [])
    if "*" in role_perms:
        return True
    if required_permission in role_perms:
        return True
    
    # Prefix matches or generic rules
    prefix = required_permission.split(".")[0]
    if f"{prefix}.*" in role_perms:
        return True
        
    # Match *.read permission mapping
    if required_permission.endswith(".read"):
        for perm in role_perms:
            if perm == "*.read" or (perm.endswith(".read") and perm.split(".")[0] == prefix):
                return True
                
    return False

