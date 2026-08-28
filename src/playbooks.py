import json
import re
import uuid
import hashlib
from datetime import datetime
from typing import Dict, Any, List, Optional, Set
from src.audit import AuditLogger
from src.database import Database
from src.soar.actions import ACTION_REGISTRY, EndpointAdapterFactory
from src.soar.config import SOARConfig

def sanitize_secrets(data: Any) -> Any:
    """
    Recursively scrub sensitive keys (passwords, tokens, API keys, credentials, secret) from data.
    """
    if isinstance(data, dict):
        scrubbed = {}
        for k, v in data.items():
            if any(secret_kw in k.lower() for secret_kw in ["password", "token", "secret", "api_key", "credentials", "auth"]):
                scrubbed[k] = "******"
            else:
                scrubbed[k] = sanitize_secrets(v)
        return scrubbed
    elif isinstance(data, list):
        return [sanitize_secrets(item) for item in data]
    return data

class PlaybookEngine:
    """
    Phase 8 — Modular SOAR & Playbook Automation Engine.
    Handles server-side feature gates, target allowlisting, trigger matching,
    condition evaluation, dry-run preview, approval state machines, separation of duties,
    atomic concurrency locking, idempotent execution, safety controls, and rollback capability.
    """
    DEFAULT_PLAYBOOKS = [
        {
            "id": "PB-001",
            "playbook_id": "PB-001",
            "name": "Automated Threat Intel & IP Reputation Enrichment",
            "description": "Automatically queries threat feeds for attacking IP addresses and notifies duty analyst.",
            "trigger": {"event": "alert_created", "min_risk_score": 50},
            "conditions": ["alert.risk_score >= 50"],
            "actions": [
                {"action_type": "ENRICH_IOC"},
                {"action_type": "NOTIFY_ANALYST"}
            ],
            "required_permission": "playbook.execute",
            "approval_required": 0,
            "risk_level": "LOW",
            "enabled": 1,
            "execution_mode": "SIMULATION",
            "created_by": "System",
            "created_at": "2026-08-24T00:00:00Z",
            "updated_at": "2026-08-24T00:00:00Z"
        },
        {
            "id": "PB-002",
            "playbook_id": "PB-002",
            "name": "Controlled Endpoint Host Isolation",
            "description": "Isolates workstation network interface in simulated lab environment. Requires Analyst Approval.",
            "trigger": {"event": "high_risk_alert", "min_risk_score": 80},
            "conditions": ["alert.risk_score >= 80", "alert.status == 'NEW'"],
            "actions": [
                {"action_type": "ISOLATE_HOST"},
                {"action_type": "ADD_CASE_NOTE"}
            ],
            "required_permission": "playbook.execute",
            "approval_required": 1,
            "risk_level": "HIGH",
            "enabled": 1,
            "execution_mode": "SIMULATION",
            "created_by": "System",
            "created_at": "2026-08-24T00:00:00Z",
            "updated_at": "2026-08-24T00:00:00Z"
        },
        {
            "id": "PB-003",
            "playbook_id": "PB-003",
            "name": "User Account Suspend & Incident Escalation",
            "description": "Suspends compromised domain user tokens in lab DB and escalates incident. Requires Approval.",
            "trigger": {"event": "credential_access", "mitre_technique": "T1078"},
            "conditions": ["alert.severity in ['high', 'critical']"],
            "actions": [
                {"action_type": "DISABLE_ACCOUNT"},
                {"action_type": "CREATE_INCIDENT"}
            ],
            "required_permission": "playbook.execute",
            "approval_required": 1,
            "risk_level": "HIGH",
            "enabled": 1,
            "execution_mode": "SIMULATION",
            "created_by": "System",
            "created_at": "2026-08-24T00:00:00Z",
            "updated_at": "2026-08-24T00:00:00Z"
        },
        {
            "id": "PB-004",
            "playbook_id": "PB-004",
            "name": "Automated IOC Blocklist Escalation",
            "description": "Adds malicious IOCs to simulated blocklist and raises alert severity.",
            "trigger": {"event": "ioc_malicious"},
            "conditions": ["ioc.classification == 'MALICIOUS'"],
            "actions": [
                {"action_type": "ADD_IOC_SIMULATED_BLOCKLIST"},
                {"action_type": "CHANGE_ALERT_SEVERITY"}
            ],
            "required_permission": "playbook.execute",
            "approval_required": 0,
            "risk_level": "MEDIUM",
            "enabled": 1,
            "execution_mode": "SIMULATION",
            "created_by": "System",
            "created_at": "2026-08-24T00:00:00Z",
            "updated_at": "2026-08-24T00:00:00Z"
        }
    ]

    def __init__(self, db: Optional[Database] = None):
        self.db = db or Database()
        self.audit_logger = AuditLogger()
        self._ensure_seed_playbooks()

    def _ensure_seed_playbooks(self):
        cursor = self.db.get_cursor()
        for pb in self.DEFAULT_PLAYBOOKS:
            cursor.execute("SELECT id FROM playbooks WHERE id = ? OR playbook_id = ?", (pb["id"], pb["id"]))
            if not cursor.fetchone():
                self.create_playbook(pb, created_by="System")
            else:
                cursor.execute("""
                    UPDATE playbooks 
                    SET approval_required = ?, requires_approval = ?, risk_level = ?, execution_mode = ?, actions = ?
                    WHERE id = ? OR playbook_id = ?
                """, (
                    pb["approval_required"], pb["approval_required"], pb["risk_level"], pb["execution_mode"],
                    json.dumps(pb["actions"]), pb["id"], pb["id"]
                ))
                self.db.conn.commit()

    # =========================================================================
    # PLAYBOOK CRUD OPERATIONS
    # =========================================================================

    def get_playbooks(self, enabled_only: bool = False) -> List[Dict[str, Any]]:
        cursor = self.db.get_cursor()
        query = "SELECT * FROM playbooks"
        params = []
        if enabled_only:
            query += " WHERE enabled = 1"
        query += " ORDER BY id ASC"
        cursor.execute(query, params)
        rows = cursor.fetchall()
        result = []
        for r in rows:
            dict_r = dict(r)
            for field in ["trigger", "conditions", "actions"]:
                if isinstance(dict_r.get(field), str):
                    try:
                        dict_r[field] = json.loads(dict_r[field])
                    except Exception:
                        pass
            dict_r["requires_approval"] = bool(dict_r.get("approval_required") or dict_r.get("requires_approval"))
            dict_r["playbook_id"] = dict_r.get("playbook_id") or dict_r.get("id")
            dict_r["action_type"] = ", ".join([a.get("action_type", "") if isinstance(a, dict) else str(a) for a in dict_r.get("actions", [])])
            result.append(dict_r)
        return result

    def get_playbook(self, playbook_id: str) -> Optional[Dict[str, Any]]:
        cursor = self.db.get_cursor()
        cursor.execute("SELECT * FROM playbooks WHERE id = ? OR playbook_id = ?", (playbook_id, playbook_id))
        row = cursor.fetchone()
        if not row:
            return None
        dict_r = dict(row)
        for field in ["trigger", "conditions", "actions"]:
            if isinstance(dict_r.get(field), str):
                try:
                    dict_r[field] = json.loads(dict_r[field])
                except Exception:
                    pass
        appr_val = dict_r.get("approval_required")
        if appr_val is not None:
            dict_r["requires_approval"] = bool(int(appr_val) if isinstance(appr_val, (int, str)) and str(appr_val).isdigit() else appr_val)
        else:
            dict_r["requires_approval"] = bool(dict_r.get("requires_approval"))
        dict_r["playbook_id"] = dict_r.get("playbook_id") or dict_r.get("id")
        return dict_r

    def create_playbook(self, data: Dict[str, Any], created_by: str = "system") -> Dict[str, Any]:
        pb_id = data.get("playbook_id") or data.get("id") or f"PB-{uuid.uuid4().hex[:6].upper()}"
        name = data.get("name") or data.get("playbook_name") or f"Playbook {pb_id}"
        description = data.get("description", "")
        trigger = data.get("trigger") or {}
        conditions = data.get("conditions") or []
        actions = data.get("actions") or []
        req_perm = data.get("required_permission", "playbook.execute")
        if "approval_required" in data:
            appr_req = 1 if data["approval_required"] else 0
        elif "requires_approval" in data:
            appr_req = 1 if data["requires_approval"] else 0
        else:
            appr_req = 1 if data.get("risk_level", "").upper() in ["HIGH", "CRITICAL"] else 0
        risk_lvl = data.get("risk_level", "LOW").upper()
        enabled = 1 if data.get("enabled", True) else 0
        mode = data.get("execution_mode", "SIMULATION").upper()
        now_str = datetime.now().isoformat()

        cursor = self.db.get_cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO playbooks
            (id, playbook_id, name, description, trigger, conditions, actions, required_permission, approval_required, risk_level, enabled, execution_mode, created_by, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            pb_id, pb_id, name, description,
            json.dumps(trigger) if isinstance(trigger, (dict, list)) else str(trigger),
            json.dumps(conditions) if isinstance(conditions, list) else str(conditions),
            json.dumps(actions) if isinstance(actions, list) else str(actions),
            req_perm, appr_req, risk_lvl, enabled, mode, created_by, now_str, now_str
        ))
        self.db.conn.commit()

        self.audit_logger.log(
            username=created_by,
            role="User",
            action="PLAYBOOK_CREATED",
            target_type="playbook",
            target_id=pb_id,
            new_value=sanitize_secrets(data)
        )
        return self.get_playbook(pb_id)

    def update_playbook(self, playbook_id: str, updates: Dict[str, Any], updated_by: str = "system") -> Dict[str, Any]:
        pb = self.get_playbook(playbook_id)
        if not pb:
            raise ValueError(f"Playbook '{playbook_id}' not found.")

        old_val = pb.copy()
        cursor = self.db.get_cursor()
        now_str = datetime.now().isoformat()

        name = updates.get("name", pb.get("name"))
        desc = updates.get("description", pb.get("description"))
        trigger = updates.get("trigger", pb.get("trigger"))
        conditions = updates.get("conditions", pb.get("conditions"))
        actions = updates.get("actions", pb.get("actions"))
        req_perm = updates.get("required_permission", pb.get("required_permission"))
        appr_req = 1 if updates.get("approval_required", pb.get("requires_approval")) else 0
        risk_lvl = updates.get("risk_level", pb.get("risk_level")).upper()
        enabled = 1 if updates.get("enabled", pb.get("enabled")) else 0
        mode = updates.get("execution_mode", pb.get("execution_mode")).upper()

        cursor.execute('''
            UPDATE playbooks
            SET name = ?, description = ?, trigger = ?, conditions = ?, actions = ?,
                required_permission = ?, approval_required = ?, risk_level = ?, enabled = ?,
                execution_mode = ?, updated_at = ?
            WHERE id = ? OR playbook_id = ?
        ''', (
            name, desc,
            json.dumps(trigger) if isinstance(trigger, (dict, list)) else str(trigger),
            json.dumps(conditions) if isinstance(conditions, list) else str(conditions),
            json.dumps(actions) if isinstance(actions, list) else str(actions),
            req_perm, appr_req, risk_lvl, enabled, mode, now_str,
            playbook_id, playbook_id
        ))
        self.db.conn.commit()

        new_pb = self.get_playbook(playbook_id)
        self.audit_logger.log(
            username=updated_by,
            role="User",
            action="PLAYBOOK_UPDATED",
            target_type="playbook",
            target_id=playbook_id,
            old_value=sanitize_secrets(old_val),
            new_value=sanitize_secrets(new_pb)
        )
        return new_pb

    def delete_playbook(self, playbook_id: str, deleted_by: str = "system") -> bool:
        pb = self.get_playbook(playbook_id)
        if not pb:
            return False
        cursor = self.db.get_cursor()
        cursor.execute("DELETE FROM playbooks WHERE id = ? OR playbook_id = ?", (playbook_id, playbook_id))
        self.db.conn.commit()

        self.audit_logger.log(
            username=deleted_by,
            role="User",
            action="PLAYBOOK_DELETED",
            target_type="playbook",
            target_id=playbook_id,
            old_value=sanitize_secrets(pb)
        )
        return True

    # =========================================================================
    # DRY-RUN / PREVIEW CAPABILITY
    # =========================================================================

    def preview_playbook(
        self,
        playbook_id: str,
        target: str = "127.0.0.1",
        context: Optional[Dict[str, Any]] = None,
        requested_by: str = "Analyst"
    ) -> Dict[str, Any]:
        """
        Non-mutating playbook dry-run preview. Inspects actions, conditions, risk, permissions,
        and target authorization without altering state or executing actions.
        """
        pb = self.get_playbook(playbook_id)
        if not pb:
            return {"status": "FAILED", "reason": f"Playbook '{playbook_id}' not found."}

        mode = (pb.get("execution_mode") or "SIMULATION").upper()
        mode_gate = SOARConfig.validate_execution_mode(mode)
        target_gate = SOARConfig.validate_target_authorization(target, mode)

        actions_list = pb.get("actions", [])
        expected_effects = []

        has_high_risk = False
        for act in actions_list:
            act_type = act.get("action_type") if isinstance(act, dict) else str(act)
            inst = ACTION_REGISTRY.get(act_type)
            if inst and inst.risk_level in ["HIGH", "CRITICAL"]:
                has_high_risk = True
            expected_effects.append(f"[{mode}] Would execute action '{act_type}' against target '{target}'")

        requires_appr = bool(pb.get("requires_approval") or pb.get("risk_level") in ["HIGH", "CRITICAL"] or has_high_risk)

        self.audit_logger.log(
            username=requested_by,
            role="User",
            action="PLAYBOOK_PREVIEW",
            target_type="PLAYBOOK",
            target_id=playbook_id,
            new_value={"target": target, "mode": mode}
        )

        return {
            "status": "PREVIEW_SUCCESS",
            "playbook_id": playbook_id,
            "name": pb["name"],
            "description": pb.get("description", ""),
            "target": target,
            "execution_mode": mode,
            "execution_mode_status": mode_gate,
            "target_authorized": target_gate == "OK",
            "target_authorization_status": target_gate,
            "risk_level": pb.get("risk_level", "LOW"),
            "requires_approval": requires_appr,
            "required_permission": pb.get("required_permission", "playbook.execute"),
            "actions": [a.get("action_type") if isinstance(a, dict) else str(a) for a in actions_list],
            "expected_effects": expected_effects,
            "is_dry_run": True
        }

    # =========================================================================
    # TRIGGER & CONDITION EVALUATION
    # =========================================================================

    def evaluate_condition(self, condition_str: str, context: Dict[str, Any]) -> bool:
        """
        Safely evaluate condition strings like 'alert.risk_score >= 80' or 'alert.status == NEW'.
        """
        try:
            cond = condition_str.strip()
            # Handle list inclusion 'in' syntax
            if " in " in cond:
                left_var, right_val = cond.split(" in ", 1)
                val = self._resolve_path(left_var.strip(), context)
                options = [opt.strip(" '\"[]") for opt in right_val.split(",")]
                return str(val).lower() in [o.lower() for o in options]

            # Standard comparison operators
            operators = [">=", "<=", "==", "!=", ">", "<"]
            for op in operators:
                if op in cond:
                    left, right = cond.split(op, 1)
                    left_val = self._resolve_path(left.strip(), context)
                    right_val_str = right.strip().strip("'\"")

                    # Numeric comparison
                    if str(left_val).replace('.', '', 1).isdigit() and right_val_str.replace('.', '', 1).isdigit():
                        l_num, r_num = float(left_val), float(right_val_str)
                        if op == ">=": return l_num >= r_num
                        if op == "<=": return l_num <= r_num
                        if op == "==": return l_num == r_num
                        if op == "!=": return l_num != r_num
                        if op == ">":  return l_num > r_num
                        if op == "<":  return l_num < r_num

                    # String comparison
                    l_str, r_str = str(left_val).upper(), right_val_str.upper()
                    if op == "==": return l_str == r_str
                    if op == "!=": return l_str != r_str

            return True
        except Exception:
            return False

    def _resolve_path(self, path: str, context: Dict[str, Any]) -> Any:
        parts = path.split(".")
        val = context
        for p in parts:
            if isinstance(val, dict):
                val = val.get(p, "")
            else:
                return ""
        return val

    def evaluate_alert_triggers(self, alert: Dict[str, Any]) -> List[Dict[str, Any]]:
        playbooks = self.get_playbooks(enabled_only=True)
        matching = []
        context = {"alert": alert, "ioc": alert.get("indicators", {})}

        for pb in playbooks:
            conditions = pb.get("conditions", [])
            match = True
            for cond in conditions:
                if not self.evaluate_condition(cond, context):
                    match = False
                    break
            if match:
                matching.append(pb)
        return matching

    # =========================================================================
    # PLAYBOOK EXECUTION & APPROVAL WORKFLOW ENGINE
    # =========================================================================

    def execute_playbook(
        self,
        playbook_id: str,
        target: str = "127.0.0.1",
        context: Optional[Dict[str, Any]] = None,
        executed_by: str = "Analyst",
        approved: bool = False,
        execution_mode: Optional[str] = None,
        idempotency_key: Optional[str] = None,
        user_role: str = "",
        existing_execution_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Execute a playbook against alert/incident/case context.
        Supports feature gates, target allowlisting, idempotency, approval gates, atomic concurrency locking,
        safety controls, secret scrubbing, and failure isolation.
        """
        pb = self.get_playbook(playbook_id)
        if not pb:
            return {"status": "FAILED", "reason": f"Playbook {playbook_id} not found."}

        if not pb.get("enabled", True):
            return {"status": "FAILED", "reason": f"Playbook {playbook_id} is currently disabled."}

        mode = (execution_mode or pb.get("execution_mode") or "SIMULATION").upper()

        # 1. Feature Gate Check
        mode_gate = SOARConfig.validate_execution_mode(mode)
        if mode_gate != "OK":
            return {
                "status": mode_gate,
                "execution_mode": mode,
                "reason": f"Execution mode '{mode}' is disabled in server configuration ({mode_gate}). Action execution was blocked for safety."
            }

        # 2. Target Authorization Check
        target_gate = SOARConfig.validate_target_authorization(target, mode)
        if target_gate != "OK":
            return {
                "status": target_gate,
                "target": target,
                "execution_mode": mode,
                "reason": f"Target '{target}' is not in the server authorized allowlist for {mode} execution ({target_gate}). Action execution was blocked."
            }

        ctx = context or {}
        ctx["db"] = self.db
        ctx["target"] = target
        ctx["executed_by"] = executed_by

        alert_id = ctx.get("alert_id") or (ctx.get("alert") or {}).get("id") or ""
        incident_id = ctx.get("incident_id") or (ctx.get("incident") or {}).get("id") or ""
        case_id = ctx.get("case_id") or ""

        # 3. Strong Idempotency Check
        if idempotency_key and not existing_execution_id:
            cursor = self.db.get_cursor()
            cursor.execute("SELECT * FROM playbook_executions WHERE idempotency_key = ?", (idempotency_key,))
            existing = cursor.fetchone()
            if existing:
                dict_e = dict(existing)
                try:
                    dict_e["results"] = json.loads(dict_e["results"])
                except Exception:
                    pass
                return sanitize_secrets(dict_e)

        exec_id = existing_execution_id or f"EXEC-{datetime.now().strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:4]}"
        now_str = datetime.now().isoformat()

        # 4. Atomic Concurrency Lock Check
        cursor = self.db.get_cursor()
        cursor.execute("SELECT status FROM playbook_executions WHERE execution_id = ?", (exec_id,))
        current_rec = cursor.fetchone()
        if current_rec and dict(current_rec).get("status") == "EXECUTING":
            return {
                "status": "ALREADY_EXECUTING",
                "execution_id": exec_id,
                "reason": f"Execution '{exec_id}' is currently being executed by another process."
            }

        # 5. Approval Gate Check
        actions_list = pb.get("actions", [])
        has_high_risk_action = any(
            ACTION_REGISTRY.get(a.get("action_type") if isinstance(a, dict) else str(a), None) and
            ACTION_REGISTRY.get(a.get("action_type") if isinstance(a, dict) else str(a)).risk_level in ["HIGH", "CRITICAL"]
            for a in actions_list
        )

        requires_appr = pb.get("requires_approval") or pb.get("risk_level") in ["HIGH", "CRITICAL"] or has_high_risk_action

        if requires_appr and not approved:
            # Save PENDING_APPROVAL record
            self._save_execution_log(
                execution_id=exec_id,
                playbook_id=playbook_id,
                alert_id=alert_id,
                incident_id=incident_id,
                case_id=case_id,
                target=target,
                execution_mode=mode,
                requested_by=executed_by,
                approved_by="",
                approval_reason="",
                started_at=now_str,
                status="PENDING_APPROVAL",
                actions=actions_list,
                results=[],
                idempotency_key=idempotency_key or ""
            )

            self.audit_logger.log(
                username=executed_by,
                role=user_role or "Analyst",
                action="PLAYBOOK_PENDING_APPROVAL",
                target_type="PLAYBOOK",
                target_id=playbook_id,
                new_value={"execution_id": exec_id, "target": target, "mode": mode}
            )

            return {
                "status": "PENDING_APPROVAL",
                "execution_id": exec_id,
                "playbook_id": playbook_id,
                "name": pb["name"],
                "target": target,
                "execution_mode": mode,
                "message": f"Execution of high-risk playbook '{pb['name']}' requires explicit analyst approval."
            }

        # 6. EXECUTING State Transition Lock
        cursor.execute('''
            UPDATE playbook_executions
            SET status = 'EXECUTING'
            WHERE execution_id = ? AND status != 'EXECUTING'
        ''', (exec_id,))
        self.db.conn.commit()

        if current_rec and cursor.rowcount == 0:
            return {
                "status": "ALREADY_EXECUTING",
                "execution_id": exec_id,
                "reason": "Execution lock conflict: execution was locked by a concurrent worker."
            }

        # Save EXECUTING record if new
        if not current_rec:
            self._save_execution_log(
                execution_id=exec_id,
                playbook_id=playbook_id,
                alert_id=alert_id,
                incident_id=incident_id,
                case_id=case_id,
                target=target,
                execution_mode=mode,
                requested_by=executed_by,
                approved_by=executed_by if approved else "Auto-Approved",
                started_at=now_str,
                status="EXECUTING",
                actions=actions_list,
                results=[],
                idempotency_key=idempotency_key or ""
            )

        # 7. Action Execution Loop with Capped Limit (Max 10 actions) and Failure Isolation
        results = []
        overall_status = "COMPLETED"
        error_msg = ""
        max_actions = min(len(actions_list), 10)

        for i in range(max_actions):
            act_item = actions_list[i]
            act_type = act_item.get("action_type") if isinstance(act_item, dict) else str(act_item)
            action_inst = ACTION_REGISTRY.get(act_type)

            if not action_inst:
                res = {
                    "status": "FAILED",
                    "action_type": act_type,
                    "execution_mode": mode,
                    "error": f"Action handler '{act_type}' not found in registry."
                }
                results.append(res)
                overall_status = "FAILED"
                error_msg = res["error"]
                break

            # Failure isolation (catch action exceptions)
            try:
                res = action_inst.execute(ctx, execution_mode=mode)
                results.append(res)
                if res.get("status") in ["FAILED", "NOT_CONFIGURED"]:
                    if res.get("status") == "FAILED":
                        overall_status = "FAILED"
                        error_msg = res.get("error", "Action failed during execution.")
                        break
            except Exception as e:
                res = {
                    "status": "FAILED",
                    "action_type": act_type,
                    "execution_mode": mode,
                    "error": f"Unhandled action exception: {str(e)}"
                }
                results.append(res)
                overall_status = "FAILED"
                error_msg = str(e)
                break

        completed_at = datetime.now().isoformat()
        scrubbed_results = sanitize_secrets(results)

        # Update final execution record
        self._save_execution_log(
            execution_id=exec_id,
            playbook_id=playbook_id,
            alert_id=alert_id,
            incident_id=incident_id,
            case_id=case_id,
            target=target,
            execution_mode=mode,
            requested_by=executed_by,
            approved_by=executed_by if approved else "Auto-Approved",
            started_at=now_str,
            completed_at=completed_at,
            status=overall_status,
            actions=actions_list,
            results=scrubbed_results,
            error=error_msg,
            idempotency_key=idempotency_key or ""
        )

        self.audit_logger.log(
            username=executed_by,
            role=user_role or "Analyst",
            action=f"EXECUTE_PLAYBOOK_{overall_status}",
            target_type="PLAYBOOK",
            target_id=playbook_id,
            new_value={"execution_id": exec_id, "status": overall_status, "results": scrubbed_results}
        )

        return {
            "status": overall_status,
            "execution_id": exec_id,
            "playbook_id": playbook_id,
            "name": pb["name"],
            "target": target,
            "executed_by": executed_by,
            "execution_mode": mode,
            "started_at": now_str,
            "completed_at": completed_at,
            "results": scrubbed_results,
            "error": error_msg
        }

    # =========================================================================
    # APPROVAL WORKFLOW ACTIONS & SEPARATION OF DUTIES
    # =========================================================================

    def approve_execution(self, execution_id: str, approved_by: str, reason: str = "", user_role: str = "") -> Dict[str, Any]:
        exec_record = self.get_execution(execution_id)
        if not exec_record:
            return {"status": "FAILED", "reason": f"Execution '{execution_id}' not found."}

        if exec_record["status"] != "PENDING_APPROVAL":
            return {"status": "FAILED", "reason": f"Execution '{execution_id}' is in status '{exec_record['status']}', not PENDING_APPROVAL."}

        # 1. Separation of Duties Check
        requested_by = exec_record.get("requested_by", "")
        if approved_by and requested_by and approved_by.lower().strip() == requested_by.lower().strip():
            return {
                "status": "FAILED",
                "reason": "Separation of duties violation: Analyst cannot approve their own playbook execution request."
            }

        pb_id = exec_record["playbook_id"]
        pb = self.get_playbook(pb_id) or {}
        risk_level = pb.get("risk_level", "LOW").upper()

        # 2. CRITICAL Risk Role Requirement
        if risk_level == "CRITICAL":
            allowed_roles = ["SOC Analyst L2", "Incident Responder", "SOC Manager", "Administrator", "Admin"]
            if user_role and user_role not in allowed_roles:
                return {
                    "status": "FAILED",
                    "reason": f"Role '{user_role}' is not authorized to approve CRITICAL risk playbooks. Must be Responder/Manager/Admin."
                }

        target = exec_record.get("target", "127.0.0.1")
        mode = exec_record.get("execution_mode", "SIMULATION")

        self.audit_logger.log(
            username=approved_by,
            role=user_role or "Approver",
            action="PLAYBOOK_APPROVED",
            target_type="PLAYBOOK_EXECUTION",
            target_id=execution_id,
            new_value={"reason": reason, "approver": approved_by, "requested_by": requested_by}
        )

        # Trigger execution as approved
        return self.execute_playbook(
            playbook_id=pb_id,
            target=target,
            context={"alert_id": exec_record.get("alert_id"), "incident_id": exec_record.get("incident_id"), "case_id": exec_record.get("case_id")},
            executed_by=approved_by,
            approved=True,
            execution_mode=mode,
            user_role=user_role,
            existing_execution_id=execution_id
        )

    def reject_execution(self, execution_id: str, rejected_by: str, reason: str = "") -> Dict[str, Any]:
        exec_record = self.get_execution(execution_id)
        if not exec_record:
            return {"status": "FAILED", "reason": f"Execution '{execution_id}' not found."}

        now_str = datetime.now().isoformat()
        cursor = self.db.get_cursor()
        cursor.execute('''
            UPDATE playbook_executions
            SET status = 'REJECTED', approved_by = ?, approval_reason = ?, completed_at = ?
            WHERE execution_id = ?
        ''', (rejected_by, reason or "Execution rejected by analyst", now_str, execution_id))
        self.db.conn.commit()

        self.audit_logger.log(
            username=rejected_by,
            role="User",
            action="PLAYBOOK_REJECTED",
            target_type="PLAYBOOK_EXECUTION",
            target_id=execution_id,
            new_value={"reason": reason}
        )

        return {
            "status": "REJECTED",
            "execution_id": execution_id,
            "rejected_by": rejected_by,
            "reason": reason,
            "completed_at": now_str
        }

    def cancel_execution(self, execution_id: str, cancelled_by: str, reason: str = "") -> Dict[str, Any]:
        exec_record = self.get_execution(execution_id)
        if not exec_record:
            return {"status": "FAILED", "reason": f"Execution '{execution_id}' not found."}

        now_str = datetime.now().isoformat()
        cursor = self.db.get_cursor()
        cursor.execute('''
            UPDATE playbook_executions
            SET status = 'CANCELLED', approval_reason = ?, completed_at = ?
            WHERE execution_id = ?
        ''', (reason or f"Cancelled by {cancelled_by}", now_str, execution_id))
        self.db.conn.commit()

        self.audit_logger.log(
            username=cancelled_by,
            role="User",
            action="PLAYBOOK_CANCELLED",
            target_type="PLAYBOOK_EXECUTION",
            target_id=execution_id,
            new_value={"reason": reason}
        )

        return {
            "status": "CANCELLED",
            "execution_id": execution_id,
            "cancelled_by": cancelled_by,
            "completed_at": now_str
        }

    def rollback_execution(self, execution_id: str, requested_by: str = "Analyst") -> Dict[str, Any]:
        exec_record = self.get_execution(execution_id)
        if not exec_record:
            return {"status": "FAILED", "reason": f"Execution '{execution_id}' not found."}

        actions_list = exec_record.get("actions", [])
        mode = exec_record.get("execution_mode", "SIMULATION")
        rollback_results = []
        overall_rollback_status = "COMPLETED"

        ctx = {"db": self.db, "target": exec_record.get("target"), "executed_by": requested_by}

        for act_item in reversed(actions_list):
            act_type = act_item.get("action_type") if isinstance(act_item, dict) else str(act_item)
            action_inst = ACTION_REGISTRY.get(act_type)

            if action_inst:
                res = action_inst.rollback(ctx, execution_mode=mode)
                rollback_results.append(res)
                if res.get("status") not in ["SUCCESS", "SIMULATED_SUCCESS", "LAB_SUCCESS", "NOT_SUPPORTED"]:
                    overall_rollback_status = "FAILED"

        now_str = datetime.now().isoformat()
        cursor = self.db.get_cursor()
        cursor.execute("UPDATE playbook_executions SET rollback_status = ? WHERE execution_id = ?", (overall_rollback_status, execution_id))
        self.db.conn.commit()

        self.audit_logger.log(
            username=requested_by,
            role="User",
            action=f"ROLLBACK_PLAYBOOK_{overall_rollback_status}",
            target_type="PLAYBOOK_EXECUTION",
            target_id=execution_id,
            new_value={"rollback_results": sanitize_secrets(rollback_results)}
        )

        return {
            "status": "ROLLBACK_COMPLETED" if overall_rollback_status == "COMPLETED" else "ROLLBACK_FAILED",
            "execution_id": execution_id,
            "rollback_status": overall_rollback_status,
            "rollback_results": sanitize_secrets(rollback_results)
        }

    # =========================================================================
    # LOGGING & QUERYING EXECUTION HISTORY
    # =========================================================================

    def _save_execution_log(
        self,
        execution_id: str,
        playbook_id: str,
        alert_id: str,
        incident_id: str,
        case_id: str,
        target: str,
        execution_mode: str,
        requested_by: str,
        approved_by: str = "",
        approval_reason: str = "",
        started_at: str = "",
        completed_at: str = "",
        status: str = "PENDING_APPROVAL",
        actions: list = None,
        results: list = None,
        error: str = "",
        idempotency_key: str = ""
    ):
        cursor = self.db.get_cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO playbook_executions
            (execution_id, playbook_id, alert_id, incident_id, case_id, target, execution_mode, requested_by, approved_by, approval_reason, started_at, completed_at, status, actions, results, error, rollback_status, idempotency_key)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'NONE', ?)
        ''', (
            execution_id, playbook_id, alert_id or "", incident_id or "", case_id or "",
            target or "", execution_mode or "SIMULATION", requested_by or "system", approved_by or "",
            approval_reason or "", started_at or datetime.now().isoformat(), completed_at or "",
            status, json.dumps(sanitize_secrets(actions or [])), json.dumps(sanitize_secrets(results or [])),
            error or "", idempotency_key or ""
        ))
        self.db.conn.commit()

    def get_execution(self, execution_id: str) -> Optional[Dict[str, Any]]:
        cursor = self.db.get_cursor()
        cursor.execute("SELECT * FROM playbook_executions WHERE execution_id = ?", (execution_id,))
        row = cursor.fetchone()
        if not row:
            return None
        dict_r = dict(row)
        for field in ["actions", "results"]:
            if isinstance(dict_r.get(field), str):
                try:
                    dict_r[field] = json.loads(dict_r[field])
                except Exception:
                    pass
        return sanitize_secrets(dict_r)

    def list_executions(self, status: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
        cursor = self.db.get_cursor()
        query = "SELECT * FROM playbook_executions"
        params = []
        if status:
            query += " WHERE status = ?"
            params.append(status)
        query += " ORDER BY started_at DESC LIMIT ?"
        params.append(min(limit, 200))

        cursor.execute(query, params)
        rows = cursor.fetchall()
        result = []
        for r in rows:
            dict_r = dict(r)
            for field in ["actions", "results"]:
                if isinstance(dict_r.get(field), str):
                    try:
                        dict_r[field] = json.loads(dict_r[field])
                    except Exception:
                        pass
            result.append(sanitize_secrets(dict_r))
        return result
