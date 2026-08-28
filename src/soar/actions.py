from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from datetime import datetime
import json
import uuid

class BaseAction(ABC):
    """
    Abstract Base Class for SOAR Playbook Response Actions.
    All actions must specify action_type, risk_level, and default approval requirements.
    """
    action_type: str = "BASE_ACTION"
    risk_level: str = "LOW"  # LOW, MEDIUM, HIGH, CRITICAL
    requires_approval: bool = False

    @abstractmethod
    def execute(self, context: Dict[str, Any], execution_mode: str = "SIMULATION") -> Dict[str, Any]:
        """
        Execute the action with the given context and execution mode.
        Returns a dict containing status, details, execution_mode, data, and error.
        """
        pass

    def rollback(self, context: Dict[str, Any], execution_mode: str = "SIMULATION") -> Dict[str, Any]:
        """
        Optional rollback method for reversible actions.
        Default implementation returns NOT_SUPPORTED.
        """
        return {
            "status": "NOT_SUPPORTED",
            "action_type": self.action_type,
            "execution_mode": execution_mode,
            "details": f"Rollback is not supported for action {self.action_type}",
            "rollback_status": "NONE"
        }

# ==============================================================================
# SAFE LAB ACTIONS
# ==============================================================================

class CreateIncidentAction(BaseAction):
    action_type = "CREATE_INCIDENT"
    risk_level = "MEDIUM"
    requires_approval = False

    def execute(self, context: Dict[str, Any], execution_mode: str = "SIMULATION") -> Dict[str, Any]:
        db = context.get("db")
        alert = context.get("alert") or {}
        alert_id = context.get("alert_id") or alert.get("id") or ""
        title = context.get("title") or f"Incident: {alert.get('title', 'Playbook Triggered Incident')}"
        severity = context.get("severity") or alert.get("severity") or "high"
        
        inc_id = f"INC-{datetime.now().strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:4]}"
        incident_data = {
            "id": inc_id,
            "title": title,
            "severity": severity,
            "priority": "P2",
            "status": "open",
            "alert_id": alert_id,
            "description": context.get("description") or alert.get("description") or "Automatically created by SOAR Playbook",
            "category": "SOAR Playbook Auto-Creation",
            "created_at": datetime.now().isoformat()
        }

        if db:
            db.save_incident(incident_data)

        return {
            "status": "SUCCESS",
            "action_type": self.action_type,
            "execution_mode": execution_mode,
            "details": f"Created incident {inc_id} from alert context.",
            "data": {"incident_id": inc_id, "incident": incident_data}
        }


class ChangeAlertSeverityAction(BaseAction):
    action_type = "CHANGE_ALERT_SEVERITY"
    risk_level = "MEDIUM"
    requires_approval = False

    def execute(self, context: Dict[str, Any], execution_mode: str = "SIMULATION") -> Dict[str, Any]:
        db = context.get("db")
        alert_id = context.get("alert_id") or (context.get("alert") or {}).get("id")
        new_severity = context.get("new_severity") or "high"

        if not alert_id:
            alert_id = "ALERT-SOAR-SIMULATED"

        if db:
            cursor = db.get_cursor()
            cursor.execute("UPDATE alerts SET severity = ? WHERE id = ?", (new_severity, alert_id))
            db.conn.commit()

        return {
            "status": "SUCCESS",
            "action_type": self.action_type,
            "execution_mode": execution_mode,
            "details": f"Alert {alert_id} severity updated to '{new_severity}'.",
            "data": {"alert_id": alert_id, "new_severity": new_severity}
        }


class AddIOCToSimulatedBlocklistAction(BaseAction):
    action_type = "ADD_IOC_SIMULATED_BLOCKLIST"
    risk_level = "LOW"
    requires_approval = False

    def execute(self, context: Dict[str, Any], execution_mode: str = "SIMULATION") -> Dict[str, Any]:
        db = context.get("db")
        ioc_val = context.get("ioc") or context.get("target")
        ioc_type = context.get("ioc_type") or "ip"

        if not ioc_val:
            return {
                "status": "FAILED",
                "action_type": self.action_type,
                "execution_mode": execution_mode,
                "error": "No IOC value provided for blocklist action."
            }

        if db:
            cursor = db.get_cursor()
            now_str = datetime.now().isoformat()
            ioc_id = f"ioc-{uuid.uuid4().hex[:12]}"
            try:
                cursor.execute('''
                    INSERT INTO iocs (id, type, value, normalized_value, reputation, tags, description, first_seen, created_at, updated_at)
                    VALUES (?, ?, ?, ?, 'MALICIOUS', '["SIMULATED_BLOCKLIST"]', 'Added to blocklist via SOAR playbook', ?, ?, ?)
                    ON CONFLICT(type, normalized_value) DO UPDATE SET reputation='MALICIOUS', tags='["SIMULATED_BLOCKLIST"]', updated_at=?
                ''', (ioc_id, ioc_type, ioc_val, ioc_val.lower().strip(), now_str, now_str, now_str, now_str))
                db.conn.commit()
            except Exception as e:
                pass

        return {
            "status": "SIMULATED_SUCCESS",
            "action_type": self.action_type,
            "execution_mode": execution_mode,
            "details": f"IOC '{ioc_val}' added to simulated SOC blocklist.",
            "data": {"ioc": ioc_val, "ioc_type": ioc_type, "blocklist_status": "SIMULATED_BLOCKED"}
        }

    def rollback(self, context: Dict[str, Any], execution_mode: str = "SIMULATION") -> Dict[str, Any]:
        remove_action = RemoveIOCFromSimulatedBlocklistAction()
        res = remove_action.execute(context, execution_mode)
        res["rollback_status"] = "COMPLETED"
        return res


class RemoveIOCFromSimulatedBlocklistAction(BaseAction):
    action_type = "REMOVE_IOC_SIMULATED_BLOCKLIST"
    risk_level = "LOW"
    requires_approval = False

    def execute(self, context: Dict[str, Any], execution_mode: str = "SIMULATION") -> Dict[str, Any]:
        db = context.get("db")
        ioc_val = context.get("ioc") or context.get("target")

        if not ioc_val:
            return {
                "status": "FAILED",
                "action_type": self.action_type,
                "execution_mode": execution_mode,
                "error": "No IOC value provided for removal."
            }

        if db:
            cursor = db.get_cursor()
            cursor.execute("UPDATE iocs SET reputation='BENIGN', tags='[]' WHERE normalized_value = ?", (ioc_val.lower().strip(),))
            db.conn.commit()

        return {
            "status": "SIMULATED_SUCCESS",
            "action_type": self.action_type,
            "execution_mode": execution_mode,
            "details": f"IOC '{ioc_val}' removed from simulated blocklist.",
            "data": {"ioc": ioc_val, "blocklist_status": "REMOVED"}
        }


class IsolateHostAction(BaseAction):
    action_type = "ISOLATE_HOST"
    risk_level = "HIGH"
    requires_approval = True

    def execute(self, context: Dict[str, Any], execution_mode: str = "SIMULATION") -> Dict[str, Any]:
        db = context.get("db")
        target_host = context.get("target") or context.get("hostname") or "unknown-host"
        mode_upper = (execution_mode or "SIMULATION").upper()

        if mode_upper == "LIVE":
            adapter = EndpointAdapterFactory.get_adapter("EDR")
            return adapter.execute_containment(target_host, "ISOLATE_HOST")

        # In LAB mode
        if mode_upper == "LAB":
            if db:
                cursor = db.get_cursor()
                cursor.execute("UPDATE assets SET agent_status = 'LAB_ISOLATED' WHERE hostname = ? OR ip = ?", (target_host, target_host))
                db.conn.commit()
            return {
                "status": "LAB_SUCCESS",
                "action_type": self.action_type,
                "execution_mode": "LAB",
                "details": f"[LAB MODE] Host '{target_host}' network interface isolated in authorized SOC lab environment.",
                "data": {
                    "target": target_host,
                    "lab_isolation": True,
                    "agent_status": "LAB_ISOLATED"
                }
            }

        # In SIMULATION mode
        if db:
            cursor = db.get_cursor()
            cursor.execute("UPDATE assets SET agent_status = 'SIMULATED_ISOLATED' WHERE hostname = ? OR ip = ?", (target_host, target_host))
            db.conn.commit()

        return {
            "status": "SIMULATED_SUCCESS",
            "action_type": self.action_type,
            "execution_mode": "SIMULATION",
            "details": f"[SIMULATION MODE] Host '{target_host}' network interface marked as SIMULATED_ISOLATED in lab environment. No real physical network disruption occurred.",
            "data": {
                "target": target_host,
                "simulated_isolation": True,
                "real_containment_applied": False,
                "agent_status": "SIMULATED_ISOLATED"
            }
        }

    def rollback(self, context: Dict[str, Any], execution_mode: str = "SIMULATION") -> Dict[str, Any]:
        db = context.get("db")
        target_host = context.get("target") or context.get("hostname") or "unknown-host"
        mode_upper = (execution_mode or "SIMULATION").upper()
        if db:
            cursor = db.get_cursor()
            cursor.execute("UPDATE assets SET agent_status = 'ONLINE' WHERE hostname = ? OR ip = ?", (target_host, target_host))
            db.conn.commit()

        status_code = "LAB_SUCCESS" if mode_upper == "LAB" else "SIMULATED_SUCCESS"
        return {
            "status": status_code,
            "action_type": self.action_type,
            "execution_mode": mode_upper,
            "details": f"[{mode_upper} MODE] Host '{target_host}' network isolation reverted to ONLINE in lab registry.",
            "rollback_status": "COMPLETED",
            "data": {"target": target_host, "agent_status": "ONLINE"}
        }


class DisableAccountAction(BaseAction):
    action_type = "DISABLE_ACCOUNT"
    risk_level = "HIGH"
    requires_approval = True

    def execute(self, context: Dict[str, Any], execution_mode: str = "SIMULATION") -> Dict[str, Any]:
        db = context.get("db")
        target_user = context.get("target") or context.get("username") or "unknown-user"
        mode_upper = (execution_mode or "SIMULATION").upper()

        if mode_upper == "LIVE":
            adapter = EndpointAdapterFactory.get_adapter("Windows")
            return adapter.execute_containment(target_user, "DISABLE_ACCOUNT")

        if mode_upper == "LAB":
            if db:
                cursor = db.get_cursor()
                cursor.execute("UPDATE users SET is_active = 0 WHERE username = ?", (target_user,))
                db.conn.commit()
            return {
                "status": "LAB_SUCCESS",
                "action_type": self.action_type,
                "execution_mode": "LAB",
                "details": f"[LAB MODE] Account '{target_user}' disabled in authorized SOC lab environment.",
                "data": {
                    "target": target_user,
                    "lab_disable": True,
                    "is_active": 0
                }
            }

        if db:
            cursor = db.get_cursor()
            cursor.execute("UPDATE users SET is_active = 0 WHERE username = ?", (target_user,))
            db.conn.commit()

        return {
            "status": "SIMULATED_SUCCESS",
            "action_type": self.action_type,
            "execution_mode": "SIMULATION",
            "details": f"[SIMULATION MODE] Account '{target_user}' marked as disabled in SOC lab database.",
            "data": {
                "target": target_user,
                "simulated_disable": True,
                "real_account_disabled": False,
                "is_active": 0
            }
        }

    def rollback(self, context: Dict[str, Any], execution_mode: str = "SIMULATION") -> Dict[str, Any]:
        db = context.get("db")
        target_user = context.get("target") or context.get("username") or "unknown-user"
        if db:
            cursor = db.get_cursor()
            cursor.execute("UPDATE users SET is_active = 1 WHERE username = ?", (target_user,))
            db.conn.commit()

        return {
            "status": "SIMULATED_SUCCESS",
            "action_type": self.action_type,
            "execution_mode": execution_mode,
            "details": f"[SIMULATION MODE] Account '{target_user}' re-enabled in SOC lab database.",
            "rollback_status": "COMPLETED",
            "data": {"target": target_user, "is_active": 1}
        }


class AddCaseNoteAction(BaseAction):
    action_type = "ADD_CASE_NOTE"
    risk_level = "LOW"
    requires_approval = False

    def execute(self, context: Dict[str, Any], execution_mode: str = "SIMULATION") -> Dict[str, Any]:
        db = context.get("db")
        case_id = context.get("case_id") or "CASE-SOAR"
        note_content = context.get("note") or context.get("details") or "Note added automatically by SOAR Playbook."
        author = context.get("executed_by") or "SOAR_Engine"

        if db:
            cursor = db.get_cursor()
            note_id = f"note-{uuid.uuid4().hex[:8]}"
            now_str = datetime.now().isoformat()
            try:
                cursor.execute('''
                    INSERT INTO case_notes (note_id, case_id, author, timestamp, content, updated_at, updated_by)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (note_id, case_id, author, now_str, note_content, now_str, author))
                db.conn.commit()
            except Exception:
                pass

        return {
            "status": "SUCCESS",
            "action_type": self.action_type,
            "execution_mode": execution_mode,
            "details": f"Added case note to case '{case_id}'.",
            "data": {"case_id": case_id, "note": note_content}
        }


class EnrichIOCAction(BaseAction):
    action_type = "ENRICH_IOC"
    risk_level = "LOW"
    requires_approval = False

    def execute(self, context: Dict[str, Any], execution_mode: str = "SIMULATION") -> Dict[str, Any]:
        enrichment_mgr = context.get("enrichment_mgr")
        indicator = context.get("target") or context.get("indicator") or "192.168.1.1"

        if enrichment_mgr:
            res = enrichment_mgr.enrich_indicator(indicator)
            return {
                "status": "SUCCESS",
                "action_type": self.action_type,
                "execution_mode": execution_mode,
                "details": f"Enriched IOC '{indicator}' via Phase 7 threat intel providers.",
                "data": res
            }

        return {
            "status": "SIMULATED_SUCCESS",
            "action_type": self.action_type,
            "execution_mode": execution_mode,
            "details": f"Simulated threat intel query for IOC '{indicator}'.",
            "data": {"indicator": indicator, "reputation": "SUSPICIOUS", "confidence": 75}
        }


class NotifyAnalystAction(BaseAction):
    action_type = "NOTIFY_ANALYST"
    risk_level = "LOW"
    requires_approval = False

    def execute(self, context: Dict[str, Any], execution_mode: str = "SIMULATION") -> Dict[str, Any]:
        recipient = context.get("recipient") or "SOC_Duty_Analyst"
        message = context.get("message") or f"SOAR Alert Notification for target '{context.get('target', 'N/A')}'"

        return {
            "status": "SUCCESS",
            "action_type": self.action_type,
            "execution_mode": execution_mode,
            "details": f"Dispatched notification to '{recipient}': {message}",
            "data": {"recipient": recipient, "message": message, "timestamp": datetime.now().isoformat()}
        }


class AddEvidenceAction(BaseAction):
    action_type = "ADD_EVIDENCE"
    risk_level = "LOW"
    requires_approval = False

    def execute(self, context: Dict[str, Any], execution_mode: str = "SIMULATION") -> Dict[str, Any]:
        db = context.get("db")
        case_id = context.get("case_id") or "CASE-SOAR"
        ev_type = context.get("evidence_type") or "telemetry_log"
        description = context.get("description") or "Automated SOAR evidence capture"

        if db:
            cursor = db.get_cursor()
            ev_id = f"ev-{uuid.uuid4().hex[:8]}"
            now_str = datetime.now().isoformat()
            try:
                cursor.execute('''
                    INSERT INTO evidence (evidence_id, case_id, type, source, timestamp, added_by, description)
                    VALUES (?, ?, ?, 'SOAR Playbook', ?, 'SOAR_Engine', ?)
                ''', (ev_id, case_id, ev_type, now_str, description))
                db.conn.commit()
            except Exception:
                pass

        return {
            "status": "SUCCESS",
            "action_type": self.action_type,
            "execution_mode": execution_mode,
            "details": f"Added evidence item to case '{case_id}'.",
            "data": {"case_id": case_id, "evidence_type": ev_type}
        }


class CreateInvestigationTaskAction(BaseAction):
    action_type = "CREATE_INVESTIGATION_TASK"
    risk_level = "LOW"
    requires_approval = False

    def execute(self, context: Dict[str, Any], execution_mode: str = "SIMULATION") -> Dict[str, Any]:
        task_title = context.get("task_title") or context.get("title") or "Verify host telemetry and network logs"
        target = context.get("target") or "Unassigned"

        return {
            "status": "SUCCESS",
            "action_type": self.action_type,
            "execution_mode": execution_mode,
            "details": f"Created investigation task: '{task_title}'.",
            "data": {"task": task_title, "target": target, "status": "OPEN"}
        }


# ==============================================================================
# REAL ENDPOINT ADAPTERS (NOT CONFIGURED SAFETY CONTROL)
# ==============================================================================

class BaseEndpointAdapter:
    adapter_name: str = "GENERIC_ENDPOINT"

    def execute_containment(self, target: str, action: str) -> Dict[str, Any]:
        """
        Returns NOT_CONFIGURED state since physical endpoints are not connected.
        Never fabricates physical containment.
        """
        return {
            "status": "NOT_CONFIGURED",
            "adapter": self.adapter_name,
            "action": action,
            "target": target,
            "execution_mode": "LIVE",
            "details": f"Physical integration '{self.adapter_name}' is NOT_CONFIGURED in current laboratory environment. Real-world containment was NOT performed.",
            "error": f"Endpoint adapter '{self.adapter_name}' is NOT_CONFIGURED for physical execution."
        }


class WindowsEndpointAdapter(BaseEndpointAdapter):
    adapter_name = "Windows_ActiveDirectory_EDR"


class LinuxEndpointAdapter(BaseEndpointAdapter):
    adapter_name = "Linux_SSH_IPTables"


class WazuhAdapter(BaseEndpointAdapter):
    adapter_name = "Wazuh_ActiveResponse"


class EDRAdapter(BaseEndpointAdapter):
    adapter_name = "Enterprise_EDR_Agent"


class FirewallAdapter(BaseEndpointAdapter):
    adapter_name = "Perimeter_Firewall"


class NetworkAdapter(BaseEndpointAdapter):
    adapter_name = "Network_NAC_Switch"


class EndpointAdapterFactory:
    _adapters = {
        "Windows": WindowsEndpointAdapter(),
        "Linux": LinuxEndpointAdapter(),
        "Wazuh": WazuhAdapter(),
        "EDR": EDRAdapter(),
        "Firewall": FirewallAdapter(),
        "Network": NetworkAdapter(),
    }

    @classmethod
    def get_adapter(cls, name: str) -> BaseEndpointAdapter:
        return cls._adapters.get(name, BaseEndpointAdapter())


# ==============================================================================
# ACTION REGISTRY
# ==============================================================================

ACTION_REGISTRY: Dict[str, BaseAction] = {
    "CREATE_INCIDENT": CreateIncidentAction(),
    "CHANGE_ALERT_SEVERITY": ChangeAlertSeverityAction(),
    "ADD_IOC_SIMULATED_BLOCKLIST": AddIOCToSimulatedBlocklistAction(),
    "REMOVE_IOC_SIMULATED_BLOCKLIST": RemoveIOCFromSimulatedBlocklistAction(),
    "ISOLATE_HOST": IsolateHostAction(),
    "DISABLE_ACCOUNT": DisableAccountAction(),
    "ADD_CASE_NOTE": AddCaseNoteAction(),
    "ENRICH_IOC": EnrichIOCAction(),
    "NOTIFY_ANALYST": NotifyAnalystAction(),
    "ADD_EVIDENCE": AddEvidenceAction(),
    "CREATE_INVESTIGATION_TASK": CreateInvestigationTaskAction(),
}
