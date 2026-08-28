import json
import os
import re
from datetime import datetime, timedelta
from collections import defaultdict
from typing import List, Dict, Any, Optional

class DetectionEngine:
    """
    Modular, Data-Driven Rule Detection Engine for Enterprise SOC.
    Evaluates normalized telemetry events against structured detection rules.
    """
    def __init__(self, db=None, rules_file: str = None):
        self.db = db
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.rules_file = rules_file or os.path.join(base_dir, "data", "rules", "default_rules.json")
        
        # Sliding memory buffer for threshold evaluation: key -> list of (timestamp, event_id, event_dict)
        self.sliding_windows = defaultdict(list)
        
        self.init_rules_in_db()

    def init_rules_in_db(self):
        """Seed default rules into DB detection_rules table if table is empty or missing rules."""
        if not os.path.exists(self.rules_file):
            return
        
        try:
            with open(self.rules_file, "r") as f:
                rules_data = json.load(f)
        except Exception:
            return

        if self.db:
            cursor = self.db.get_cursor()
            for r in rules_data:
                rule_id = r["rule_id"]
                cursor.execute("SELECT id FROM detection_rules WHERE id = ?", (rule_id,))
                if not cursor.fetchone():
                    cursor.execute('''
                        INSERT INTO detection_rules 
                        (id, rule_name, description, severity, category, mitre_tactic, 
                         mitre_technique_id, mitre_technique_name, rule_type, rule_logic, enabled, created_by, created_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        rule_id,
                        r.get("name", "Rule"),
                        r.get("description", ""),
                        r.get("severity", "medium"),
                        r.get("mitre_tactic", "Execution"),
                        r.get("mitre_tactic", "Execution"),
                        r.get("mitre_technique_id", "T1059"),
                        r.get("mitre_technique_name", "Execution"),
                        "threshold" if r.get("threshold", 1) > 1 else "signature",
                        json.dumps(r),
                        1 if r.get("enabled", True) else 0,
                        "System",
                        datetime.now().isoformat()
                    ))
            self.db.conn.commit()

    def get_all_rules(self) -> List[Dict[str, Any]]:
        """Retrieve all rules from DB or fallback file."""
        if self.db:
            cursor = self.db.get_cursor()
            cursor.execute("SELECT * FROM detection_rules ORDER BY id ASC")
            rows = cursor.fetchall()
            rules = []
            for row in rows:
                dict_row = dict(row)
                try:
                    rule_logic = json.loads(dict_row.get("rule_logic", "{}"))
                except Exception:
                    rule_logic = {}
                
                # Merge DB fields over logic
                rule_logic["rule_id"] = dict_row["id"]
                rule_logic["name"] = dict_row["rule_name"]
                rule_logic["description"] = dict_row["description"]
                rule_logic["severity"] = dict_row["severity"]
                rule_logic["mitre_tactic"] = dict_row.get("mitre_tactic", "")
                rule_logic["mitre_technique_id"] = dict_row.get("mitre_technique_id", "")
                rule_logic["mitre_technique_name"] = dict_row.get("mitre_technique_name", "")
                rule_logic["enabled"] = bool(dict_row.get("enabled", 1))
                rules.append(rule_logic)
            if rules:
                return rules
                
        if os.path.exists(self.rules_file):
            with open(self.rules_file, "r") as f:
                return json.load(f)
        return []

    def evaluate_event(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Evaluates normalized telemetry event against all active enabled rules.
        Returns list of detection rule match objects.
        """
        matches = []
        rules = self.get_all_rules()
        
        event_id = event.get("event_id", "")
        timestamp_str = event.get("timestamp") or datetime.now().isoformat()
        try:
            event_ts = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00")).timestamp()
        except Exception:
            event_ts = datetime.now().timestamp()
            
        entity_key = event.get("source_ip") or event.get("hostname") or event.get("username") or "global"

        for rule in rules:
            if not rule.get("enabled", True):
                continue

            if self._matches_conditions(rule, event):
                rule_id = rule["rule_id"]
                threshold = int(rule.get("threshold", 1))
                time_window = int(rule.get("time_window", 60))
                
                if threshold > 1:
                    # Maintain sliding window per (rule_id, entity_key)
                    win_key = f"{rule_id}:{entity_key}"
                    buffer = self.sliding_windows[win_key]
                    
                    # Clean up old events outside window
                    cutoff = event_ts - time_window
                    self.sliding_windows[win_key] = [item for item in buffer if item[0] >= cutoff]
                    self.sliding_windows[win_key].append((event_ts, event_id, event))
                    
                    current_count = len(self.sliding_windows[win_key])
                    if current_count >= threshold:
                        triggering_events = [item[2] for item in self.sliding_windows[win_key]]
                        triggering_ids = [item[1] for item in self.sliding_windows[win_key] if item[1]]
                        
                        match_obj = self._build_detection_match(
                            rule=rule,
                            event=event,
                            triggering_events=triggering_events,
                            triggering_ids=triggering_ids,
                            reason=f"{current_count} matching events occurred within {time_window}s for entity '{entity_key}' meeting rule threshold ({threshold})."
                        )
                        matches.append(match_obj)
                        # Reset sliding window after trigger to prevent flooding
                        self.sliding_windows[win_key] = []
                else:
                    match_obj = self._build_detection_match(
                        rule=rule,
                        event=event,
                        triggering_events=[event],
                        triggering_ids=[event_id] if event_id else [],
                        reason=f"Event matched signature conditions for rule '{rule.get('name')}': {event.get('event_type')} on {event.get('hostname')} by user '{event.get('username')}'."
                    )
                    matches.append(match_obj)
                    
        return matches

    def _matches_conditions(self, rule: Dict[str, Any], event: Dict[str, Any]) -> bool:
        conditions = rule.get("event_conditions", [])
        if not conditions:
            return False

        for cond in conditions:
            field = cond.get("field")
            operator = cond.get("operator", "eq")
            target_val = cond.get("value")

            # Extract value from event or raw_event
            val = event.get(field)
            if val is None and isinstance(event.get("raw_event"), dict):
                val = event["raw_event"].get(field)
            if val is None:
                val = str(event) if field == "raw_event" else ""

            val_str = str(val).lower()
            target_str = str(target_val).lower()

            if operator == "eq":
                if val_str != target_str:
                    return False
            elif operator == "contains":
                if target_str not in val_str:
                    return False
            elif operator == "regex":
                try:
                    if not re.search(target_val, str(val), re.IGNORECASE):
                        return False
                except Exception:
                    return False
            elif operator == "in":
                if isinstance(target_val, list):
                    if val_str not in [str(x).lower() for x in target_val]:
                        return False
                elif target_str not in val_str:
                    return False

        return True

    def _build_detection_match(
        self,
        rule: Dict[str, Any],
        event: Dict[str, Any],
        triggering_events: List[Dict[str, Any]],
        triggering_ids: List[str],
        reason: str
    ) -> Dict[str, Any]:
        return {
            "rule_id": rule["rule_id"],
            "title": rule.get("name", "Security Detection"),
            "description": rule.get("description", ""),
            "severity": rule.get("severity", "medium"),
            "confidence": int(rule.get("confidence", 80)),
            "mitre_tactic": rule.get("mitre_tactic", "Execution"),
            "mitre_technique_id": rule.get("mitre_technique_id", "T1059"),
            "mitre_technique_name": rule.get("mitre_technique_name", "Execution"),
            "mitre_technique": f"{rule.get('mitre_technique_id', 'T1059')} - {rule.get('mitre_technique_name', 'Execution')}",
            "reason": reason,
            "source": event.get("source_ip") or event.get("hostname", "unknown"),
            "destination": event.get("destination_ip", "0.0.0.0"),
            "affected_asset": event.get("hostname", "unknown-host"),
            "affected_user": event.get("username", "system"),
            "triggering_event_ids": triggering_ids,
            "evidence": [
                {
                    "event_id": ev.get("event_id"),
                    "timestamp": ev.get("timestamp"),
                    "source_type": ev.get("source_type"),
                    "event_type": ev.get("event_type"),
                    "username": ev.get("username"),
                    "hostname": ev.get("hostname"),
                    "source_ip": ev.get("source_ip"),
                    "process_name": ev.get("process_name")
                } for ev in triggering_events[:10]
            ],
            "references": rule.get("references", []),
            "false_positive_guidance": rule.get("false_positive_guidance", "")
        }
