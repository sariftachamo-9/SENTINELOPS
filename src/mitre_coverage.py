from typing import Dict, Any, List
from src.detection_engine import DetectionEngine

class MITRECoverageAnalyzer:
    """
    Analyzes MITRE ATT&CK coverage based on active detection rules and generated alerts.
    """
    def __init__(self, db=None):
        self.db = db
        self.detection_engine = DetectionEngine(db=db)

    def get_coverage_matrix(self) -> Dict[str, Any]:
        all_tactics = [
            "Reconnaissance", "Resource Development", "Initial Access", "Execution",
            "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
            "Discovery", "Lateral Movement", "Collection", "Command and Control",
            "Exfiltration", "Impact"
        ]

        rules = self.detection_engine.get_all_rules()
        
        # Query alert counts and last detected times per technique from DB if available
        alerts_by_technique = {}
        if self.db:
            try:
                cursor = self.db.get_cursor()
                cursor.execute('''
                    SELECT mitre_technique, COUNT(*) as cnt, MAX(timestamp) as last_seen 
                    FROM alerts 
                    WHERE mitre_technique IS NOT NULL AND mitre_technique != ''
                    GROUP BY mitre_technique
                ''')
                rows = cursor.fetchall()
                for r in rows:
                    tech_str = r["mitre_technique"]
                    alerts_by_technique[tech_str] = {
                        "count": r["cnt"],
                        "last_detected": r["last_seen"]
                    }
            except Exception:
                pass

        matrix = {tactic: [] for tactic in all_tactics}

        for rule in rules:
            if not rule.get("enabled", True):
                continue
            
            tactic = rule.get("mitre_tactic", "Execution")
            # Normalize tactic string if compound
            primary_tactic = tactic.split("/")[0].strip() if "/" in tactic else tactic
            if primary_tactic not in matrix:
                primary_tactic = "Execution"

            tech_id = rule.get("mitre_technique_id", "T1059")
            tech_name = rule.get("mitre_technique_name", "General Technique")
            full_tech_key = f"{tech_id} - {tech_name}"

            alert_info = alerts_by_technique.get(full_tech_key) or alerts_by_technique.get(tech_id) or {"count": 0, "last_detected": None}

            status = "ALERTED" if alert_info["count"] > 0 else "COVERED"

            matrix[primary_tactic].append({
                "rule_id": rule.get("rule_id"),
                "rule_name": rule.get("name"),
                "technique_id": tech_id,
                "technique_name": tech_name,
                "severity": rule.get("severity", "medium"),
                "alert_count": alert_info["count"],
                "last_detected": alert_info["last_detected"],
                "coverage_status": status
            })

        covered_count = sum(1 for tactic, items in matrix.items() if len(items) > 0)
        total_rules = len(rules)
        total_alerts = sum(sum(item["alert_count"] for item in items) for items in matrix.values())

        return {
            "total_tactics": len(all_tactics),
            "covered_tactics": covered_count,
            "coverage_percentage": round((covered_count / len(all_tactics)) * 100, 1),
            "total_active_rules": total_rules,
            "total_detections_triggered": total_alerts,
            "matrix": matrix
        }
