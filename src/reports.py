import json
import csv
import io
from datetime import datetime
from src.database import Database

class SOCReportGenerator:
    def __init__(self, db: Database = None):
        self.db = db if db else Database()

    def generate_json_report(self, report_type: str = "daily_soc") -> dict:
        stats = self.db.get_stats()
        alerts = self.db.get_alerts(limit=50)
        incidents = self.db.get_incidents(limit=20)

        return {
            "report_title": f"Enterprise SOC {report_type.replace('_', ' ').title()} Report",
            "generated_at": datetime.now().isoformat(),
            "environment": "Production Lab",
            "summary": {
                "total_alerts": stats.get("total_alerts", 0),
                "active_incidents": stats.get("active_incidents", 0),
                "total_incidents": stats.get("total_incidents", 0),
                "total_events": stats.get("total_events", 0)
            },
            "recent_incidents": incidents,
            "top_alerts": alerts[:10]
        }

    def generate_csv_report(self, report_type: str = "alerts") -> str:
        output = io.StringIO()
        writer = csv.writer(output)

        if report_type == "incidents":
            incidents = self.db.get_incidents(limit=100)
            writer.writerow(["Incident ID", "Title", "Severity", "Priority", "Status", "Created At", "Category", "MITRE ATT&CK"])
            for inc in incidents:
                writer.writerow([
                    inc.get("id"), inc.get("title"), inc.get("severity"), inc.get("priority"),
                    inc.get("status"), inc.get("created_at"), inc.get("category"), inc.get("mitre_attack")
                ])
        else:
            alerts = self.db.get_alerts(limit=100)
            writer.writerow(["Alert ID", "Title", "Severity", "Status", "Source", "Destination", "Timestamp", "Rule"])
            for alt in alerts:
                writer.writerow([
                    alt.get("id"), alt.get("title"), alt.get("severity"), alt.get("status"),
                    alt.get("source"), alt.get("destination"), alt.get("timestamp"), alt.get("detection_rule")
                ])

        return output.getvalue()


class TrainingReportGenerator:
    """
    Generates training evaluation summary reports in JSON and CSV formats.
    """

    def __init__(self, db: Database = None):
        self.db = db if db else Database()

    def generate_training_json_report(self, session_id: str) -> dict:
        from src.simulation.training import TrainingManager
        tm = TrainingManager(db=self.db)
        sess = tm.get_session(session_id)
        if not sess:
            return {"error": f"Session '{session_id}' not found."}

        scorecard = sess.get("scorecard", {})
        return {
            "report_title": "SOC Analyst Training Performance Report",
            "generated_at": datetime.now().isoformat(),
            "session_id": session_id,
            "analyst_username": sess.get("analyst_username"),
            "scenario": {
                "id": sess.get("scenario_id"),
                "name": (sess.get("scenario") or {}).get("name"),
                "difficulty": (sess.get("scenario") or {}).get("difficulty")
            },
            "evaluation": {
                "status": sess.get("status"),
                "final_score": sess.get("final_score", 0),
                "passed": bool(sess.get("passed")),
                "scorecard": scorecard
            }
        }

    def generate_training_csv_report(self, session_id: str) -> str:
        from src.simulation.training import TrainingManager
        tm = TrainingManager(db=self.db)
        sess = tm.get_session(session_id)
        output = io.StringIO()
        writer = csv.writer(output)

        writer.writerow(["Session ID", "Analyst", "Scenario ID", "Status", "Final Score", "Passed", "Started At", "Submitted At"])
        if sess:
            writer.writerow([
                sess.get("session_id"),
                sess.get("analyst_username"),
                sess.get("scenario_id"),
                sess.get("status"),
                sess.get("final_score"),
                sess.get("passed"),
                sess.get("started_at"),
                sess.get("submitted_at")
            ])
        return output.getvalue()

