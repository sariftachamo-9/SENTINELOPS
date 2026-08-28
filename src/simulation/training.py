"""
SOC Lab — Training Manager (Phase 9)
=====================================
Orchestrates analyst training workflows, progressive hints, answer submissions,
and scorecard persistence.
"""

from typing import Dict, List, Any, Optional
from datetime import datetime
import json
import uuid

from src.database import Database
from src.audit import AuditLogger
from src.simulation.engine import ScenarioEngine
from src.simulation.scoring import AnalystScoringEngine


class TrainingManager:
    """
    Manages interactive training sessions for SOC analysts.
    """

    def __init__(self, db: Optional[Database] = None):
        self.db = db or Database()
        self.audit_logger = AuditLogger()
        self.engine = ScenarioEngine(db=self.db)
        self.scorer = AnalystScoringEngine()

    def start_session(self, analyst_username: str, scenario_id: str) -> Dict[str, Any]:
        scen = self.engine.get_scenario(scenario_id)
        if not scen:
            return {"status": "ERROR", "error": f"Scenario '{scenario_id}' not found."}

        # Start a scenario run for this training session
        run_res = self.engine.start_scenario(
            scenario_id=scenario_id,
            requested_by=analyst_username,
            speed_multiplier=1.0,
            sync_execute=True
        )

        session_id = f"trn-{uuid.uuid4().hex[:8]}"
        now_str = datetime.now().isoformat()

        cursor = self.db.get_cursor()
        cursor.execute('''
            INSERT INTO training_sessions (session_id, scenario_id, scenario_run_id, analyst_username, status, hints_used, current_step, started_at)
            VALUES (?, ?, ?, ?, 'IN_PROGRESS', '[]', 1, ?)
        ''', (session_id, scenario_id, run_res.get("run_id", ""), analyst_username, now_str))
        self.db.conn.commit()

        self.audit_logger.log(
            username=analyst_username,
            role="User",
            action="START_TRAINING_SESSION",
            target_type="TRAINING_SESSION",
            target_id=session_id,
            new_value={"scenario_id": scenario_id}
        )

        return self.get_session(session_id)

    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        cursor = self.db.get_cursor()
        cursor.execute("SELECT * FROM training_sessions WHERE session_id = ?", (session_id,))
        row = cursor.fetchone()
        if not row:
            return None
        dict_r = dict(row)
        if isinstance(dict_r.get("hints_used"), str):
            try:
                dict_r["hints_used"] = json.loads(dict_r["hints_used"])
            except Exception:
                pass

        scen = self.engine.get_scenario(dict_r["scenario_id"])
        dict_r["scenario"] = scen

        # Fetch recorded scorecard if completed
        if dict_r["status"] == "COMPLETED":
            cursor.execute("SELECT * FROM training_scores WHERE session_id = ?", (session_id,))
            sc_row = cursor.fetchone()
            if sc_row:
                score_dict = dict(sc_row)
                for field in ["breakdown_json", "mistakes_json", "correct_actions_json", "recommendations_json"]:
                    if isinstance(score_dict.get(field), str):
                        try:
                            score_dict[field.replace("_json", "")] = json.loads(score_dict[field])
                        except Exception:
                            pass
                dict_r["scorecard"] = score_dict

        return dict_r

    def request_hint(self, session_id: str, analyst_username: str = "analyst") -> Dict[str, Any]:
        session = self.get_session(session_id)
        if not session:
            return {"status": "ERROR", "error": f"Training session '{session_id}' not found."}

        hints_list = session["scenario"].get("hints", [])
        used_hints = session.get("hints_used", [])

        if len(used_hints) >= len(hints_list):
            return {
                "status": "NO_MORE_HINTS",
                "message": "All available hints for this scenario have already been requested.",
                "hints_used": used_hints
            }

        next_hint = hints_list[len(used_hints)]
        used_hints.append(next_hint)

        cursor = self.db.get_cursor()
        cursor.execute("UPDATE training_sessions SET hints_used = ? WHERE session_id = ?", (json.dumps(used_hints), session_id))
        self.db.conn.commit()

        self.audit_logger.log(
            username=analyst_username,
            role="User",
            action="REQUEST_TRAINING_HINT",
            target_type="TRAINING_SESSION",
            target_id=session_id,
            new_value={"hint_index": len(used_hints)}
        )

        return {
            "status": "HINT_PROVIDED",
            "hint": next_hint,
            "hints_used_count": len(used_hints),
            "total_hints_available": len(hints_list)
        }

    def submit_answers(
        self,
        session_id: str,
        answers: Dict[str, Any],
        analyst_username: str = "analyst"
    ) -> Dict[str, Any]:
        """
        Submit final investigation answers and compute scorecard.
        """
        session = self.get_session(session_id)
        if not session:
            return {"status": "ERROR", "error": f"Training session '{session_id}' not found."}

        scen_dict = session["scenario"]
        expected_answers = scen_dict.get("expected_answers", {})
        hints_used = session.get("hints_used", [])

        # Evaluate performance using AnalystScoringEngine
        score_res = self.scorer.evaluate_session(
            expected_answers=expected_answers,
            analyst_answers=answers,
            hints_used_count=len(hints_used)
        )

        score_id = f"sc-{uuid.uuid4().hex[:8]}"
        now_str = datetime.now().isoformat()

        cursor = self.db.get_cursor()
        cursor.execute('''
            INSERT INTO training_scores
            (score_id, session_id, scenario_id, analyst_username, total_score, percentage, passed, breakdown_json, mistakes_json, correct_actions_json, recommendations_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            score_id, session_id, session["scenario_id"], analyst_username,
            score_res["total_score"], score_res["percentage"], 1 if score_res["passed"] else 0,
            json.dumps(score_res["breakdown"]), json.dumps(score_res["mistakes"]),
            json.dumps(score_res["correct_actions"]), json.dumps(score_res["recommendations"]),
            now_str
        ))

        cursor.execute('''
            UPDATE training_sessions
            SET status = 'COMPLETED', submitted_at = ?, final_score = ?, passed = ?
            WHERE session_id = ?
        ''', (now_str, score_res["total_score"], 1 if score_res["passed"] else 0, session_id))
        self.db.conn.commit()

        self.audit_logger.log(
            username=analyst_username,
            role="User",
            action="SUBMIT_TRAINING_SESSION",
            target_type="TRAINING_SESSION",
            target_id=session_id,
            new_value={"total_score": score_res["total_score"], "passed": score_res["passed"]}
        )

        return self.get_session(session_id)

    def list_sessions(self, analyst_username: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
        cursor = self.db.get_cursor()
        if analyst_username:
            cursor.execute("SELECT * FROM training_sessions WHERE analyst_username = ? ORDER BY started_at DESC LIMIT ?", (analyst_username, limit))
        else:
            cursor.execute("SELECT * FROM training_sessions ORDER BY started_at DESC LIMIT ?", (limit,))
        return [dict(r) for r in cursor.fetchall()]
