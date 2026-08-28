"""
SOC Lab — Scenario Engine & Lifecycle Controller (Phase 9)
===========================================================
Manages scenario lifecycle states (DRAFT, READY, RUNNING, PAUSED, COMPLETED, FAILED, CANCELLED).
Dispatches events into the Telemetry Pipeline with speed scaling (1x, 5x, 10x, 50x).
Enforces atomic state locking to prevent concurrent scenario runs.
Supports immutable replay by creating new scenario run IDs.
"""

from typing import Dict, List, Any, Optional
from datetime import datetime
import json
import uuid
import time

from src.database import Database
from src.audit import AuditLogger
from src.telemetry.pipeline import TelemetryPipeline
from src.simulation.scenarios import get_scenario, list_scenarios, SCENARIOS_CATALOG


class ScenarioEngine:
    """
    Core state machine and orchestrator for SOC simulation scenario runs.
    """

    def __init__(self, db: Optional[Database] = None):
        self.db = db or Database()
        self.audit_logger = AuditLogger()
        self.pipeline = TelemetryPipeline(db=self.db)
        self._ensure_scenarios_seeded()

    def _ensure_scenarios_seeded(self):
        """Seed standard scenarios into scenarios table if empty."""
        cursor = self.db.get_cursor()
        for scen_id, scen in SCENARIOS_CATALOG.items():
            cursor.execute("SELECT scenario_id FROM scenarios WHERE scenario_id = ?", (scen_id,))
            if not cursor.fetchone():
                now_str = datetime.now().isoformat()
                cursor.execute('''
                    INSERT INTO scenarios (scenario_id, name, category, difficulty, target_role, description, mitre_attack, steps, hints, estimated_duration_mins, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    scen.scenario_id, scen.name, scen.category, scen.difficulty, scen.target_role,
                    scen.description, json.dumps(scen.mitre_attack), json.dumps(scen.steps),
                    json.dumps(scen.hints), scen.estimated_duration_mins, now_str, now_str
                ))
        self.db.conn.commit()

    def get_scenario(self, scenario_id: str) -> Optional[Dict[str, Any]]:
        scen = get_scenario(scenario_id)
        if scen:
            return scen.to_dict()
        cursor = self.db.get_cursor()
        cursor.execute("SELECT * FROM scenarios WHERE scenario_id = ?", (scenario_id,))
        row = cursor.fetchone()
        if not row:
            return None
        dict_r = dict(row)
        for field in ["mitre_attack", "steps", "hints"]:
            if isinstance(dict_r.get(field), str):
                try:
                    dict_r[field] = json.loads(dict_r[field])
                except Exception:
                    pass
        return dict_r

    def list_scenarios(self) -> List[Dict[str, Any]]:
        return list_scenarios()

    def start_scenario(
        self,
        scenario_id: str,
        requested_by: str = "system",
        speed_multiplier: float = 1.0,
        sync_execute: bool = True
    ) -> Dict[str, Any]:
        """
        Start a new scenario run with atomic state locking.
        """
        scen = self.get_scenario(scenario_id)
        if not scen:
            return {"status": "ERROR", "error": f"Scenario '{scenario_id}' not found."}

        cursor = self.db.get_cursor()

        # Atomic Concurrency Lock: Check if any scenario run is currently RUNNING
        cursor.execute("SELECT run_id, scenario_id FROM scenario_runs WHERE status = 'RUNNING'")
        active = cursor.fetchone()
        if active:
            return {
                "status": "CONCURRENCY_LOCK_ERROR",
                "error": f"Scenario run '{active['run_id']}' (Scenario '{active['scenario_id']}') is currently RUNNING. Concurrent runs are locked.",
                "active_run_id": active['run_id']
            }

        run_id = f"run-{uuid.uuid4().hex[:8]}"
        now_str = datetime.now().isoformat()

        cursor.execute('''
            INSERT INTO scenario_runs (run_id, scenario_id, status, speed_multiplier, started_at, requested_by, source_mode, created_at)
            VALUES (?, ?, 'RUNNING', ?, ?, ?, 'simulation', ?)
        ''', (run_id, scenario_id, speed_multiplier, now_str, requested_by, now_str))
        self.db.conn.commit()

        self.audit_logger.log(
            username=requested_by,
            role="User",
            action="START_SCENARIO_RUN",
            target_type="SCENARIO_RUN",
            target_id=run_id,
            new_value={"scenario_id": scenario_id, "speed_multiplier": speed_multiplier}
        )

        if sync_execute:
            return self._execute_run(run_id, scen, speed_multiplier, requested_by)

        return {
            "status": "RUNNING",
            "run_id": run_id,
            "scenario_id": scenario_id,
            "started_at": now_str
        }

    def _execute_run(
        self,
        run_id: str,
        scen_dict: Dict[str, Any],
        speed_multiplier: float,
        requested_by: str
    ) -> Dict[str, Any]:
        """
        Execute event timeline generation and dispatch through TelemetryPipeline.
        """
        scen_obj = get_scenario(scen_dict["scenario_id"])
        events = scen_obj.generate_events() if scen_obj else []

        cursor = self.db.get_cursor()
        total_events = len(events)
        total_alerts = 0
        step_index = 1

        for ev in events:
            # Check if run was paused or cancelled during loop
            cursor.execute("SELECT status FROM scenario_runs WHERE run_id = ?", (run_id,))
            st_row = cursor.fetchone()
            if st_row and st_row[0] in ["PAUSED", "CANCELLED"]:
                return self.get_run(run_id)

            # Enforce simulation source_mode
            ev["source_mode"] = "simulation"
            ev["simulation"] = True

            # Process event through standard pipeline
            pipe_res = self.pipeline.process_event(raw_event=ev, source_type=ev.get("source_type", "linux"), environment="lab")
            total_alerts += pipe_res.alerts_triggered

            # Record scenario event log
            cursor.execute('''
                INSERT INTO scenario_events (id, run_id, step_number, event_id, source_mode, event_type, timestamp, payload)
                VALUES (?, ?, ?, ?, 'simulation', ?, ?, ?)
            ''', (
                f"sev-{uuid.uuid4().hex[:8]}", run_id, step_index, pipe_res.event_id or ev["event_id"],
                ev.get("event_type", ""), datetime.now().isoformat(), json.dumps(ev)
            ))
            step_index += 1

        now_str = datetime.now().isoformat()
        cursor.execute('''
            UPDATE scenario_runs
            SET status = 'COMPLETED', completed_at = ?, events_count = ?, alerts_count = ?
            WHERE run_id = ?
        ''', (now_str, total_events, total_alerts, run_id))
        self.db.conn.commit()

        self.audit_logger.log(
            username=requested_by,
            role="User",
            action="COMPLETED_SCENARIO_RUN",
            target_type="SCENARIO_RUN",
            target_id=run_id,
            new_value={"events_count": total_events, "alerts_count": total_alerts}
        )

        return self.get_run(run_id)

    def pause_run(self, run_id: str, requested_by: str = "system") -> Dict[str, Any]:
        cursor = self.db.get_cursor()
        cursor.execute("SELECT status FROM scenario_runs WHERE run_id = ?", (run_id,))
        row = cursor.fetchone()
        if not row:
            return {"status": "ERROR", "error": f"Run '{run_id}' not found."}
        if row[0] != "RUNNING":
            return {"status": "ERROR", "error": f"Run '{run_id}' cannot be paused from state '{row[0]}'."}

        now_str = datetime.now().isoformat()
        cursor.execute("UPDATE scenario_runs SET status = 'PAUSED', paused_at = ? WHERE run_id = ?", (now_str, run_id))
        self.db.conn.commit()

        self.audit_logger.log(
            username=requested_by,
            role="User",
            action="PAUSE_SCENARIO_RUN",
            target_type="SCENARIO_RUN",
            target_id=run_id,
            new_value={"status": "PAUSED"}
        )
        return self.get_run(run_id)

    def resume_run(self, run_id: str, requested_by: str = "system") -> Dict[str, Any]:
        cursor = self.db.get_cursor()
        cursor.execute("SELECT status, scenario_id, speed_multiplier FROM scenario_runs WHERE run_id = ?", (run_id,))
        row = cursor.fetchone()
        if not row:
            return {"status": "ERROR", "error": f"Run '{run_id}' not found."}
        if row[0] != "PAUSED":
            return {"status": "ERROR", "error": f"Run '{run_id}' is not in PAUSED state."}

        cursor.execute("UPDATE scenario_runs SET status = 'RUNNING', paused_at = NULL WHERE run_id = ?", (run_id,))
        self.db.conn.commit()

        self.audit_logger.log(
            username=requested_by,
            role="User",
            action="RESUME_SCENARIO_RUN",
            target_type="SCENARIO_RUN",
            target_id=run_id,
            new_value={"status": "RUNNING"}
        )
        scen = self.get_scenario(row["scenario_id"])
        return self._execute_run(run_id, scen, row["speed_multiplier"], requested_by)

    def cancel_run(self, run_id: str, requested_by: str = "system", reason: str = "User cancelled") -> Dict[str, Any]:
        cursor = self.db.get_cursor()
        cursor.execute("SELECT status FROM scenario_runs WHERE run_id = ?", (run_id,))
        row = cursor.fetchone()
        if not row:
            return {"status": "ERROR", "error": f"Run '{run_id}' not found."}

        now_str = datetime.now().isoformat()
        cursor.execute("UPDATE scenario_runs SET status = 'CANCELLED', completed_at = ?, error_msg = ? WHERE run_id = ?", (now_str, reason, run_id))
        self.db.conn.commit()

        self.audit_logger.log(
            username=requested_by,
            role="User",
            action="CANCEL_SCENARIO_RUN",
            target_type="SCENARIO_RUN",
            target_id=run_id,
            new_value={"status": "CANCELLED", "reason": reason}
        )
        return self.get_run(run_id)

    def replay_run(self, run_id: str, requested_by: str = "system") -> Dict[str, Any]:
        """
        Replay an existing run by starting a fresh scenario run with a UNIQUE run_id.
        Historical run data remains immutable.
        """
        old_run = self.get_run(run_id)
        if not old_run:
            return {"status": "ERROR", "error": f"Run '{run_id}' not found for replay."}

        return self.start_scenario(
            scenario_id=old_run["scenario_id"],
            requested_by=requested_by,
            speed_multiplier=old_run.get("speed_multiplier", 1.0),
            sync_execute=True
        )

    def reset_engine_state(self, requested_by: str = "system") -> Dict[str, Any]:
        """
        Reset any stuck RUNNING scenario runs to CANCELLED state.
        """
        cursor = self.db.get_cursor()
        cursor.execute("UPDATE scenario_runs SET status = 'CANCELLED', error_msg = 'Engine Reset' WHERE status IN ('RUNNING', 'PAUSED')")
        self.db.conn.commit()
        return {"status": "SUCCESS", "details": "Cleared active scenario runs."}

    def get_run(self, run_id: str) -> Optional[Dict[str, Any]]:
        cursor = self.db.get_cursor()
        cursor.execute("SELECT * FROM scenario_runs WHERE run_id = ?", (run_id,))
        row = cursor.fetchone()
        if not row:
            return None
        dict_r = dict(row)
        cursor.execute("SELECT COUNT(*) FROM scenario_events WHERE run_id = ?", (run_id,))
        dict_r["events_recorded"] = cursor.fetchone()[0]
        return dict_r

    def get_run_timeline(self, run_id: str) -> List[Dict[str, Any]]:
        cursor = self.db.get_cursor()
        cursor.execute("SELECT * FROM scenario_events WHERE run_id = ? ORDER BY step_number ASC", (run_id,))
        rows = cursor.fetchall()
        results = []
        for r in rows:
            dict_r = dict(r)
            if isinstance(dict_r.get("payload"), str):
                try:
                    dict_r["payload"] = json.loads(dict_r["payload"])
                except Exception:
                    pass
            results.append(dict_r)
        return results

    def list_runs(self, limit: int = 50) -> List[Dict[str, Any]]:
        cursor = self.db.get_cursor()
        cursor.execute("SELECT * FROM scenario_runs ORDER BY created_at DESC LIMIT ?", (limit,))
        return [dict(r) for r in cursor.fetchall()]
