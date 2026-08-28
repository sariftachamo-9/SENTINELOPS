"""
Phase 6 — Case Management
Full state-machine, IDOR protection, alert/incident linking, pagination.

Valid statuses:    OPEN → IN_PROGRESS → CONTAINED → RESOLVED → CLOSED
Valid dispositions: TRUE_POSITIVE | FALSE_POSITIVE | BENIGN | UNDETERMINED
"""
import json
import uuid
from datetime import datetime
from typing import Optional, List, Dict, Any

from src.database import Database
from src.audit import AuditLogger

VALID_STATUSES = ["OPEN", "IN_PROGRESS", "CONTAINED", "RESOLVED", "CLOSED"]
VALID_DISPOSITIONS = ["TRUE_POSITIVE", "FALSE_POSITIVE", "BENIGN", "UNDETERMINED"]
VALID_PRIORITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
VALID_SEVERITIES = ["critical", "high", "medium", "low"]

# Allowed forward transitions (backward moves require cases.manage)
ALLOWED_TRANSITIONS = {
    "OPEN":        {"IN_PROGRESS", "RESOLVED", "CLOSED"},
    "IN_PROGRESS": {"CONTAINED", "RESOLVED", "CLOSED"},
    "CONTAINED":   {"RESOLVED", "CLOSED"},
    "RESOLVED":    {"CLOSED"},
    "CLOSED":      set(),
}


class CaseStateError(Exception):
    pass


class CaseConcurrencyError(Exception):
    """Raised when an optimistic concurrency check fails on a case write."""
    pass


class CaseManager:
    def __init__(self, db: Database = None):
        self.db = db if db else Database()
        self.audit = AuditLogger(db=self.db)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _row_to_dict(self, row) -> dict:
        d = dict(row)
        for field in ["investigators", "related_incidents", "tasks", "tags"]:
            try:
                d[field] = json.loads(d[field]) if d.get(field) else []
            except Exception:
                d[field] = []
        return d

    def _now(self) -> str:
        return datetime.now().isoformat()

    def _check_concurrency(self, case_id: str, expected_version: Optional[int]):
        """If expected_version is provided, verify it matches the current DB version."""
        if expected_version is None:
            return
        cursor = self.db.get_cursor()
        cursor.execute("SELECT version FROM cases WHERE id = ?", (case_id,))
        row = cursor.fetchone()
        if not row:
            return
        db_version = row["version"] if "version" in row.keys() else 1
        if db_version != expected_version:
            raise CaseConcurrencyError(
                f"Stale write rejected: case '{case_id}' is at version {db_version}, "
                f"but expected version {expected_version}. Fetch the latest version and retry."
            )

    # ------------------------------------------------------------------
    # Case CRUD
    # ------------------------------------------------------------------

    def create_case(
        self,
        title: str,
        description: str = "",
        severity: str = "medium",
        priority: str = "MEDIUM",
        created_by: str = "system",
        tags: List[str] = None,
        due_date: str = "",
        assigned_to: str = "Unassigned",
    ) -> dict:
        severity = severity.lower()
        priority = priority.upper()
        if severity not in VALID_SEVERITIES:
            raise ValueError(f"Invalid severity '{severity}'. Must be one of: {VALID_SEVERITIES}")
        if priority not in VALID_PRIORITIES:
            raise ValueError(f"Invalid priority '{priority}'. Must be one of: {VALID_PRIORITIES}")

        case_id = f"CASE-{datetime.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
        now_str = self._now()
        tags_json = json.dumps(tags or [])

        cursor = self.db.get_cursor()
        cursor.execute(
            """
            INSERT INTO cases
            (id, title, description, severity, priority, status, assigned_to, created_by,
             created_at, updated_at, closed_at, disposition, tags, due_date,
             lead_investigator, investigators, related_incidents, tasks)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                case_id, title, description, severity, priority,
                "OPEN", assigned_to, created_by,
                now_str, now_str, "", "UNDETERMINED", tags_json, due_date or "",
                created_by, json.dumps([created_by]), json.dumps([]), json.dumps([]),
            ),
        )
        self.db.conn.commit()

        self.audit.log(
            username=created_by,
            role="analyst",
            action="CASE_CREATED",
            target_type="case",
            target_id=case_id,
            new_value={"title": title, "severity": severity, "priority": priority},
        )

        return self.get_case(case_id)

    def get_case(self, case_id: str) -> Optional[dict]:
        cursor = self.db.get_cursor()
        cursor.execute("SELECT * FROM cases WHERE id = ?", (case_id,))
        row = cursor.fetchone()
        if not row:
            return None
        return self._row_to_dict(row)

    def list_cases(
        self,
        status: str = None,
        severity: str = None,
        assigned_to: str = None,
        limit: int = 50,
        offset: int = 0,
    ) -> dict:
        cursor = self.db.get_cursor()
        conditions, params = [], []

        if status:
            conditions.append("status = ?")
            params.append(status.upper())
        if severity:
            conditions.append("severity = ?")
            params.append(severity.lower())
        if assigned_to:
            conditions.append("assigned_to = ?")
            params.append(assigned_to)

        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        count_params = list(params)
        params.extend([limit, offset])

        cursor.execute(f"SELECT COUNT(*) FROM cases {where}", count_params)
        total = cursor.fetchone()[0]

        cursor.execute(
            f"SELECT * FROM cases {where} ORDER BY created_at DESC LIMIT ? OFFSET ?",
            params,
        )
        cases = [self._row_to_dict(r) for r in cursor.fetchall()]
        return {"cases": cases, "total": total, "limit": limit, "offset": offset}

    def update_case(self, case_id: str, updates: Dict[str, Any], updated_by: str) -> dict:
        existing = self.get_case(case_id)
        if not existing:
            raise ValueError(f"Case '{case_id}' not found")

        allowed_update_fields = {"title", "description", "due_date", "tags"}
        sanitized = {}
        for field, value in updates.items():
            if field in allowed_update_fields:
                sanitized[field] = value

        if not sanitized:
            raise ValueError("No valid fields to update")

        now_str = self._now()
        for field, value in sanitized.items():
            if field == "tags" and isinstance(value, list):
                value = json.dumps(value)
            cursor = self.db.get_cursor()
            cursor.execute(
                f"UPDATE cases SET {field} = ?, updated_at = ? WHERE id = ?",
                (value, now_str, case_id),
            )
        self.db.conn.commit()

        self.audit.log(
            username=updated_by,
            role="analyst",
            action="CASE_UPDATED",
            target_type="case",
            target_id=case_id,
            old_value={f: existing.get(f) for f in sanitized},
            new_value=sanitized,
        )
        return self.get_case(case_id)

    # ------------------------------------------------------------------
    # Status Machine
    # ------------------------------------------------------------------

    def update_case_status(
        self, case_id: str, new_status: str, user: str, role: str = "",
        force: bool = False, expected_version: Optional[int] = None
    ) -> dict:
        existing = self.get_case(case_id)
        if not existing:
            raise ValueError(f"Case '{case_id}' not found")

        self._check_concurrency(case_id, expected_version)

        new_status = new_status.upper()
        if new_status not in VALID_STATUSES:
            raise CaseStateError(
                f"Invalid status '{new_status}'. Valid statuses: {VALID_STATUSES}"
            )

        old_status = existing["status"]
        allowed = ALLOWED_TRANSITIONS.get(old_status, set())

        if new_status not in allowed and not force:
            # Privileged roles (cases.manage) may bypass the forward-only restriction
            if role not in ("Administrator", "SOC Manager", "Incident Responder"):
                raise CaseStateError(
                    f"Invalid state transition: {old_status} → {new_status}. "
                    f"Allowed: {sorted(allowed) or ['none']}"
                )

        now_str = self._now()
        closed_at = now_str if new_status == "CLOSED" else existing.get("closed_at", "")

        cursor = self.db.get_cursor()
        cursor.execute(
            "UPDATE cases SET status = ?, closed_at = ?, updated_at = ?, "
            "version = version + 1 WHERE id = ?",
            (new_status, closed_at, now_str, case_id),
        )
        self.db.conn.commit()

        self.audit.log(
            username=user,
            role=role or "analyst",
            action="CASE_STATUS_CHANGED",
            target_type="case",
            target_id=case_id,
            old_value={"status": old_status},
            new_value={"status": new_status},
        )
        return self.get_case(case_id)

    def update_case_disposition(
        self, case_id: str, disposition: str, user: str, role: str = "",
        expected_version: Optional[int] = None
    ) -> dict:
        existing = self.get_case(case_id)
        if not existing:
            raise ValueError(f"Case '{case_id}' not found")

        self._check_concurrency(case_id, expected_version)

        disposition = disposition.upper()
        if disposition not in VALID_DISPOSITIONS:
            raise ValueError(
                f"Invalid disposition '{disposition}'. Must be one of: {VALID_DISPOSITIONS}"
            )

        now_str = self._now()
        cursor = self.db.get_cursor()
        cursor.execute(
            "UPDATE cases SET disposition = ?, updated_at = ?, version = version + 1 WHERE id = ?",
            (disposition, now_str, case_id),
        )
        self.db.conn.commit()

        self.audit.log(
            username=user,
            role=role or "analyst",
            action="CASE_DISPOSITION_SET",
            target_type="case",
            target_id=case_id,
            old_value={"disposition": existing.get("disposition")},
            new_value={"disposition": disposition},
        )
        return self.get_case(case_id)

    def assign_case(
        self, case_id: str, assignee: str, user: str, role: str = "",
        expected_version: Optional[int] = None
    ) -> dict:
        existing = self.get_case(case_id)
        if not existing:
            raise ValueError(f"Case '{case_id}' not found")

        self._check_concurrency(case_id, expected_version)

        old_assignee = existing.get("assigned_to", "Unassigned")
        now_str = self._now()
        cursor = self.db.get_cursor()
        cursor.execute(
            "UPDATE cases SET assigned_to = ?, updated_at = ?, version = version + 1 WHERE id = ?",
            (assignee, now_str, case_id),
        )
        self.db.conn.commit()

        self.audit.log(
            username=user,
            role=role or "analyst",
            action="CASE_ASSIGNED",
            target_type="case",
            target_id=case_id,
            old_value={"assigned_to": old_assignee},
            new_value={"assigned_to": assignee},
        )
        return self.get_case(case_id)

    # ------------------------------------------------------------------
    # Alert / Incident linking
    # ------------------------------------------------------------------

    def link_alert_to_case(self, case_id: str, alert_id: str, linked_by: str) -> dict:
        existing = self.get_case(case_id)
        if not existing:
            raise ValueError(f"Case '{case_id}' not found")

        now_str = self._now()
        cursor = self.db.get_cursor()
        try:
            cursor.execute(
                "INSERT OR IGNORE INTO case_alerts (case_id, alert_id, linked_by, linked_at) "
                "VALUES (?, ?, ?, ?)",
                (case_id, alert_id, linked_by, now_str),
            )
        except Exception:
            pass
        self.db.conn.commit()

        # Update case updated_at
        cursor.execute("UPDATE cases SET updated_at = ? WHERE id = ?", (now_str, case_id))
        self.db.conn.commit()

        self.audit.log(
            username=linked_by,
            role="analyst",
            action="ALERT_LINKED_TO_CASE",
            target_type="case",
            target_id=case_id,
            new_value={"alert_id": alert_id},
        )
        return {"status": "linked", "case_id": case_id, "alert_id": alert_id}

    def link_incident_to_case(self, case_id: str, incident_id: str, linked_by: str) -> dict:
        existing = self.get_case(case_id)
        if not existing:
            raise ValueError(f"Case '{case_id}' not found")

        now_str = self._now()
        cursor = self.db.get_cursor()
        try:
            cursor.execute(
                "INSERT OR IGNORE INTO case_incidents (case_id, incident_id, linked_by, linked_at) "
                "VALUES (?, ?, ?, ?)",
                (case_id, incident_id, linked_by, now_str),
            )
        except Exception:
            pass
        self.db.conn.commit()

        cursor.execute("UPDATE cases SET updated_at = ? WHERE id = ?", (now_str, case_id))
        self.db.conn.commit()

        self.audit.log(
            username=linked_by,
            role="analyst",
            action="INCIDENT_LINKED_TO_CASE",
            target_type="case",
            target_id=case_id,
            new_value={"incident_id": incident_id},
        )
        return {"status": "linked", "case_id": case_id, "incident_id": incident_id}

    def get_case_alerts(self, case_id: str) -> List[dict]:
        cursor = self.db.get_cursor()
        cursor.execute(
            "SELECT a.* FROM alerts a "
            "JOIN case_alerts ca ON a.id = ca.alert_id "
            "WHERE ca.case_id = ? ORDER BY a.timestamp DESC",
            (case_id,),
        )
        rows = []
        for row in cursor.fetchall():
            d = dict(row)
            for col in ["indicators", "evidence", "triggering_event_ids", "analyst_notes"]:
                try:
                    d[col] = json.loads(d[col]) if d.get(col) else []
                except Exception:
                    d[col] = []
            rows.append(d)
        return rows

    def get_case_incidents(self, case_id: str) -> List[dict]:
        cursor = self.db.get_cursor()
        cursor.execute(
            "SELECT i.* FROM incidents i "
            "JOIN case_incidents ci ON i.id = ci.incident_id "
            "WHERE ci.case_id = ? ORDER BY i.created_at DESC",
            (case_id,),
        )
        rows = []
        for row in cursor.fetchall():
            d = dict(row)
            for field in ["affected_assets", "affected_users", "related_alerts",
                          "evidence", "timeline", "ioc_list", "analysts"]:
                try:
                    d[field] = json.loads(d[field]) if d.get(field) else []
                except Exception:
                    d[field] = []
            rows.append(d)
        return rows
