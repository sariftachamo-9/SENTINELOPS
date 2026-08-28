"""
Phase 6 Hardened — Incident Manager
Implements Incident as a first-class object in the Alert → Incident → Case chain.

Valid statuses:  OPEN → IN_INVESTIGATION → CONTAINED → RESOLVED → CLOSED
Valid severities: critical | high | medium | low
Valid priorities: P1 | P2 | P3 | P4

Optimistic concurrency: pass expected_version to update methods.
Rejects stale writes with CaseIncidentConcurrencyError (→ HTTP 409).
"""
import json
import uuid
from datetime import datetime
from typing import Optional, List, Dict, Any

from src.database import Database
from src.audit import AuditLogger

INCIDENT_VALID_STATUSES = ["OPEN", "IN_INVESTIGATION", "CONTAINED", "RESOLVED", "CLOSED"]
INCIDENT_VALID_SEVERITIES = ["critical", "high", "medium", "low"]
INCIDENT_VALID_PRIORITIES = ["P1", "P2", "P3", "P4"]

INCIDENT_ALLOWED_TRANSITIONS: Dict[str, set] = {
    "OPEN":             {"IN_INVESTIGATION", "CONTAINED", "RESOLVED", "CLOSED"},
    "IN_INVESTIGATION": {"CONTAINED", "RESOLVED", "CLOSED"},
    "CONTAINED":        {"RESOLVED", "CLOSED"},
    "RESOLVED":         {"CLOSED"},
    "CLOSED":           set(),
}


class IncidentStateError(Exception):
    pass


class IncidentConcurrencyError(Exception):
    """Raised when an optimistic concurrency check fails (stale write)."""
    pass


class IncidentManager:
    def __init__(self, db: Database = None):
        self.db = db if db else Database()
        self.audit = AuditLogger(db=self.db)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _now(self) -> str:
        return datetime.now().isoformat()

    def _row_to_dict(self, row) -> dict:
        if row is None:
            return {}
        d = dict(row)
        for field in ["related_alerts", "mitre_techniques", "affected_assets",
                      "affected_users", "ioc_list", "analysts"]:
            try:
                d[field] = json.loads(d[field]) if d.get(field) else []
            except Exception:
                d[field] = []
        return d

    def _check_concurrency(self, incident_id: str, expected_version: Optional[int]):
        """If expected_version is given, verify it matches the stored version."""
        if expected_version is None:
            return
        cursor = self.db.get_cursor()
        cursor.execute("SELECT version FROM incidents WHERE id = ?", (incident_id,))
        row = cursor.fetchone()
        if not row:
            return
        db_version = row["version"] if "version" in row.keys() else 1
        if db_version != expected_version:
            raise IncidentConcurrencyError(
                f"Stale write rejected: incident '{incident_id}' is at version {db_version}, "
                f"but expected version {expected_version}. Fetch the latest version and retry."
            )

    # ------------------------------------------------------------------
    # Incident CRUD
    # ------------------------------------------------------------------

    def create_incident(
        self,
        title: str,
        description: str = "",
        severity: str = "medium",
        priority: str = "P2",
        category: str = "Security Incident",
        related_alert_ids: List[str] = None,
        mitre_techniques: List[str] = None,
        assigned_to: str = "Unassigned",
        created_by: str = "system",
    ) -> dict:
        """Create a first-class Incident with optional alert and MITRE linkage."""
        severity = severity.lower()
        priority = priority.upper()
        if severity not in INCIDENT_VALID_SEVERITIES:
            raise ValueError(f"Invalid severity '{severity}'. Must be one of: {INCIDENT_VALID_SEVERITIES}")
        if priority not in INCIDENT_VALID_PRIORITIES:
            raise ValueError(f"Invalid priority '{priority}'. Must be one of: {INCIDENT_VALID_PRIORITIES}")

        incident_id = f"INC-{datetime.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
        now_str = self._now()

        cursor = self.db.get_cursor()
        cursor.execute(
            """
            INSERT INTO incidents
            (id, title, severity, priority, status, category, description,
             created_at, updated_at, assigned_to, related_alerts,
             mitre_techniques, affected_assets, affected_users, ioc_list, version)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
            """,
            (
                incident_id, title, severity, priority, "OPEN", category, description,
                now_str, now_str, assigned_to,
                json.dumps(related_alert_ids or []),
                json.dumps(mitre_techniques or []),
                "[]", "[]", "[]",
            ),
        )
        self.db.conn.commit()

        # Link alerts via junction table
        for alert_id in (related_alert_ids or []):
            self._link_alert(incident_id, alert_id, linked_by=created_by)

        self.audit.log(
            username=created_by,
            role="system",
            action="INCIDENT_CREATED",
            target_type="incident",
            target_id=incident_id,
            new_value={
                "title": title,
                "severity": severity,
                "priority": priority,
                "related_alerts": related_alert_ids or [],
                "mitre_techniques": mitre_techniques or [],
            },
        )

        return self.get_incident(incident_id)

    def get_incident(self, incident_id: str) -> Optional[dict]:
        cursor = self.db.get_cursor()
        cursor.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,))
        row = cursor.fetchone()
        if not row:
            return None
        d = self._row_to_dict(row)
        d["linked_alerts"] = self.get_incident_alerts(incident_id)
        return d

    def list_incidents(
        self,
        status: str = None,
        severity: str = None,
        assigned_to: str = None,
        limit: int = 50,
        offset: int = 0,
    ) -> dict:
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
        cursor = self.db.get_cursor()

        cursor.execute(f"SELECT COUNT(*) FROM incidents {where}", params)
        total = cursor.fetchone()[0]

        cursor.execute(
            f"SELECT * FROM incidents {where} ORDER BY created_at DESC LIMIT ? OFFSET ?",
            params + [limit, offset],
        )
        incidents = [self._row_to_dict(r) for r in cursor.fetchall()]
        return {"incidents": incidents, "total": total, "limit": limit, "offset": offset}

    # ------------------------------------------------------------------
    # Status state machine
    # ------------------------------------------------------------------

    def update_incident_status(
        self,
        incident_id: str,
        new_status: str,
        user: str,
        role: str = "",
        expected_version: Optional[int] = None,
    ) -> dict:
        inc = self.get_incident(incident_id)
        if not inc:
            raise ValueError(f"Incident '{incident_id}' not found")

        self._check_concurrency(incident_id, expected_version)

        new_status = new_status.upper()
        current_status = inc.get("status", "OPEN").upper()

        if new_status not in INCIDENT_VALID_STATUSES:
            raise IncidentStateError(f"Invalid status '{new_status}'")

        allowed = INCIDENT_ALLOWED_TRANSITIONS.get(current_status, set())
        if new_status not in allowed:
            raise IncidentStateError(
                f"Transition {current_status} → {new_status} is not allowed. "
                f"Allowed: {', '.join(sorted(allowed)) or 'none'}"
            )

        now_str = self._now()
        resolved_at = now_str if new_status in ("RESOLVED", "CLOSED") else inc.get("resolved_at", "")

        cursor = self.db.get_cursor()
        cursor.execute(
            "UPDATE incidents SET status = ?, updated_at = ?, resolved_at = ?, "
            "version = version + 1 WHERE id = ?",
            (new_status, now_str, resolved_at, incident_id),
        )
        self.db.conn.commit()

        self.audit.log(
            username=user,
            role=role,
            action="INCIDENT_STATUS_CHANGED",
            target_type="incident",
            target_id=incident_id,
            old_value={"status": current_status},
            new_value={"status": new_status},
        )
        return self.get_incident(incident_id)

    # ------------------------------------------------------------------
    # Assignment
    # ------------------------------------------------------------------

    def update_incident_assignment(
        self,
        incident_id: str,
        assigned_to: str,
        user: str,
        role: str = "",
        expected_version: Optional[int] = None,
    ) -> dict:
        inc = self.get_incident(incident_id)
        if not inc:
            raise ValueError(f"Incident '{incident_id}' not found")

        self._check_concurrency(incident_id, expected_version)

        old_assignee = inc.get("assigned_to", "Unassigned")
        now_str = self._now()
        cursor = self.db.get_cursor()
        cursor.execute(
            "UPDATE incidents SET assigned_to = ?, updated_at = ?, version = version + 1 WHERE id = ?",
            (assigned_to, now_str, incident_id),
        )
        self.db.conn.commit()

        self.audit.log(
            username=user,
            role=role,
            action="INCIDENT_ASSIGNED",
            target_type="incident",
            target_id=incident_id,
            old_value={"assigned_to": old_assignee},
            new_value={"assigned_to": assigned_to},
        )
        return self.get_incident(incident_id)

    # ------------------------------------------------------------------
    # Alert linkage
    # ------------------------------------------------------------------

    def _link_alert(self, incident_id: str, alert_id: str, linked_by: str = "system"):
        now_str = self._now()
        cursor = self.db.get_cursor()
        try:
            cursor.execute(
                "INSERT OR IGNORE INTO incident_alerts "
                "(incident_id, alert_id, linked_by, linked_at) VALUES (?, ?, ?, ?)",
                (incident_id, alert_id, linked_by, now_str),
            )
            self.db.conn.commit()
        except Exception:
            pass

    def link_alert_to_incident(
        self, incident_id: str, alert_id: str, linked_by: str = "analyst"
    ) -> dict:
        inc = self.get_incident(incident_id)
        if not inc:
            raise ValueError(f"Incident '{incident_id}' not found")

        self._link_alert(incident_id, alert_id, linked_by=linked_by)

        self.audit.log(
            username=linked_by,
            role="analyst",
            action="INCIDENT_ALERT_LINKED",
            target_type="incident",
            target_id=incident_id,
            new_value={"alert_id": alert_id},
        )
        return self.get_incident(incident_id)

    def get_incident_alerts(self, incident_id: str) -> List[dict]:
        """Return alerts linked to this incident via the incident_alerts junction."""
        cursor = self.db.get_cursor()
        cursor.execute(
            """
            SELECT a.id, a.title, a.severity, a.status, a.timestamp,
                   a.mitre_tactic, a.mitre_technique, a.affected_asset,
                   ia.linked_by, ia.linked_at
            FROM incident_alerts ia
            LEFT JOIN alerts a ON ia.alert_id = a.id
            WHERE ia.incident_id = ?
            ORDER BY ia.linked_at ASC
            """,
            (incident_id,),
        )
        return [dict(r) for r in cursor.fetchall()]

    # ------------------------------------------------------------------
    # Incident timeline
    # ------------------------------------------------------------------

    def get_incident_timeline(self, incident_id: str) -> List[dict]:
        """
        Build a unified timeline for the incident from:
        - Incident creation / status changes (audit log)
        - Linked alert timestamps
        """
        cursor = self.db.get_cursor()

        # Audit events for this incident
        cursor.execute(
            "SELECT timestamp, username, action, old_value, new_value "
            "FROM audit_logs WHERE target_type = 'incident' AND target_id = ? "
            "ORDER BY timestamp ASC",
            (incident_id,),
        )
        audit_rows = cursor.fetchall()

        timeline = []
        for row in audit_rows:
            try:
                old_val = json.loads(row["old_value"]) if row["old_value"] else {}
            except Exception:
                old_val = {}
            try:
                new_val = json.loads(row["new_value"]) if row["new_value"] else {}
            except Exception:
                new_val = {}
            timeline.append({
                "timestamp": row["timestamp"],
                "type": "audit",
                "actor": row["username"],
                "action": row["action"],
                "old_value": old_val,
                "new_value": new_val,
            })

        # Linked alert events
        linked_alerts = self.get_incident_alerts(incident_id)
        for a in linked_alerts:
            if a.get("timestamp"):
                timeline.append({
                    "timestamp": a["timestamp"],
                    "type": "alert_linked",
                    "actor": a.get("linked_by", "system"),
                    "action": "ALERT_LINKED",
                    "alert_id": a.get("id"),
                    "alert_title": a.get("title"),
                    "severity": a.get("severity"),
                })

        timeline.sort(key=lambda x: x.get("timestamp") or "")
        return timeline
