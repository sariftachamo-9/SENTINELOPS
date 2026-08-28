"""
Phase 6 — Threat Hunting Engine
Implements a safe structured query model.
No raw SQL is accepted from users. Fields and operators are whitelisted.
"""
import json
import uuid
from datetime import datetime
from typing import List, Dict, Any, Optional
from src.database import Database
from src.audit import AuditLogger

# Whitelisted searchable fields mapped to actual DB column names
ALLOWED_FIELDS: Dict[str, str] = {
    "hostname":          "hostname",
    "username":          "username",
    "source_ip":         "source_ip",
    "destination_ip":    "destination_ip",
    "process_name":      "process_name",
    "event_type":        "event_type",
    "severity":          "severity",
    "source_type":       "source_type",
    "mitre_technique":   "mitre_technique",
    "rule_id":           "rule_id",
    "environment":       "environment",
}

# Whitelisted operators mapped to SQL fragments
ALLOWED_OPERATORS: Dict[str, str] = {
    "equals":       "= ?",
    "not_equals":   "!= ?",
    "contains":     "LIKE ?",
    "starts_with":  "LIKE ?",
    "ends_with":    "LIKE ?",
    "in":           "IN",        # special handling
    "greater_than": "> ?",
    "less_than":    "< ?",
}

# Events table columns that exist (for field validation against telemetry events)
EVENTS_TABLE_COLUMNS = {
    "hostname", "username", "source_ip", "destination_ip",
    "process_name", "event_type", "severity", "source_type", "environment",
}

# Safety limits (Req #6) — prevent accidental full-database scans
MAX_HUNT_LIMIT = 500            # Maximum results per page
MAX_HUNT_FILTERS = 10           # Maximum filter conditions per query
MAX_HUNT_TIME_RANGE_DAYS = 90   # Maximum time window in days


class HuntQueryValidationError(Exception):
    pass


class ThreatHunter:
    def __init__(self, db: Database = None):
        self.db = db if db else Database()
        self.audit = AuditLogger(db=self.db)

    # ------------------------------------------------------------------
    # Query validation
    # ------------------------------------------------------------------

    def _validate_filter(self, f: Dict[str, Any]) -> tuple:
        """Validate one filter dict, return (column, operator_sql, value)."""
        field = f.get("field", "")
        operator = f.get("operator", "")
        value = f.get("value")

        if field not in ALLOWED_FIELDS:
            raise HuntQueryValidationError(
                f"Field '{field}' is not searchable. "
                f"Allowed fields: {', '.join(sorted(ALLOWED_FIELDS))}"
            )
        if operator not in ALLOWED_OPERATORS:
            raise HuntQueryValidationError(
                f"Operator '{operator}' is not allowed. "
                f"Allowed operators: {', '.join(sorted(ALLOWED_OPERATORS))}"
            )
        if value is None or value == "":
            raise HuntQueryValidationError(f"Filter value for field '{field}' cannot be empty")

        column = ALLOWED_FIELDS[field]
        op_sql = ALLOWED_OPERATORS[operator]
        return column, operator, op_sql, value

    def _build_query(self, filters: List[Dict[str, Any]],
                     time_from: str = None, time_to: str = None,
                     limit: int = 100, offset: int = 0) -> tuple:
        """Build parameterized SQL from validated filters."""
        conditions = []
        params = []

        if time_from:
            conditions.append("timestamp >= ?")
            params.append(time_from)
        if time_to:
            conditions.append("timestamp <= ?")
            params.append(time_to)

        for f in filters:
            column, operator, op_sql, value = self._validate_filter(f)

            if operator == "in":
                if not isinstance(value, list) or not value:
                    raise HuntQueryValidationError(f"Operator 'in' requires a non-empty list value for field '{column}'")
                placeholders = ",".join("?" for _ in value)
                conditions.append(f"{column} IN ({placeholders})")
                params.extend(str(v) for v in value)
            elif operator == "contains":
                conditions.append(f"{column} {op_sql}")
                params.append(f"%{value}%")
            elif operator == "starts_with":
                conditions.append(f"{column} {op_sql}")
                params.append(f"{value}%")
            elif operator == "ends_with":
                conditions.append(f"{column} {op_sql}")
                params.append(f"%{value}")
            else:
                conditions.append(f"{column} {op_sql}")
                params.append(str(value))

        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        sql = (
            f"SELECT event_id, timestamp, hostname, username, source_ip, destination_ip, "
            f"source_port, destination_port, process_name, event_type, severity, "
            f"source_type, environment, normalized_event "
            f"FROM events {where} ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        )
        params.extend([limit, offset])

        # Count query
        count_sql = f"SELECT COUNT(*) FROM events {where}"
        count_params = params[: len(params) - 2]

        return sql, params, count_sql, count_params

    # ------------------------------------------------------------------
    # Execute hunt
    # ------------------------------------------------------------------

    def execute_hunt(self, query: Dict[str, Any], executing_user: str = "analyst",
                     limit: int = 100, offset: int = 0) -> Dict[str, Any]:
        """
        Execute a structured hunt query.
        Returns paginated results without ever touching raw user SQL.
        Safety limits enforced (Req #6):
          - MAX_HUNT_FILTERS: max filter conditions
          - MAX_HUNT_TIME_RANGE_DAYS: max time window
          - MAX_HUNT_LIMIT: max results per page
        """
        filters = query.get("filters", [])
        time_range = query.get("time_range", {})
        time_from = time_range.get("from") if isinstance(time_range, dict) else None
        time_to   = time_range.get("to")   if isinstance(time_range, dict) else None

        # Enforce max filter count
        if len(filters) > MAX_HUNT_FILTERS:
            raise HuntQueryValidationError(
                f"Too many filters: {len(filters)} provided, maximum is {MAX_HUNT_FILTERS}."
            )

        # Enforce max time range
        if time_from and time_to:
            try:
                from datetime import datetime as _dt
                dt_from = _dt.fromisoformat(time_from)
                dt_to   = _dt.fromisoformat(time_to)
                delta_days = (dt_to - dt_from).days
                if delta_days > MAX_HUNT_TIME_RANGE_DAYS:
                    raise HuntQueryValidationError(
                        f"Time range too large: {delta_days} days. "
                        f"Maximum allowed is {MAX_HUNT_TIME_RANGE_DAYS} days."
                    )
                if delta_days < 0:
                    raise HuntQueryValidationError(
                        "time_range 'from' must be before 'to'."
                    )
            except HuntQueryValidationError:
                raise
            except Exception:
                raise HuntQueryValidationError(
                    "Invalid time_range format. Use ISO 8601 (e.g. '2026-01-01T00:00:00')."
                )

        # Clamp limit to safety ceiling
        limit = min(limit, MAX_HUNT_LIMIT)
        if limit <= 0:
            limit = 100

        sql, params, count_sql, count_params = self._build_query(
            filters, time_from=time_from, time_to=time_to,
            limit=limit, offset=offset
        )

        cursor = self.db.get_cursor()
        cursor.execute(count_sql, count_params)
        total = cursor.fetchone()[0]

        cursor.execute(sql, params)
        rows = cursor.fetchall()

        results = []
        for r in rows:
            d = dict(r)
            try:
                d["normalized_event"] = json.loads(d.get("normalized_event") or "{}")
            except Exception:
                d["normalized_event"] = {}
            results.append(d)

        self.audit.log(
            username=executing_user,
            role="analyst",
            action="HUNT_EXECUTED",
            target_type="hunt",
            target_id="threat_hunt",
            new_value={"filters": filters, "total_results": total},
        )

        return {
            "results": results,
            "total": total,
            "limit": limit,
            "offset": offset,
            "returned": len(results),
        }

    # ------------------------------------------------------------------
    # Saved hunts
    # ------------------------------------------------------------------

    def save_hunt(self, name: str, query: Dict[str, Any], owner: str) -> dict:
        """Save a named hunt query. RBAC enforcement done at API layer."""
        hunt_id = f"HUNT-{uuid.uuid4().hex[:10].upper()}"
        now_str = datetime.now().isoformat()

        # Validate query before saving
        filters = query.get("filters", [])
        for f in filters:
            self._validate_filter(f)

        cursor = self.db.get_cursor()
        cursor.execute(
            "INSERT INTO saved_hunts (hunt_id, name, query, owner, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (hunt_id, name, json.dumps(query), owner, now_str, now_str),
        )
        self.db.conn.commit()

        self.audit.log(
            username=owner,
            role="analyst",
            action="HUNT_SAVED",
            target_type="saved_hunt",
            target_id=hunt_id,
            new_value={"name": name},
        )

        return self.get_saved_hunt(hunt_id, owner, bypass_owner_check=True)

    def get_saved_hunt(self, hunt_id: str, requesting_user: str,
                       requesting_role: str = "", bypass_owner_check: bool = False) -> Optional[dict]:
        """Retrieve a saved hunt. Non-admins can only see their own hunts."""
        cursor = self.db.get_cursor()
        cursor.execute("SELECT * FROM saved_hunts WHERE hunt_id = ?", (hunt_id,))
        row = cursor.fetchone()
        if not row:
            return None
        d = dict(row)
        try:
            d["query"] = json.loads(d.get("query") or "{}")
        except Exception:
            d["query"] = {}

        if bypass_owner_check:
            return d
        if requesting_role == "Administrator":
            return d
        if d.get("owner") != requesting_user:
            return None  # IDOR — not their hunt
        return d

    def list_saved_hunts(self, requesting_user: str, requesting_role: str = "",
                         limit: int = 50, offset: int = 0) -> List[dict]:
        """List saved hunts. Admins see all; others see only their own."""
        cursor = self.db.get_cursor()
        if requesting_role == "Administrator":
            cursor.execute(
                "SELECT * FROM saved_hunts ORDER BY created_at DESC LIMIT ? OFFSET ?",
                (limit, offset),
            )
        else:
            cursor.execute(
                "SELECT * FROM saved_hunts WHERE owner = ? ORDER BY created_at DESC LIMIT ? OFFSET ?",
                (requesting_user, limit, offset),
            )
        results = []
        for row in cursor.fetchall():
            d = dict(row)
            try:
                d["query"] = json.loads(d.get("query") or "{}")
            except Exception:
                d["query"] = {}
            results.append(d)
        return results

    def delete_saved_hunt(self, hunt_id: str, requesting_user: str, requesting_role: str = "") -> bool:
        """Delete a saved hunt. Only owner or admin."""
        hunt = self.get_saved_hunt(hunt_id, requesting_user, requesting_role)
        if not hunt:
            return False
        cursor = self.db.get_cursor()
        cursor.execute("DELETE FROM saved_hunts WHERE hunt_id = ?", (hunt_id,))
        self.db.conn.commit()
        return True

    # ------------------------------------------------------------------
    # Promote hunt result → alert reference
    # ------------------------------------------------------------------

    def promote_to_alert_reference(self, event_id: str, analyst: str,
                                   case_id: str = "", note: str = "") -> dict:
        """
        Analyst explicitly promotes a hunt result to an alert reference.
        Does NOT auto-create a detection rule.
        Returns a reference record for case/alert linking.
        """
        ref_id = f"HUNTREF-{uuid.uuid4().hex[:8].upper()}"
        now_str = datetime.now().isoformat()

        # Verify event exists
        cursor = self.db.get_cursor()
        cursor.execute("SELECT * FROM events WHERE event_id = ?", (event_id,))
        event_row = cursor.fetchone()
        event = dict(event_row) if event_row else {}

        self.audit.log(
            username=analyst,
            role="analyst",
            action="HUNT_RESULT_PROMOTED",
            target_type="hunt_ref",
            target_id=ref_id,
            new_value={
                "event_id": event_id,
                "case_id": case_id,
                "analyst": analyst,
                "note": note,
            },
        )

        return {
            "ref_id": ref_id,
            "event_id": event_id,
            "case_id": case_id,
            "promoted_by": analyst,
            "promoted_at": now_str,
            "note": note,
            "event_summary": {
                "hostname": event.get("hostname"),
                "event_type": event.get("event_type"),
                "timestamp": event.get("timestamp"),
                "source_ip": event.get("source_ip"),
            },
        }
