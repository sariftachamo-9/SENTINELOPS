"""
Phase 6 — Evidence Management
Provides add/get/list/update for case evidence with an append-only chain-of-custody trail.
No arbitrary files are stored; only metadata, references, and hashes.
"""
import html
import json
import uuid
from datetime import datetime
from typing import Optional, List, Dict, Any

from src.database import Database
from src.audit import AuditLogger

VALID_EVIDENCE_TYPES = {
    "telemetry_event",
    "alert",
    "screenshot_meta",
    "ioc",
    "analyst_note",
    "external_ref",
    "file_meta",
}


class EvidenceManager:
    def __init__(self, db: Database = None):
        self.db = db if db else Database()
        self.audit = AuditLogger(db=self.db)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _sanitize(self, text: str) -> str:
        """HTML-escape analyst-provided free-text to prevent stored XSS."""
        if not text:
            return ""
        return html.escape(str(text))

    def _row_to_dict(self, row) -> dict:
        d = dict(row)
        for field in ["chain_of_custody"]:
            try:
                d[field] = json.loads(d[field]) if d.get(field) else []
            except Exception:
                d[field] = []
        return d

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def add_evidence(
        self,
        case_id: str,
        evidence_type: str,
        source: str,
        description: str,
        added_by: str,
        hash_value: str = "",
        content_ref: str = "",
    ) -> dict:
        """
        Add evidence to a case. Returns the created evidence record.
        Evidence type must be in VALID_EVIDENCE_TYPES.
        """
        if evidence_type not in VALID_EVIDENCE_TYPES:
            raise ValueError(
                f"Invalid evidence type '{evidence_type}'. "
                f"Must be one of: {', '.join(sorted(VALID_EVIDENCE_TYPES))}"
            )

        evidence_id = f"EV-{uuid.uuid4().hex[:12].upper()}"
        now_str = datetime.now().isoformat()
        description_safe = self._sanitize(description)
        source_safe = self._sanitize(source)

        initial_custody = [
            {
                "action": "ADDED",
                "by": added_by,
                "at": now_str,
                "note": "Evidence item created",
            }
        ]

        cursor = self.db.get_cursor()
        cursor.execute(
            """
            INSERT INTO evidence
            (evidence_id, case_id, type, source, timestamp, added_by,
             description, hash, content_ref, chain_of_custody)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                evidence_id,
                case_id,
                evidence_type,
                source_safe,
                now_str,
                added_by,
                description_safe,
                hash_value or "",
                content_ref or "",
                json.dumps(initial_custody),
            ),
        )
        self.db.conn.commit()

        self.audit.log(
            username=added_by,
            role="analyst",
            action="EVIDENCE_ADDED",
            target_type="evidence",
            target_id=evidence_id,
            new_value={
                "case_id": case_id,
                "type": evidence_type,
                "source": source_safe,
            },
        )

        return self.get_evidence(evidence_id, case_id)

    def get_evidence(self, evidence_id: str, case_id: str) -> Optional[dict]:
        """
        Retrieve a single evidence item.
        IDOR protection: case_id must match the stored record.
        """
        cursor = self.db.get_cursor()
        cursor.execute(
            "SELECT * FROM evidence WHERE evidence_id = ? AND case_id = ?",
            (evidence_id, case_id),
        )
        row = cursor.fetchone()
        if not row:
            return None
        return self._row_to_dict(row)

    def list_case_evidence(self, case_id: str) -> List[dict]:
        """Return all evidence items for a case, ordered by timestamp."""
        cursor = self.db.get_cursor()
        cursor.execute(
            "SELECT * FROM evidence WHERE case_id = ? ORDER BY timestamp ASC",
            (case_id,),
        )
        return [self._row_to_dict(r) for r in cursor.fetchall()]

    def update_evidence_metadata(
        self,
        evidence_id: str,
        case_id: str,
        updates: Dict[str, Any],
        updated_by: str,
        reason: str = "",
    ) -> dict:
        """
        Update mutable metadata fields (description, hash, content_ref).
        Appends an entry to chain_of_custody — never removes prior entries.
        Each CoC entry embeds previous_value and new_value per field (Req #3).
        """
        ev = self.get_evidence(evidence_id, case_id)
        if not ev:
            raise ValueError(f"Evidence '{evidence_id}' not found in case '{case_id}'")

        if not reason or not reason.strip():
            raise ValueError("A reason is required when updating evidence metadata")

        now_str = datetime.now().isoformat()
        allowed_fields = {"description", "hash", "content_ref"}
        sanitized_updates: Dict[str, str] = {}

        for field, value in updates.items():
            if field not in allowed_fields:
                raise ValueError(f"Field '{field}' is not modifiable")
            sanitized_updates[field] = self._sanitize(str(value)) if field == "description" else str(value)

        if not sanitized_updates:
            raise ValueError("No valid fields to update")

        # Build change record with previous and new values embedded in the CoC entry
        changes = {
            field: {
                "previous_value": ev.get(field, ""),
                "new_value": new_val,
            }
            for field, new_val in sanitized_updates.items()
        }

        # Append chain of custody entry
        custody_trail: list = ev.get("chain_of_custody", [])
        custody_trail.append(
            {
                "action": "METADATA_UPDATED",
                "by": updated_by,
                "at": now_str,
                "reason": self._sanitize(reason),
                "changes": changes,
            }
        )

        # Build SET clause safely — only whitelisted fields
        set_clauses = ", ".join(f"{f} = ?" for f in sanitized_updates)
        values = list(sanitized_updates.values()) + [json.dumps(custody_trail), now_str, evidence_id, case_id]

        cursor = self.db.get_cursor()
        cursor.execute(
            f"UPDATE evidence SET {set_clauses}, chain_of_custody = ?, updated_at = ? "
            f"WHERE evidence_id = ? AND case_id = ?",
            values,
        )
        self.db.conn.commit()

        self.audit.log(
            username=updated_by,
            role="analyst",
            action="EVIDENCE_METADATA_UPDATED",
            target_type="evidence",
            target_id=evidence_id,
            old_value={f: ev.get(f) for f in sanitized_updates},
            new_value=sanitized_updates,
        )

        return self.get_evidence(evidence_id, case_id)
