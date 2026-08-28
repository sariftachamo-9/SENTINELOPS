"""
Phase 6 Hardened — Analyst Case Notes
Content is stored as PLAIN TEXT.
- HTML tags are stripped before storage (never trust HTML from analyst input).
- html.escape() is applied only at render time, not at storage time.
- Max note length: 10,000 characters.
- All creates and updates are audit-logged.
"""
import html
import re
import uuid
from datetime import datetime
from typing import Optional, List
from src.database import Database
from src.audit import AuditLogger

MAX_NOTE_LENGTH = 10_000


class CaseNotesManager:
    def __init__(self, db: Database = None):
        self.db = db if db else Database()
        self.audit = AuditLogger(db=self.db)

    def _sanitize(self, text: str) -> str:
        """Strip HTML tags and store as plain text. Do NOT escape — that is for rendering."""
        if not text:
            return ""
        # Remove all HTML/XML tags
        stripped = re.sub(r'<[^>]+>', '', str(text))
        # Collapse extra whitespace, enforce max length
        return stripped.strip()[:MAX_NOTE_LENGTH]

    def _render_html(self, text: str) -> str:
        """Escape plain-text for safe embedding in HTML responses."""
        return html.escape(text) if text else ""

    def add_note(self, case_id: str, author: str, content: str) -> dict:
        note_id = f"NOTE-{uuid.uuid4().hex[:10].upper()}"
        now_str = datetime.now().isoformat()
        safe_content = self._sanitize(content)
        cursor = self.db.get_cursor()
        cursor.execute(
            "INSERT INTO case_notes (note_id, case_id, author, timestamp, content, updated_at, updated_by) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (note_id, case_id, author, now_str, safe_content, now_str, author),
        )
        self.db.conn.commit()
        self.audit.log(author, "analyst", "CASE_NOTE_ADDED", "case_note", note_id,
                       new_value={"case_id": case_id, "note_id": note_id})
        return self.get_note(note_id, case_id)

    def get_note(self, note_id: str, case_id: str) -> Optional[dict]:
        cursor = self.db.get_cursor()
        cursor.execute(
            "SELECT * FROM case_notes WHERE note_id = ? AND case_id = ?",
            (note_id, case_id),
        )
        row = cursor.fetchone()
        return dict(row) if row else None

    def list_case_notes(self, case_id: str) -> List[dict]:
        cursor = self.db.get_cursor()
        cursor.execute(
            "SELECT * FROM case_notes WHERE case_id = ? ORDER BY timestamp ASC",
            (case_id,),
        )
        return [dict(r) for r in cursor.fetchall()]

    def update_note(self, note_id: str, case_id: str, content: str, updated_by: str) -> dict:
        existing = self.get_note(note_id, case_id)
        if not existing:
            raise ValueError(f"Note '{note_id}' not found in case '{case_id}'")
        now_str = datetime.now().isoformat()
        safe_content = self._sanitize(content)
        cursor = self.db.get_cursor()
        cursor.execute(
            "UPDATE case_notes SET content = ?, updated_at = ?, updated_by = ? "
            "WHERE note_id = ? AND case_id = ?",
            (safe_content, now_str, updated_by, note_id, case_id),
        )
        self.db.conn.commit()
        self.audit.log(updated_by, "analyst", "CASE_NOTE_UPDATED", "case_note", note_id,
                       old_value={"content": existing.get("content", "")},
                       new_value={"content": safe_content})
        return self.get_note(note_id, case_id)
