import json
from datetime import datetime
from src.database import Database

class AuditLogger:
    def __init__(self, db: Database = None):
        self.db = db if db else Database()

    def log(self, username: str, role: str, action: str, target_type: str, target_id: str, old_value=None, new_value=None, ip_address: str = "127.0.0.1", status: str = "SUCCESS"):
        cursor = self.db.get_cursor()
        now_str = datetime.now().isoformat()
        cursor.execute('''
            INSERT INTO audit_logs 
            (timestamp, username, role, action, target_type, target_id, old_value, new_value, ip_address, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            now_str,
            username,
            role,
            action,
            target_type,
            target_id,
            json.dumps(old_value) if old_value is not None else "",
            json.dumps(new_value) if new_value is not None else "",
            ip_address,
            status
        ))
        self.db.conn.commit()

    def get_logs(self, limit=100):
        cursor = self.db.get_cursor()
        cursor.execute("SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT ?", (limit,))
        rows = cursor.fetchall()
        return [dict(r) for r in rows]
