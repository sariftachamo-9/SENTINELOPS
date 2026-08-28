"""
SOC Lab — Telemetry Storage Abstraction (Phase 3)
=================================================
Provides abstract StorageBackend protocol and concrete SQLiteEventStore implementation.

Separates Application Data from Security Telemetry:
  - Security Telemetry resides in `telemetry_events` table (or external search engine in Phase 4+).
  - Application data (users, alerts, incidents, audit logs) remains in core DB tables.

Enables future migration to PostgreSQL / OpenSearch / Elasticsearch without changing higher-level code.
"""

from __future__ import annotations

import json
import sqlite3
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Tuple

from src.telemetry.schema import NormalizedEvent


class StorageBackend(ABC):
    """Abstract interface for security telemetry storage."""

    @abstractmethod
    def store_event(self, event: NormalizedEvent) -> bool:
        """Store a single normalized event."""

    @abstractmethod
    def store_batch(self, events: List[NormalizedEvent]) -> Tuple[int, int]:
        """Store a batch of normalized events. Returns (success_count, failure_count)."""

    @abstractmethod
    def get_event_by_id(self, event_id: str) -> Optional[NormalizedEvent]:
        """Retrieve a single normalized event by ID."""

    @abstractmethod
    def query_events(
        self,
        filters: Dict[str, Any],
        limit: int = 50,
        offset: int = 0
    ) -> Tuple[List[NormalizedEvent], int]:
        """Query events matching filters. Returns (list_of_events, total_count)."""

    @abstractmethod
    def get_timeline(
        self,
        entity_type: str,
        entity_value: str,
        limit: int = 100
    ) -> List[NormalizedEvent]:
        """Retrieve chronological timeline for host, user, IP, incident, or alert."""

    @abstractmethod
    def count_events(self, filters: Optional[Dict[str, Any]] = None) -> int:
        """Count total events matching optional filters."""


class SQLiteEventStore(StorageBackend):
    """
    SQLite implementation of telemetry storage backend.
    Uses `telemetry_events` table in `soc_data.db`.
    """

    def __init__(self, db_path: str = "soc_data.db"):
        self.db_path = db_path
        self.init_table()

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def init_table(self):
        """Create `telemetry_events` table if not existing."""
        with self._get_conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS telemetry_events (
                    event_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    ingestion_timestamp TEXT NOT NULL,
                    source_type TEXT NOT NULL,
                    source_product TEXT,
                    source_sensor TEXT,
                    environment TEXT NOT NULL DEFAULT 'lab',
                    hostname TEXT,
                    asset_id TEXT,
                    fqdn TEXT,
                    source_ip TEXT,
                    destination_ip TEXT,
                    source_port INTEGER,
                    destination_port INTEGER,
                    protocol TEXT,
                    network_direction TEXT,
                    bytes_sent INTEGER,
                    bytes_received INTEGER,
                    username TEXT,
                    domain TEXT,
                    user_id TEXT,
                    process_name TEXT,
                    process_id INTEGER,
                    parent_process TEXT,
                    parent_process_id INTEGER,
                    command_line TEXT,
                    executable_hash TEXT,
                    event_type TEXT,
                    event_code TEXT,
                    severity TEXT NOT NULL DEFAULT 'low',
                    action TEXT,
                    outcome TEXT,
                    message TEXT,
                    risk_score INTEGER DEFAULT 0,
                    correlation_id TEXT,
                    session_id TEXT,
                    tags TEXT,
                    raw_event TEXT,
                    content_hash TEXT,
                    occurrence_count INTEGER DEFAULT 1,
                    first_seen TEXT,
                    last_seen TEXT,
                    processed INTEGER DEFAULT 0,
                    simulation INTEGER DEFAULT 0,
                    source_mode TEXT DEFAULT 'live'
                )
            """)
            # Migration check: Ensure source_mode column exists in pre-existing tables
            cursor = conn.cursor()
            cursor.execute("PRAGMA table_info(telemetry_events)")
            cols = [col[1] for col in cursor.fetchall()]
            if "source_mode" not in cols:
                try:
                    conn.execute("ALTER TABLE telemetry_events ADD COLUMN source_mode TEXT DEFAULT 'live'")
                except Exception as ex:
                    print(f"[SQLiteEventStore] Migration notice: {ex}")

            # Create indexes for search performance
            conn.execute("CREATE INDEX IF NOT EXISTS idx_telemetry_ts ON telemetry_events(timestamp DESC)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_telemetry_src_ip ON telemetry_events(source_ip)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_telemetry_dst_ip ON telemetry_events(destination_ip)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_telemetry_host ON telemetry_events(hostname)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_telemetry_user ON telemetry_events(username)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_telemetry_type ON telemetry_events(event_type)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_telemetry_source_type ON telemetry_events(source_type)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_telemetry_severity ON telemetry_events(severity)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_telemetry_hash ON telemetry_events(content_hash)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_telemetry_source_mode ON telemetry_events(source_mode)")
            conn.commit()

    def store_event(self, event: NormalizedEvent) -> bool:
        sql = """
            INSERT INTO telemetry_events (
                event_id, timestamp, ingestion_timestamp, source_type, source_product,
                source_sensor, environment, hostname, asset_id, fqdn, source_ip,
                destination_ip, source_port, destination_port, protocol, network_direction,
                bytes_sent, bytes_received, username, domain, user_id, process_name,
                process_id, parent_process, parent_process_id, command_line, executable_hash,
                event_type, event_code, severity, action, outcome, message, risk_score,
                correlation_id, session_id, tags, raw_event, content_hash, occurrence_count,
                first_seen, last_seen, processed, simulation, source_mode
            ) VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
            ON CONFLICT(event_id) DO UPDATE SET
                occurrence_count = excluded.occurrence_count,
                last_seen = excluded.last_seen
        """
        params = (
            event.event_id, event.timestamp, event.ingestion_timestamp, event.source_type,
            event.source_product, event.source_sensor, event.environment, event.hostname,
            event.asset_id, event.fqdn, event.source_ip, event.destination_ip,
            event.source_port, event.destination_port, event.protocol, event.network_direction,
            event.bytes_sent, event.bytes_received, event.username, event.domain,
            event.user_id, event.process_name, event.process_id, event.parent_process,
            event.parent_process_id, event.command_line, event.executable_hash,
            event.event_type, event.event_code, event.severity, event.action, event.outcome,
            event.message, event.risk_score, event.correlation_id, event.session_id,
            json.dumps(event.tags or []), json.dumps(event.raw_event or {}),
            event.content_hash, event.occurrence_count, event.first_seen, event.last_seen,
            1 if event.processed else 0, 1 if event.simulation else 0,
            event.source_mode or "live"
        )
        try:
            with self._get_conn() as conn:
                conn.execute(sql, params)
                conn.commit()
            return True
        except Exception as e:
            print(f"[SQLiteEventStore] Error storing event {event.event_id}: {e}")
            return False

    def store_batch(self, events: List[NormalizedEvent]) -> Tuple[int, int]:
        success = 0
        failures = 0
        for ev in events:
            if self.store_event(ev):
                success += 1
            else:
                failures += 1
        return success, failures

    def get_event_by_id(self, event_id: str) -> Optional[NormalizedEvent]:
        with self._get_conn() as conn:
            cur = conn.cursor()
            cur.execute("SELECT * FROM telemetry_events WHERE event_id = ?", (event_id,))
            row = cur.fetchone()
            if not row:
                return None
            return self._row_to_event(dict(row))

    def query_events(
        self,
        filters: Dict[str, Any],
        limit: int = 50,
        offset: int = 0
    ) -> Tuple[List[NormalizedEvent], int]:
        where_clauses = []
        params = []

        mapping = {
            "source_type": "source_type = ?",
            "hostname": "hostname = ?",
            "source_ip": "source_ip = ?",
            "destination_ip": "destination_ip = ?",
            "username": "username = ?",
            "event_type": "event_type = ?",
            "severity": "severity = ?",
            "environment": "environment = ?",
            "process_name": "process_name = ?",
            "asset_id": "asset_id = ?",
            "correlation_id": "correlation_id = ?",
            "simulation": "simulation = ?",
            "source_mode": "source_mode = ?",
        }

        for key, clause in mapping.items():
            if filters.get(key) is not None:
                val = filters[key]
                if key == "simulation":
                    params.append(1 if val in (True, "true", "1", 1) else 0)
                else:
                    params.append(str(val))
                where_clauses.append(clause)

        if filters.get("time_from"):
            where_clauses.append("timestamp >= ?")
            params.append(str(filters["time_from"]))

        if filters.get("time_to"):
            where_clauses.append("timestamp <= ?")
            params.append(str(filters["time_to"]))

        if filters.get("search_query"):
            where_clauses.append("(message LIKE ? OR raw_event LIKE ? OR process_name LIKE ?)")
            q = f"%{filters['search_query']}%"
            params.extend([q, q, q])

        where_sql = (" WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

        with self._get_conn() as conn:
            cur = conn.cursor()
            # Count query
            cur.execute(f"SELECT COUNT(*) FROM telemetry_events{where_sql}", params)
            total_count = cur.fetchone()[0]

            # Fetch query
            fetch_sql = f"SELECT * FROM telemetry_events{where_sql} ORDER BY timestamp DESC LIMIT ? OFFSET ?"
            cur.execute(fetch_sql, params + [limit, offset])
            rows = cur.fetchall()

            events = [self._row_to_event(dict(r)) for r in rows]
            return events, total_count

    def get_timeline(
        self,
        entity_type: str,
        entity_value: str,
        limit: int = 100
    ) -> List[NormalizedEvent]:
        entity_type = entity_type.lower().strip()
        field_map = {
            "host": "hostname",
            "hostname": "hostname",
            "user": "username",
            "username": "username",
            "ip": "source_ip",
            "source_ip": "source_ip",
            "destination_ip": "destination_ip",
            "asset": "asset_id",
            "asset_id": "asset_id",
            "correlation": "correlation_id",
            "correlation_id": "correlation_id",
        }

        col = field_map.get(entity_type, "hostname")
        sql = f"SELECT * FROM telemetry_events WHERE {col} = ? OR (source_ip = ? AND ? = 'ip') ORDER BY timestamp ASC LIMIT ?"
        with self._get_conn() as conn:
            cur = conn.cursor()
            cur.execute(sql, (entity_value, entity_value, entity_type, limit))
            rows = cur.fetchall()
            return [self._row_to_event(dict(r)) for r in rows]

    def count_events(self, filters: Optional[Dict[str, Any]] = None) -> int:
        filters = filters or {}
        _, total = self.query_events(filters, limit=1)
        return total

    def _row_to_event(self, row: dict) -> NormalizedEvent:
        if isinstance(row.get("tags"), str):
            try: row["tags"] = json.loads(row["tags"])
            except: row["tags"] = []
        if isinstance(row.get("raw_event"), str):
            try: row["raw_event"] = json.loads(row["raw_event"])
            except: row["raw_event"] = {}
        row["processed"] = bool(row.get("processed"))
        row["simulation"] = bool(row.get("simulation"))
        return NormalizedEvent(**row)
