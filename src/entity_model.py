"""
Phase 6 — Entity Model
Manages entities (USER/HOST/IP/DOMAIN/PROCESS/FILE/IOC/ALERT/INCIDENT/CASE)
and their relationships. All graph data is backed by real DB records.
"""
import json
import uuid
from datetime import datetime
from typing import Optional, List, Dict, Any
from src.database import Database

VALID_ENTITY_TYPES = {
    "USER", "HOST", "IP", "DOMAIN", "PROCESS",
    "FILE", "IOC", "ALERT", "INCIDENT", "CASE"
}


class EntityManager:
    def __init__(self, db: Database = None):
        self.db = db if db else Database()

    # ------------------------------------------------------------------
    # Entity CRUD
    # ------------------------------------------------------------------

    def upsert_entity(self, entity_type: str, value: str, metadata: Dict[str, Any] = None) -> dict:
        if entity_type not in VALID_ENTITY_TYPES:
            raise ValueError(f"Invalid entity_type '{entity_type}'")
        if not value:
            raise ValueError("Entity value cannot be empty")

        now_str = datetime.now().isoformat()
        metadata_json = json.dumps(metadata or {})
        cursor = self.db.get_cursor()

        # Check existing
        cursor.execute(
            "SELECT entity_id, first_seen FROM entities WHERE entity_type = ? AND value = ?",
            (entity_type, value),
        )
        row = cursor.fetchone()
        if row:
            cursor.execute(
                "UPDATE entities SET last_seen = ?, metadata = ? WHERE entity_id = ?",
                (now_str, metadata_json, row["entity_id"]),
            )
            self.db.conn.commit()
            return self.get_entity(row["entity_id"])
        else:
            entity_id = f"ENT-{uuid.uuid4().hex[:12].upper()}"
            cursor.execute(
                "INSERT INTO entities (entity_id, entity_type, value, first_seen, last_seen, metadata) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (entity_id, entity_type, value, now_str, now_str, metadata_json),
            )
            self.db.conn.commit()
            return self.get_entity(entity_id)

    def get_entity(self, entity_id: str) -> Optional[dict]:
        cursor = self.db.get_cursor()
        cursor.execute("SELECT * FROM entities WHERE entity_id = ?", (entity_id,))
        row = cursor.fetchone()
        if not row:
            return None
        d = dict(row)
        try:
            d["metadata"] = json.loads(d.get("metadata") or "{}")
        except Exception:
            d["metadata"] = {}
        return d

    def get_entity_by_value(self, entity_type: str, value: str) -> Optional[dict]:
        cursor = self.db.get_cursor()
        cursor.execute(
            "SELECT * FROM entities WHERE entity_type = ? AND value = ?",
            (entity_type, value),
        )
        row = cursor.fetchone()
        if not row:
            return None
        d = dict(row)
        try:
            d["metadata"] = json.loads(d.get("metadata") or "{}")
        except Exception:
            d["metadata"] = {}
        return d

    def query_entities(self, entity_type: str = None, value_pattern: str = None,
                       limit: int = 50, offset: int = 0) -> List[dict]:
        cursor = self.db.get_cursor()
        conditions, params = [], []
        if entity_type:
            conditions.append("entity_type = ?")
            params.append(entity_type)
        if value_pattern:
            conditions.append("value LIKE ?")
            params.append(f"%{value_pattern}%")
        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        params.extend([limit, offset])
        cursor.execute(
            f"SELECT * FROM entities {where} ORDER BY last_seen DESC LIMIT ? OFFSET ?",
            params,
        )
        results = []
        for row in cursor.fetchall():
            d = dict(row)
            try:
                d["metadata"] = json.loads(d.get("metadata") or "{}")
            except Exception:
                d["metadata"] = {}
            results.append(d)
        return results

    # ------------------------------------------------------------------
    # Relationships
    # ------------------------------------------------------------------

    def add_relationship(self, source_entity_id: str, target_entity_id: str,
                         rel_type: str, confidence: int = 80,
                         case_id: str = "") -> dict:
        rel_id = f"REL-{uuid.uuid4().hex[:10].upper()}"
        now_str = datetime.now().isoformat()
        cursor = self.db.get_cursor()
        cursor.execute(
            "INSERT INTO entity_relationships "
            "(rel_id, source_entity_id, target_entity_id, relationship_type, confidence, first_seen, case_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (rel_id, source_entity_id, target_entity_id, rel_type, confidence, now_str, case_id or ""),
        )
        self.db.conn.commit()
        return {
            "rel_id": rel_id,
            "source_entity_id": source_entity_id,
            "target_entity_id": target_entity_id,
            "relationship_type": rel_type,
            "confidence": confidence,
            "first_seen": now_str,
            "case_id": case_id or "",
        }

    def get_entity_relationships(self, entity_id: str) -> List[dict]:
        cursor = self.db.get_cursor()
        cursor.execute(
            "SELECT * FROM entity_relationships "
            "WHERE source_entity_id = ? OR target_entity_id = ? "
            "ORDER BY first_seen DESC",
            (entity_id, entity_id),
        )
        return [dict(r) for r in cursor.fetchall()]

    def get_entity_graph(self, case_id: str = None, limit: int = 200) -> dict:
        """Return nodes + edges for the entity graph, optionally scoped to a case."""
        cursor = self.db.get_cursor()

        if case_id:
            cursor.execute(
                "SELECT * FROM entity_relationships WHERE case_id = ? LIMIT ?",
                (case_id, limit),
            )
        else:
            cursor.execute(
                "SELECT * FROM entity_relationships ORDER BY first_seen DESC LIMIT ?",
                (limit,),
            )
        rels = [dict(r) for r in cursor.fetchall()]

        # Collect unique entity IDs from edges
        entity_ids = set()
        for r in rels:
            entity_ids.add(r["source_entity_id"])
            entity_ids.add(r["target_entity_id"])

        nodes = []
        for eid in entity_ids:
            ent = self.get_entity(eid)
            if ent:
                nodes.append({
                    "id": ent["entity_id"],
                    "label": ent["value"],
                    "type": ent["entity_type"],
                    "first_seen": ent["first_seen"],
                    "last_seen": ent["last_seen"],
                })

        edges = [
            {
                "id": r["rel_id"],
                "source": r["source_entity_id"],
                "target": r["target_entity_id"],
                "relationship": r["relationship_type"],
                "confidence": r["confidence"],
            }
            for r in rels
        ]

        return {
            "nodes": nodes,
            "edges": edges,
            "total_nodes": len(nodes),
            "total_edges": len(edges),
        }

    # ------------------------------------------------------------------
    # Auto-extraction from events/alerts
    # ------------------------------------------------------------------

    def extract_entities_from_event(self, event: dict) -> List[dict]:
        """Parse a normalized event and upsert entities + relationships."""
        created = []

        hostname = event.get("hostname")
        source_ip = event.get("source_ip")
        destination_ip = event.get("destination_ip")
        username = event.get("username")
        process_name = event.get("process_name")

        host_ent = self.upsert_entity("HOST", hostname) if hostname else None
        src_ip_ent = self.upsert_entity("IP", source_ip) if source_ip else None
        dst_ip_ent = self.upsert_entity("IP", destination_ip) if destination_ip else None
        user_ent = self.upsert_entity("USER", username) if username else None
        proc_ent = self.upsert_entity("PROCESS", process_name) if process_name else None

        for e in [host_ent, src_ip_ent, dst_ip_ent, user_ent, proc_ent]:
            if e:
                created.append(e)

        # Relationships
        if user_ent and host_ent:
            self.add_relationship(user_ent["entity_id"], host_ent["entity_id"], "logged_into")
        if host_ent and src_ip_ent:
            self.add_relationship(host_ent["entity_id"], src_ip_ent["entity_id"], "has_source_ip")
        if host_ent and dst_ip_ent:
            self.add_relationship(host_ent["entity_id"], dst_ip_ent["entity_id"], "connected_to")
        if host_ent and proc_ent:
            self.add_relationship(host_ent["entity_id"], proc_ent["entity_id"], "ran_process")

        return created

    def extract_entities_from_alert(self, alert: dict, case_id: str = "") -> List[dict]:
        """Parse an alert and upsert entities + relationships, scoped to case if given."""
        created = []

        asset = alert.get("affected_asset") or alert.get("source")
        user = alert.get("affected_user")
        dst = alert.get("destination")
        rule = alert.get("detection_rule")
        alert_id = alert.get("id")

        host_ent = self.upsert_entity("HOST", asset) if asset else None
        user_ent = self.upsert_entity("USER", user) if user else None
        dst_ent = self.upsert_entity("IP", dst) if dst else None
        ioc_ent = self.upsert_entity("IOC", rule) if rule else None
        alert_ent = self.upsert_entity("ALERT", alert_id) if alert_id else None

        for e in [host_ent, user_ent, dst_ent, ioc_ent, alert_ent]:
            if e:
                created.append(e)

        if user_ent and host_ent:
            self.add_relationship(user_ent["entity_id"], host_ent["entity_id"], "active_on", case_id=case_id)
        if host_ent and dst_ent:
            self.add_relationship(host_ent["entity_id"], dst_ent["entity_id"], "connected_to", case_id=case_id)
        if dst_ent and ioc_ent:
            self.add_relationship(dst_ent["entity_id"], ioc_ent["entity_id"], "matched_ioc", confidence=90, case_id=case_id)
        if host_ent and alert_ent:
            self.add_relationship(host_ent["entity_id"], alert_ent["entity_id"], "generated_alert", case_id=case_id)

        return created
