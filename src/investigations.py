"""
Phase 6 — Investigation Workspace
All entity graph and timeline data is backed by real database records.
No fake/decorative nodes are generated.
"""
import json
from datetime import datetime
from typing import Optional, List, Dict, Any

from src.database import Database
from src.entity_model import EntityManager
from src.evidence import EvidenceManager
from src.case_notes import CaseNotesManager


class InvestigationWorkspace:
    def __init__(self, db: Database = None):
        self.db = db if db else Database()
        self.entity_mgr = EntityManager(db=self.db)
        self.evidence_mgr = EvidenceManager(db=self.db)
        self.notes_mgr = CaseNotesManager(db=self.db)

    # ------------------------------------------------------------------
    # Full workspace aggregation
    # ------------------------------------------------------------------

    def get_case_workspace(self, case_id: str) -> dict:
        """
        Aggregate all investigation data for a case into one response.
        Includes: case info, linked alerts, linked incidents, entities,
        MITRE techniques, timeline, notes, evidence, audit history.
        """
        from src.case_management import CaseManager
        case_mgr = CaseManager(db=self.db)

        case = case_mgr.get_case(case_id)
        if not case:
            return {}

        alerts = case_mgr.get_case_alerts(case_id)
        incidents = case_mgr.get_case_incidents(case_id)
        evidence = self.evidence_mgr.list_case_evidence(case_id)
        notes = self.notes_mgr.list_case_notes(case_id)
        entity_graph = self.get_entity_graph(case_id=case_id)
        timeline = self.get_investigation_timeline(case_id=case_id)

        # Extract unique affected assets, users, IPs, processes, IOCs, MITRE techniques
        assets, users, source_ips, dest_ips, processes, iocs, mitre = (
            set(), set(), set(), set(), set(), set(), set()
        )
        for a in alerts:
            if a.get("affected_asset"):
                assets.add(a["affected_asset"])
            if a.get("affected_user"):
                users.add(a["affected_user"])
            if a.get("source"):
                source_ips.add(a["source"])
            if a.get("destination"):
                dest_ips.add(a["destination"])
            if a.get("mitre_technique"):
                mitre.add(f"{a.get('mitre_tactic','?')}: {a['mitre_technique']}")
            for ind in (a.get("indicators") or []):
                iocs.add(str(ind))

        # Enrich from entity graph nodes
        for node in entity_graph.get("nodes", []):
            if node["type"] == "HOST":
                assets.add(node["label"])
            elif node["type"] == "USER":
                users.add(node["label"])
            elif node["type"] == "IP":
                source_ips.add(node["label"])
            elif node["type"] == "PROCESS":
                processes.add(node["label"])
            elif node["type"] == "IOC":
                iocs.add(node["label"])

        # Audit history for this case
        cursor = self.db.get_cursor()
        cursor.execute(
            "SELECT * FROM audit_logs WHERE target_id = ? ORDER BY timestamp DESC LIMIT 50",
            (case_id,),
        )
        audit_history = [dict(r) for r in cursor.fetchall()]

        return {
            "case": case,
            "alerts": alerts,
            "incidents": incidents,
            "affected_assets": sorted(assets),
            "affected_users": sorted(users),
            "source_ips": sorted(source_ips),
            "destination_ips": sorted(dest_ips),
            "processes": sorted(processes),
            "iocs": sorted(iocs),
            "mitre_techniques": sorted(mitre),
            "entity_graph": entity_graph,
            "timeline": timeline,
            "evidence": evidence,
            "notes": notes,
            "audit_history": audit_history,
        }

    # ------------------------------------------------------------------
    # Entity graph (real data only)
    # ------------------------------------------------------------------

    def get_entity_graph(self, case_id: str = None, limit: int = 200) -> dict:
        """
        Returns nodes + edges from the entity_relationships table.
        Scoped to a case if case_id provided.
        All nodes are real stored entities — no fake/decorative entries.
        """
        return self.entity_mgr.get_entity_graph(case_id=case_id, limit=limit)

    # ------------------------------------------------------------------
    # Unified investigation timeline
    # ------------------------------------------------------------------

    def get_investigation_timeline(
        self,
        case_id: str = None,
        time_from: str = None,
        time_to: str = None,
        hostname: str = None,
        username: str = None,
        source_ip: str = None,
        event_type: str = None,
        severity: str = None,
        limit: int = 200,
    ) -> List[dict]:
        """
        Unified chronological timeline combining:
        - Telemetry events (from linked alerts' triggering_event_ids)
        - Alert records
        - Case status changes (from audit_logs)
        - Evidence additions
        Filtered and sorted by timestamp.
        """
        timeline_items: List[dict] = []

        # --- 1. Alerts linked to case ---
        if case_id:
            from src.case_management import CaseManager
            case_mgr = CaseManager(db=self.db)
            alerts = case_mgr.get_case_alerts(case_id)
        else:
            alerts = self.db.get_alerts(limit=100)

        for alert in alerts:
            if severity and alert.get("severity", "").lower() != severity.lower():
                continue
            if hostname and alert.get("affected_asset", "").lower() != hostname.lower():
                continue
            if username and alert.get("affected_user", "").lower() != username.lower():
                continue
            if source_ip and alert.get("source", "") != source_ip:
                continue

            ts = alert.get("timestamp", "")
            if time_from and ts < time_from:
                continue
            if time_to and ts > time_to:
                continue

            timeline_items.append({
                "timestamp": ts,
                "type": "ALERT",
                "id": alert.get("id"),
                "title": alert.get("title"),
                "severity": alert.get("severity"),
                "entity": alert.get("affected_asset") or alert.get("source"),
                "description": alert.get("description"),
                "mitre_tactic": alert.get("mitre_tactic"),
                "mitre_technique": alert.get("mitre_technique"),
                "source_mode": alert.get("source_mode", "live"),
            })

            # --- 2. Triggering events for this alert ---
            evt_ids = alert.get("triggering_event_ids", [])
            if evt_ids:
                cursor = self.db.get_cursor()
                placeholders = ",".join("?" for _ in evt_ids)
                cursor.execute(
                    f"SELECT * FROM events WHERE event_id IN ({placeholders}) ORDER BY timestamp ASC",
                    evt_ids,
                )
                for erow in cursor.fetchall():
                    ev = dict(erow)
                    ev_ts = ev.get("timestamp", "")
                    if time_from and ev_ts < time_from:
                        continue
                    if time_to and ev_ts > time_to:
                        continue
                    if event_type and ev.get("event_type", "").lower() != event_type.lower():
                        continue

                    timeline_items.append({
                        "timestamp": ev_ts,
                        "type": "EVENT",
                        "id": ev.get("event_id"),
                        "title": ev.get("event_type"),
                        "severity": ev.get("severity"),
                        "entity": ev.get("hostname") or ev.get("source_ip"),
                        "description": f"{ev.get('event_type')} on {ev.get('hostname')}",
                        "source_ip": ev.get("source_ip"),
                        "username": ev.get("username"),
                        "process": ev.get("process_name"),
                        "source_mode": ev.get("environment", "live"),
                    })

        # --- 3. Case audit events (status changes, assignments, etc.) ---
        if case_id:
            cursor = self.db.get_cursor()
            cursor.execute(
                "SELECT * FROM audit_logs WHERE target_id = ? AND action LIKE 'CASE_%' "
                "ORDER BY timestamp ASC LIMIT 100",
                (case_id,),
            )
            for arow in cursor.fetchall():
                a = dict(arow)
                ts = a.get("timestamp", "")
                if time_from and ts < time_from:
                    continue
                if time_to and ts > time_to:
                    continue
                timeline_items.append({
                    "timestamp": ts,
                    "type": "CASE_EVENT",
                    "id": f"AUDIT-{a.get('id')}",
                    "title": a.get("action", ""),
                    "severity": "info",
                    "entity": a.get("username"),
                    "description": f"{a.get('action')} by {a.get('username')}",
                })

            # --- 4. Evidence additions ---
            evidence_items = self.evidence_mgr.list_case_evidence(case_id)
            for ev_item in evidence_items:
                ts = ev_item.get("timestamp", "")
                if time_from and ts < time_from:
                    continue
                if time_to and ts > time_to:
                    continue
                timeline_items.append({
                    "timestamp": ts,
                    "type": "EVIDENCE",
                    "id": ev_item.get("evidence_id"),
                    "title": f"Evidence: {ev_item.get('type')}",
                    "severity": "info",
                    "entity": ev_item.get("added_by"),
                    "description": ev_item.get("description", ""),
                })

        # Sort chronologically and cap
        timeline_items.sort(key=lambda x: x.get("timestamp") or "")
        return timeline_items[:limit]

    # ------------------------------------------------------------------
    # MITRE coverage for a case
    # ------------------------------------------------------------------

    def get_case_mitre_coverage(self, case_id: str) -> dict:
        from src.case_management import CaseManager
        case_mgr = CaseManager(db=self.db)
        alerts = case_mgr.get_case_alerts(case_id)

        techniques = {}
        for a in alerts:
            tactic = a.get("mitre_tactic", "Unknown")
            technique = a.get("mitre_technique", "")
            rule = a.get("detection_rule", "")
            if technique:
                key = f"{tactic}:{technique}"
                if key not in techniques:
                    techniques[key] = {
                        "tactic": tactic,
                        "technique": technique,
                        "rule": rule,
                        "alert_count": 0,
                    }
                techniques[key]["alert_count"] += 1

        return {"techniques": list(techniques.values()), "total": len(techniques)}
