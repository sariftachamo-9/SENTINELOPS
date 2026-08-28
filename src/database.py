import sqlite3
import json
import os
from datetime import datetime

class Database:
    def __init__(self, db_path=None):
        if db_path is None:
            # Default to absolute path in workspace root
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            db_path = os.path.join(base_dir, "soc_data.db")
        
        self.db_path = db_path
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False, timeout=30.0)
        self.conn.row_factory = sqlite3.Row
        try:
            self.conn.execute("PRAGMA journal_mode=WAL;")
        except Exception:
            pass
        self.create_tables()

    def get_cursor(self):
        return self.conn.cursor()

    def create_tables(self):
        cursor = self.conn.cursor()
        
        # 1. Normalized Events Table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS events (
                event_id TEXT PRIMARY KEY,
                timestamp TEXT,
                source_type TEXT,
                source_product TEXT,
                hostname TEXT,
                source_ip TEXT,
                destination_ip TEXT,
                source_port INTEGER DEFAULT 0,
                destination_port INTEGER DEFAULT 0,
                username TEXT,
                process_name TEXT,
                event_type TEXT,
                severity TEXT DEFAULT 'medium',
                risk_score INTEGER DEFAULT 0,
                raw_event TEXT,
                normalized_event TEXT,
                environment TEXT DEFAULT 'lab'
            )
        ''')
        
        # 2. Alerts Table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id TEXT PRIMARY KEY,
                title TEXT,
                severity TEXT,
                description TEXT,
                source TEXT,
                destination TEXT,
                timestamp TEXT,
                indicators TEXT,
                status TEXT DEFAULT 'NEW',
                confidence INTEGER DEFAULT 80,
                risk_score INTEGER DEFAULT 50,
                affected_asset TEXT,
                affected_user TEXT,
                mitre_tactic TEXT,
                mitre_technique TEXT,
                detection_rule TEXT,
                first_seen TEXT,
                last_seen TEXT,
                occurrence_count INTEGER DEFAULT 1,
                assignee TEXT,
                evidence TEXT,
                analyst_notes TEXT,
                processed BOOLEAN DEFAULT 0
            )
        ''')

        # Add missing columns dynamically to existing alerts table if needed
        self._ensure_columns("alerts", {
            "rule_id": "TEXT DEFAULT ''",
            "status": "TEXT DEFAULT 'NEW'",
            "confidence": "INTEGER DEFAULT 80",
            "risk_score": "INTEGER DEFAULT 50",
            "risk_breakdown": "TEXT DEFAULT '{}'",
            "reason": "TEXT DEFAULT ''",
            "source": "TEXT DEFAULT 'system'",
            "destination": "TEXT DEFAULT ''",
            "affected_asset": "TEXT DEFAULT ''",
            "affected_user": "TEXT DEFAULT ''",
            "mitre_tactic": "TEXT DEFAULT ''",
            "mitre_technique": "TEXT DEFAULT ''",
            "detection_rule": "TEXT DEFAULT ''",
            "source_mode": "TEXT DEFAULT 'live'",
            "triggering_event_ids": "TEXT DEFAULT '[]'",
            "first_seen": "TEXT DEFAULT ''",
            "last_seen": "TEXT DEFAULT ''",
            "occurrence_count": "INTEGER DEFAULT 1",
            "assignee": "TEXT DEFAULT 'Unassigned'",
            "evidence": "TEXT DEFAULT '[]'",
            "fp_reason": "TEXT DEFAULT ''",
            "fp_analyst": "TEXT DEFAULT ''",
            "fp_timestamp": "TEXT DEFAULT ''",
            "analyst_notes": "TEXT DEFAULT '[]'",
            "processed": "BOOLEAN DEFAULT 0"
        })
        
        # 3. Incidents Table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS incidents (
                id TEXT PRIMARY KEY,
                title TEXT,
                severity TEXT,
                priority TEXT DEFAULT 'P2',
                status TEXT DEFAULT 'open',
                category TEXT DEFAULT 'Security Breach',
                created_at TEXT,
                resolved_at TEXT,
                alert_id TEXT,
                description TEXT,
                mitre_attack TEXT,
                affected_assets TEXT DEFAULT '[]',
                affected_users TEXT DEFAULT '[]',
                related_alerts TEXT DEFAULT '[]',
                evidence TEXT DEFAULT '[]',
                timeline TEXT DEFAULT '[]',
                ioc_list TEXT DEFAULT '[]',
                analysts TEXT DEFAULT '[]',
                tasks TEXT DEFAULT '[]',
                notes TEXT DEFAULT '[]',
                containment TEXT DEFAULT '',
                eradication TEXT DEFAULT '',
                recovery TEXT DEFAULT '',
                root_cause TEXT DEFAULT '',
                lessons_learned TEXT DEFAULT '',
                closure_reason TEXT DEFAULT ''
            )
        ''')

        self._ensure_columns("incidents", {
            "priority": "TEXT DEFAULT 'P2'",
            "category": "TEXT DEFAULT 'Security Incident'",
            "mitre_attack": "TEXT DEFAULT ''",
            "mitre_techniques": "TEXT DEFAULT '[]'",
            "affected_assets": "TEXT DEFAULT '[]'",
            "affected_users": "TEXT DEFAULT '[]'",
            "related_alerts": "TEXT DEFAULT '[]'",
            "evidence": "TEXT DEFAULT '[]'",
            "timeline": "TEXT DEFAULT '[]'",
            "ioc_list": "TEXT DEFAULT '[]'",
            "analysts": "TEXT DEFAULT '[]'",
            "tasks": "TEXT DEFAULT '[]'",
            "notes": "TEXT DEFAULT '[]'",
            "containment": "TEXT DEFAULT ''",
            "eradication": "TEXT DEFAULT ''",
            "recovery": "TEXT DEFAULT ''",
            "root_cause": "TEXT DEFAULT ''",
            "lessons_learned": "TEXT DEFAULT ''",
            "closure_reason": "TEXT DEFAULT ''",
            "assigned_to": "TEXT DEFAULT 'Unassigned'",
            "updated_at": "TEXT DEFAULT ''",
            "version": "INTEGER DEFAULT 1",
        })

        # 4. Cases Table (Phase 6 full schema)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cases (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT DEFAULT '',
                severity TEXT DEFAULT 'medium',
                priority TEXT DEFAULT 'MEDIUM',
                status TEXT DEFAULT 'OPEN',
                assigned_to TEXT DEFAULT 'Unassigned',
                created_by TEXT DEFAULT 'system',
                created_at TEXT,
                updated_at TEXT,
                closed_at TEXT DEFAULT '',
                disposition TEXT DEFAULT 'UNDETERMINED',
                tags TEXT DEFAULT '[]',
                due_date TEXT DEFAULT '',
                lead_investigator TEXT DEFAULT 'Admin',
                investigators TEXT DEFAULT '[]',
                related_incidents TEXT DEFAULT '[]',
                tasks TEXT DEFAULT '[]'
            )
        ''')

        self._ensure_columns("cases", {
            "severity":     "TEXT DEFAULT 'medium'",
            "assigned_to":  "TEXT DEFAULT 'Unassigned'",
            "created_by":   "TEXT DEFAULT 'system'",
            "closed_at":    "TEXT DEFAULT ''",
            "disposition":  "TEXT DEFAULT 'UNDETERMINED'",
            "tags":         "TEXT DEFAULT '[]'",
            "due_date":     "TEXT DEFAULT ''",
            "version":      "INTEGER DEFAULT 1",
        })

        # 4a. Case–Alert junction table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS case_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT NOT NULL,
                alert_id TEXT NOT NULL,
                linked_by TEXT DEFAULT 'system',
                linked_at TEXT,
                UNIQUE(case_id, alert_id)
            )
        ''')

        # 4b. Case–Incident junction table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS case_incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT NOT NULL,
                incident_id TEXT NOT NULL,
                linked_by TEXT DEFAULT 'system',
                linked_at TEXT,
                UNIQUE(case_id, incident_id)
            )
        ''')

        # 4b2. Incident–Alert junction table (Phase 6 hardened)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS incident_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id TEXT NOT NULL,
                alert_id TEXT NOT NULL,
                linked_by TEXT DEFAULT 'system',
                linked_at TEXT,
                UNIQUE(incident_id, alert_id)
            )
        ''')

        # 4b3. Incident–Entity junction table (Phase 6 hardened)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS incident_entities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id TEXT NOT NULL,
                entity_id TEXT NOT NULL,
                linked_by TEXT DEFAULT 'system',
                linked_at TEXT,
                UNIQUE(incident_id, entity_id)
            )
        ''')

        # 4c. Evidence table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS evidence (
                evidence_id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                type TEXT NOT NULL,
                source TEXT DEFAULT '',
                timestamp TEXT,
                added_by TEXT DEFAULT 'system',
                description TEXT DEFAULT '',
                hash TEXT DEFAULT '',
                content_ref TEXT DEFAULT '',
                chain_of_custody TEXT DEFAULT '[]',
                updated_at TEXT DEFAULT ''
            )
        ''')

        # 4d. Case Notes table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS case_notes (
                note_id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                author TEXT DEFAULT 'analyst',
                timestamp TEXT,
                content TEXT DEFAULT '',
                updated_at TEXT DEFAULT '',
                updated_by TEXT DEFAULT ''
            )
        ''')

        # 4e. Entities table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS entities (
                entity_id TEXT PRIMARY KEY,
                entity_type TEXT NOT NULL,
                value TEXT NOT NULL,
                first_seen TEXT,
                last_seen TEXT,
                metadata TEXT DEFAULT '{}'
            )
        ''')

        # 4f. Entity Relationships table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS entity_relationships (
                rel_id TEXT PRIMARY KEY,
                source_entity_id TEXT NOT NULL,
                target_entity_id TEXT NOT NULL,
                relationship_type TEXT DEFAULT 'related_to',
                confidence INTEGER DEFAULT 80,
                first_seen TEXT,
                case_id TEXT DEFAULT ''
            )
        ''')

        # 4g. Saved Hunts table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS saved_hunts (
                hunt_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                query TEXT DEFAULT '{}',
                owner TEXT DEFAULT 'analyst',
                created_at TEXT,
                updated_at TEXT
            )
        ''')

        # 5. Asset Inventory Table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS assets (
                id TEXT PRIMARY KEY,
                hostname TEXT UNIQUE,
                ip TEXT,
                mac TEXT,
                os TEXT,
                role TEXT,
                owner TEXT,
                environment TEXT DEFAULT 'Production',
                criticality TEXT DEFAULT 'Medium',
                location TEXT DEFAULT 'DataCenter-1',
                agent_status TEXT DEFAULT 'ONLINE',
                last_seen TEXT,
                risk_score INTEGER DEFAULT 20,
                tags TEXT DEFAULT '[]'
            )
        ''')

        # 6. Users & Identity Table (RBAC)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE,
                password_hash TEXT,
                email TEXT,
                role TEXT DEFAULT 'SOC Analyst L1',
                permissions TEXT DEFAULT '[]',
                is_active INTEGER DEFAULT 1,
                created_at TEXT,
                last_login TEXT
            )
        ''')

        # 7. Audit Log Table (Append-only)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                username TEXT,
                role TEXT,
                action TEXT,
                target_type TEXT,
                target_id TEXT,
                old_value TEXT,
                new_value TEXT,
                ip_address TEXT,
                status TEXT DEFAULT 'SUCCESS'
            )
        ''')

        # 8. Threat Intelligence Indicators Table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_intel (
                id TEXT PRIMARY KEY,
                indicator TEXT UNIQUE,
                indicator_type TEXT,
                source TEXT,
                confidence INTEGER DEFAULT 80,
                severity TEXT DEFAULT 'high',
                first_seen TEXT,
                last_seen TEXT,
                tags TEXT DEFAULT '[]',
                malware_family TEXT DEFAULT '',
                threat_actor TEXT DEFAULT '',
                references_info TEXT DEFAULT '[]'
            )
        ''')

        # 9. Detection Rules Table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS detection_rules (
                id TEXT PRIMARY KEY,
                rule_name TEXT UNIQUE,
                description TEXT,
                severity TEXT DEFAULT 'high',
                category TEXT DEFAULT 'Threat Detection',
                mitre_tactic TEXT,
                mitre_technique_id TEXT,
                mitre_technique_name TEXT,
                rule_type TEXT DEFAULT 'correlation',
                rule_logic TEXT,
                enabled INTEGER DEFAULT 1,
                created_by TEXT DEFAULT 'System',
                created_at TEXT
            )
        ''')

        # 10. SOAR Playbooks Table (Phase 8 Extended Schema)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS playbooks (
                id TEXT PRIMARY KEY,
                playbook_id TEXT UNIQUE,
                name TEXT NOT NULL,
                description TEXT DEFAULT '',
                trigger TEXT DEFAULT '{}',
                conditions TEXT DEFAULT '[]',
                actions TEXT DEFAULT '[]',
                required_permission TEXT DEFAULT 'playbook.execute',
                approval_required INTEGER DEFAULT 0,
                risk_level TEXT DEFAULT 'LOW',
                enabled INTEGER DEFAULT 1,
                execution_mode TEXT DEFAULT 'SIMULATION',
                created_by TEXT DEFAULT 'system',
                created_at TEXT,
                updated_at TEXT
            )
        ''')

        self._ensure_columns("playbooks", {
            "playbook_id": "TEXT DEFAULT ''",
            "name": "TEXT DEFAULT ''",
            "trigger": "TEXT DEFAULT '{}'",
            "conditions": "TEXT DEFAULT '[]'",
            "actions": "TEXT DEFAULT '[]'",
            "required_permission": "TEXT DEFAULT 'playbook.execute'",
            "approval_required": "INTEGER DEFAULT 0",
            "risk_level": "TEXT DEFAULT 'LOW'",
            "enabled": "INTEGER DEFAULT 1",
            "execution_mode": "TEXT DEFAULT 'SIMULATION'",
            "created_by": "TEXT DEFAULT 'system'",
            "created_at": "TEXT DEFAULT ''",
            "updated_at": "TEXT DEFAULT ''"
        })

        # 11. SOAR Playbook Executions Log Table (Phase 8 Immutable Execution History)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS playbook_executions (
                execution_id TEXT PRIMARY KEY,
                playbook_id TEXT NOT NULL,
                alert_id TEXT DEFAULT '',
                incident_id TEXT DEFAULT '',
                case_id TEXT DEFAULT '',
                target TEXT DEFAULT '',
                execution_mode TEXT DEFAULT 'SIMULATION',
                requested_by TEXT DEFAULT 'system',
                approved_by TEXT DEFAULT '',
                approval_reason TEXT DEFAULT '',
                started_at TEXT NOT NULL,
                completed_at TEXT DEFAULT '',
                status TEXT DEFAULT 'PENDING_APPROVAL',
                actions TEXT DEFAULT '[]',
                results TEXT DEFAULT '[]',
                error TEXT DEFAULT '',
                rollback_status TEXT DEFAULT 'NONE',
                idempotency_key TEXT DEFAULT ''
            )
        ''')

        # Indexes for Performance (Phase 1–5)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_ts ON events(timestamp)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_src_ip ON events(source_ip)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_dst_ip ON events(destination_ip)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status)")
        # Phase 7 — Threat Intelligence & IOC Tables
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS iocs (
                id TEXT PRIMARY KEY,
                type TEXT NOT NULL,
                value TEXT NOT NULL,
                normalized_value TEXT NOT NULL,
                confidence INTEGER DEFAULT 80,
                severity TEXT DEFAULT 'medium',
                reputation TEXT DEFAULT 'UNKNOWN',
                analyst_classification TEXT DEFAULT 'NONE',
                analyst_override_reason TEXT DEFAULT '',
                classified_by TEXT DEFAULT '',
                classified_at TEXT DEFAULT '',
                source TEXT DEFAULT 'Local',
                tags TEXT DEFAULT '[]',
                description TEXT DEFAULT '',
                first_seen TEXT,
                last_seen TEXT,
                created_at TEXT,
                updated_at TEXT,
                UNIQUE(type, normalized_value)
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ioc_enrichment_cache (
                cache_key TEXT PRIMARY KEY,
                provider TEXT NOT NULL,
                ioc_type TEXT NOT NULL,
                normalized_value TEXT NOT NULL,
                response_json TEXT NOT NULL,
                status TEXT DEFAULT 'UNKNOWN',
                cached_at TEXT NOT NULL,
                expires_at TEXT NOT NULL
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ioc_relationships (
                id TEXT PRIMARY KEY,
                ioc_id TEXT NOT NULL,
                target_type TEXT NOT NULL,
                target_id TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        ''')

        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_logs(timestamp)")
        # Phase 6 additional indexes
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_hostname ON events(hostname)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_username ON events(username)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_event_type ON events(event_type)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_case_alerts_case ON case_alerts(case_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_case_alerts_alert ON case_alerts(alert_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_case_incidents_case ON case_incidents(case_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_evidence_case ON evidence(case_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_notes_case ON case_notes(case_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_entities_type_val ON entities(entity_type, value)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_entity_rel_src ON entity_relationships(source_entity_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_entity_rel_tgt ON entity_relationships(target_entity_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_saved_hunts_owner ON saved_hunts(owner)")
        # Phase 6 hardened — incident junction table indexes
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_incident_alerts_inc ON incident_alerts(incident_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_incident_alerts_alt ON incident_alerts(alert_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_incident_entities_inc ON incident_entities(incident_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_incidents_assigned ON incidents(assigned_to)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_incidents_updated ON incidents(updated_at)")
        # Phase 7 Threat Intelligence Indexes
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_iocs_norm ON iocs(normalized_value, type)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_iocs_rep ON iocs(reputation)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_ioc_cache_exp ON ioc_enrichment_cache(expires_at)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_ioc_rel_ioc ON ioc_relationships(ioc_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_ioc_rel_target ON ioc_relationships(target_id, target_type)")
        # Phase 8 SOAR Playbook Indexes
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_pb_exec_status ON playbook_executions(status)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_pb_exec_pb ON playbook_executions(playbook_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_pb_exec_alert ON playbook_executions(alert_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_pb_exec_inc ON playbook_executions(incident_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_pb_exec_idemp ON playbook_executions(idempotency_key)")

        # Phase 9 SOC Simulation & Training Tables
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scenarios (
                scenario_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                category TEXT DEFAULT 'ATTACK_SIMULATION',
                difficulty TEXT DEFAULT 'MEDIUM',
                target_role TEXT DEFAULT 'SOC Analyst L1',
                description TEXT DEFAULT '',
                mitre_attack TEXT DEFAULT '[]',
                steps TEXT DEFAULT '[]',
                hints TEXT DEFAULT '[]',
                estimated_duration_mins INTEGER DEFAULT 15,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scenario_runs (
                run_id TEXT PRIMARY KEY,
                scenario_id TEXT NOT NULL,
                status TEXT DEFAULT 'DRAFT',
                speed_multiplier REAL DEFAULT 1.0,
                started_at TEXT,
                paused_at TEXT,
                completed_at TEXT,
                requested_by TEXT DEFAULT 'system',
                events_count INTEGER DEFAULT 0,
                alerts_count INTEGER DEFAULT 0,
                error_msg TEXT DEFAULT '',
                source_mode TEXT DEFAULT 'simulation',
                created_at TEXT NOT NULL
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scenario_events (
                id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL,
                step_number INTEGER NOT NULL,
                event_id TEXT DEFAULT '',
                source_mode TEXT DEFAULT 'simulation',
                event_type TEXT DEFAULT '',
                timestamp TEXT NOT NULL,
                payload TEXT NOT NULL
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS training_sessions (
                session_id TEXT PRIMARY KEY,
                scenario_id TEXT NOT NULL,
                scenario_run_id TEXT DEFAULT '',
                analyst_username TEXT NOT NULL,
                status TEXT DEFAULT 'IN_PROGRESS',
                hints_used TEXT DEFAULT '[]',
                current_step INTEGER DEFAULT 1,
                started_at TEXT NOT NULL,
                submitted_at TEXT,
                final_score INTEGER DEFAULT 0,
                passed BOOLEAN DEFAULT 0
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS training_answers (
                id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                dimension TEXT NOT NULL,
                step_number INTEGER DEFAULT 1,
                answer_json TEXT NOT NULL,
                score_points INTEGER DEFAULT 0,
                max_points INTEGER DEFAULT 10,
                feedback TEXT DEFAULT '',
                submitted_at TEXT NOT NULL
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS training_scores (
                score_id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                scenario_id TEXT NOT NULL,
                analyst_username TEXT NOT NULL,
                total_score INTEGER DEFAULT 0,
                percentage REAL DEFAULT 0.0,
                passed BOOLEAN DEFAULT 0,
                breakdown_json TEXT NOT NULL,
                mistakes_json TEXT DEFAULT '[]',
                correct_actions_json TEXT DEFAULT '[]',
                recommendations_json TEXT DEFAULT '[]',
                created_at TEXT NOT NULL
            )
        ''')

        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scenario_runs_status ON scenario_runs(status)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scenario_runs_scen ON scenario_runs(scenario_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scen_events_run ON scenario_events(run_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_train_sess_analyst ON training_sessions(analyst_username)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_train_scores_session ON training_scores(session_id)")

        # Initialize Phase 3 Telemetry Events Table
        from src.telemetry.storage import SQLiteEventStore
        SQLiteEventStore(db_path=self.db_path)

        # Seed users if empty
        cursor.execute("SELECT COUNT(*) FROM users")
        if cursor.fetchone()[0] == 0:
            from src.security import hash_password
            import uuid
            import secrets
            # ----------------------------------------------------------------
            # LAB ACCOUNTS — auto-generated on first run
            # Passwords are cryptographically random and stored only as hashes.
            # Cleartext credentials are written ONCE to lab_credentials.txt.
            # ----------------------------------------------------------------
            lab_users = [
                ("analyst_l1",     "SOC Analyst L1"),
                ("analyst_l2",     "SOC Analyst L2"),
                ("threat_hunter",  "Threat Hunter"),
                ("responder",      "Incident Responder"),
                ("engineer",       "Detection Engineer"),
                ("manager",        "SOC Manager"),
                ("readonly",       "Read Only"),
            ]
            cred_lines = [
                "# ============================================================",
                "# SOC Lab — Auto-Generated Lab Account Credentials",
                "# These are LAB accounts created for the SOC Laboratory.",
                "# Generated on first-run.  Keep this file secure.",
                "# To reset: delete these users from the DB and restart.",
                "# ============================================================",
                "",
            ]
            for username, role in lab_users:
                uid = str(uuid.uuid4())
                raw_password = secrets.token_urlsafe(20)
                pwd_hash = hash_password(raw_password)
                cursor.execute(
                    "INSERT INTO users (id, username, password_hash, email, role, is_active, created_at) VALUES (?, ?, ?, ?, ?, 1, ?)",
                    (uid, username, pwd_hash, f"{username}@soclab.internal", role, datetime.now().isoformat())
                )
                cred_lines.append(f"{username:<20} | {role:<22} | {raw_password}")
            
            if os.path.basename(self.db_path) == "soc_data.db":
                # Write credentials to a file readable only by the process owner
                cred_path = os.path.join(
                    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    "lab_credentials.txt"
                )
                with open(cred_path, "w") as f:
                    f.write("\n".join(cred_lines) + "\n")
                try:
                    os.chmod(cred_path, 0o600)
                except Exception:
                    pass  # Non-fatal on platforms without chmod
                print(f"[SOC LAB] First-run credentials written to: {cred_path}")
                print("[SOC LAB] Restrict access to this file.  It will NOT be regenerated unless you reseed.")
            
        self.conn.commit()

    def _ensure_columns(self, table_name, columns_dict):
        cursor = self.conn.cursor()
        cursor.execute(f"PRAGMA table_info({table_name})")
        existing_cols = {row["name"] for row in cursor.fetchall()}
        for col_name, col_def in columns_dict.items():
            if col_name not in existing_cols:
                try:
                    cursor.execute(f"ALTER TABLE {table_name} ADD COLUMN {col_name} {col_def}")
                except Exception as e:
                    pass
        self.conn.commit()

    def save_alert(self, alert, deduplicate: bool = True):
        cursor = self.conn.cursor()
        now_str = datetime.now().isoformat()
        rule_id = alert.get('rule_id', '')
        source = alert.get('source', 'system')
        asset = alert.get('affected_asset', source)
        user = alert.get('affected_user', 'System')

        if deduplicate and rule_id:
            # Look for recent active alert for same rule_id & asset/source within 300s window
            cursor.execute('''
                SELECT id, occurrence_count, triggering_event_ids, evidence 
                FROM alerts 
                WHERE rule_id = ? AND (affected_asset = ? OR source = ?) AND status NOT IN ('RESOLVED', 'FALSE_POSITIVE')
                ORDER BY timestamp DESC LIMIT 1
            ''', (rule_id, asset, source))
            existing = cursor.fetchone()
            if existing:
                existing_id = existing["id"]
                new_count = (existing["occurrence_count"] or 1) + 1
                
                try:
                    existing_evt_ids = json.loads(existing["triggering_event_ids"]) if existing["triggering_event_ids"] else []
                except Exception:
                    existing_evt_ids = []
                new_evt_ids = alert.get("triggering_event_ids", [])
                merged_evt_ids = list(dict.fromkeys(existing_evt_ids + new_evt_ids))

                try:
                    existing_ev = json.loads(existing["evidence"]) if existing["evidence"] else []
                except Exception:
                    existing_ev = []
                new_ev = alert.get("evidence", [])
                merged_ev = existing_ev + [e for e in new_ev if e not in existing_ev]

                cursor.execute('''
                    UPDATE alerts 
                    SET occurrence_count = ?, last_seen = ?, triggering_event_ids = ?, evidence = ?
                    WHERE id = ?
                ''', (new_count, now_str, json.dumps(merged_evt_ids), json.dumps(merged_ev[:20]), existing_id))
                self.conn.commit()
                return existing_id

        alert_id = alert.get('id') or f"ALERT-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        cursor.execute('''
            INSERT OR REPLACE INTO alerts 
            (id, rule_id, title, severity, description, reason, source, destination, timestamp, indicators, status,
             confidence, risk_score, risk_breakdown, affected_asset, affected_user, mitre_tactic, mitre_technique,
             detection_rule, source_mode, triggering_event_ids, first_seen, last_seen, occurrence_count, assignee,
             evidence, fp_reason, fp_analyst, fp_timestamp, analyst_notes, processed)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            alert_id,
            rule_id,
            alert.get('title'),
            alert.get('severity', 'medium'),
            alert.get('description', ''),
            alert.get('reason', ''),
            source,
            alert.get('destination', ''),
            alert.get('timestamp', now_str),
            json.dumps(alert.get('indicators', [])) if isinstance(alert.get('indicators'), list) else str(alert.get('indicators', '[]')),
            alert.get('status', 'NEW'),
            alert.get('confidence', 80),
            alert.get('risk_score', 50),
            json.dumps(alert.get('risk_breakdown', {})) if isinstance(alert.get('risk_breakdown'), dict) else str(alert.get('risk_breakdown', '{}')),
            asset,
            user,
            alert.get('mitre_tactic', 'Defense Evasion'),
            alert.get('mitre_technique', 'T1078'),
            alert.get('detection_rule', 'Default Rule'),
            alert.get('source_mode', 'live'),
            json.dumps(alert.get('triggering_event_ids', [])) if isinstance(alert.get('triggering_event_ids'), list) else str(alert.get('triggering_event_ids', '[]')),
            alert.get('first_seen', now_str),
            alert.get('last_seen', now_str),
            alert.get('occurrence_count', 1),
            alert.get('assignee', 'Unassigned'),
            json.dumps(alert.get('evidence', [])) if isinstance(alert.get('evidence'), list) else str(alert.get('evidence', '[]')),
            alert.get('fp_reason', ''),
            alert.get('fp_analyst', ''),
            alert.get('fp_timestamp', ''),
            json.dumps(alert.get('analyst_notes', [])) if isinstance(alert.get('analyst_notes'), list) else str(alert.get('analyst_notes', '[]')),
            1 if alert.get('processed') else 0
        ))
        self.conn.commit()
        return alert_id

    def save_incident(self, incident):
        cursor = self.conn.cursor()
        now_str = datetime.now().isoformat()
        cursor.execute('''
            INSERT OR REPLACE INTO incidents
            (id, title, severity, priority, status, category, created_at, alert_id, description,
             mitre_attack, affected_assets, affected_users, related_alerts, evidence, timeline, ioc_list, analysts)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            incident.get('id'),
            incident.get('title'),
            incident.get('severity', 'high'),
            incident.get('priority', 'P2'),
            incident.get('status', 'open'),
            incident.get('category', 'Security Breach'),
            incident.get('created_at', now_str),
            incident.get('alert_id', ''),
            incident.get('description', ''),
            incident.get('mitre_attack', 'T1110 - Brute Force'),
            json.dumps(incident.get('affected_assets', [])) if isinstance(incident.get('affected_assets'), list) else str(incident.get('affected_assets', '[]')),
            json.dumps(incident.get('affected_users', [])) if isinstance(incident.get('affected_users'), list) else str(incident.get('affected_users', '[]')),
            json.dumps(incident.get('related_alerts', [])) if isinstance(incident.get('related_alerts'), list) else str(incident.get('related_alerts', '[]')),
            json.dumps(incident.get('evidence', [])) if isinstance(incident.get('evidence'), list) else str(incident.get('evidence', '[]')),
            json.dumps(incident.get('timeline', [])) if isinstance(incident.get('timeline'), list) else str(incident.get('timeline', '[]')),
            json.dumps(incident.get('ioc_list', [])) if isinstance(incident.get('ioc_list'), list) else str(incident.get('ioc_list', '[]')),
            json.dumps(incident.get('analysts', ['SOC Analyst L1'])) if isinstance(incident.get('analysts'), list) else str(incident.get('analysts', '["SOC Analyst L1"]'))
        ))
        self.conn.commit()

    def get_stats(self):
        cursor = self.conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM alerts")
        alerts_count = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM incidents WHERE status != 'resolved'")
        active_incidents = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM incidents")
        total_incidents = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM events")
        events_count = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM assets")
        assets_count = cursor.fetchone()[0]
        return {
            'total_alerts': alerts_count,
            'active_incidents': active_incidents,
            'total_incidents': total_incidents,
            'total_events': events_count,
            'total_assets': assets_count
        }

    def get_alerts(self, limit=100):
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?", (limit,))
        rows = cursor.fetchall()
        alerts = []
        for r in rows:
            dict_r = dict(r)
            for json_col in ['indicators', 'evidence', 'triggering_event_ids', 'analyst_notes']:
                try:
                    dict_r[json_col] = json.loads(dict_r[json_col]) if dict_r.get(json_col) else []
                except Exception:
                    dict_r[json_col] = []
            try:
                dict_r['risk_breakdown'] = json.loads(dict_r['risk_breakdown']) if dict_r.get('risk_breakdown') else {}
            except Exception:
                dict_r['risk_breakdown'] = {}
            alerts.append(dict_r)
        return alerts

    def get_incidents(self, limit=50):
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM incidents ORDER BY created_at DESC LIMIT ?", (limit,))
        rows = cursor.fetchall()
        incidents = []
        for r in rows:
            dict_r = dict(r)
            for field in ['affected_assets', 'affected_users', 'related_alerts', 'evidence', 'timeline', 'ioc_list', 'analysts']:
                try:
                    dict_r[field] = json.loads(dict_r[field]) if dict_r.get(field) else []
                except:
                    dict_r[field] = []
            incidents.append(dict_r)
        return incidents

    def close(self):
        self.conn.close()
