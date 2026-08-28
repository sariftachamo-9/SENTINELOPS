import json
from datetime import datetime
from src.database import Database

class AssetManager:
    """Manages SOC asset inventory and real-time integration status."""

    def __init__(self, db: Database = None):
        self.db = db if db else Database()
        self._seed_default_assets()

    def _seed_default_assets(self):
        cursor = self.db.get_cursor()
        cursor.execute("SELECT COUNT(*) FROM assets")
        if cursor.fetchone()[0] == 0:
            now_iso = datetime.now().isoformat()
            default_assets = [
                ("AST-WIN-LAB", "WIN-LAB-VM01", "10.0.2.15", "00:50:56:A1:00:10", "Windows Server 2022", "Windows Lab VM", "SecOps", "Lab", "High", "Lab-Zone", "NOT_CONFIGURED", now_iso, 50, json.dumps(["Windows", "Lab", "Winlogbeat"])),
                ("AST-LNX-LAB", "linux-lab-vm", "10.0.0.45", "00:50:56:A1:00:11", "Ubuntu 22.04 LTS", "Linux Lab VM", "DevOps", "Lab", "High", "Lab-Zone", "NOT_CONFIGURED", now_iso, 40, json.dumps(["Linux", "Lab", "Filebeat"])),
                ("AST-SOC-SRV", "soc-lab-server", "127.0.0.1", "00:00:00:00:00:00", "Linux / SOC Core", "SOC Core Server", "SecOps", "Production", "Critical", "HQ-Server-Room", "ONLINE", now_iso, 10, json.dumps(["SOC", "Core", "API"])),
                ("AST-NET-SNS", "net-sensor-01", "10.0.0.254", "00:50:56:A1:00:12", "Suricata / Zeek OS", "Network Sensor", "NetSec", "Lab", "High", "Network-Tap", "NOT_CONFIGURED", now_iso, 60, json.dumps(["Suricata", "Zeek", "NSM"])),
                ("AST-001", "DC-01.corp.internal", "10.0.0.10", "00:50:56:A1:00:01", "Windows Server 2022", "Domain Controller", "SecOps", "Production", "Critical", "DataCenter-1", "OFFLINE", now_iso, 85, json.dumps(["AD", "Identity"])),
                ("AST-002", "WEB-APP-01", "10.0.0.20", "00:50:56:A1:00:02", "Ubuntu 22.04 LTS", "Web Server", "DevOps", "Production", "High", "DMZ", "OFFLINE", now_iso, 45, json.dumps(["HTTP", "Frontend"])),
            ]
            cursor.executemany('''
                INSERT INTO assets (id, hostname, ip, mac, os, role, owner, environment, criticality, location, agent_status, last_seen, risk_score, tags)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', default_assets)
            self.db.conn.commit()

    def get_assets(self) -> list:
        cursor = self.db.get_cursor()
        cursor.execute("SELECT * FROM assets ORDER BY risk_score DESC")
        rows = cursor.fetchall()
        assets = []
        for r in rows:
            d = dict(r)
            try:
                d['tags'] = json.loads(d['tags']) if d.get('tags') else []
            except:
                d['tags'] = []
            assets.append(d)
        return assets

    def update_asset_status(self, asset_id: str, status: str, last_seen: str = None):
        cursor = self.db.get_cursor()
        now_str = last_seen or datetime.now().isoformat()
        cursor.execute(
            "UPDATE assets SET agent_status = ?, last_seen = ? WHERE id = ? OR hostname = ?",
            (status, now_str, asset_id, asset_id)
        )
        self.db.conn.commit()

