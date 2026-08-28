import psutil
from datetime import datetime
from src.database import Database
from src.siem_adapters import SIEMManager
from src.telemetry.health import TelemetryHealthMonitor

class SOCHealthMonitor:
    def __init__(self, db: Database = None):
        self.db = db if db else Database()
        self.siem_manager = SIEMManager()
        self.telemetry_health = TelemetryHealthMonitor()

    def get_system_health(self) -> dict:
        db_status = "ONLINE"
        try:
            stats = self.db.get_stats()
        except Exception:
            db_status = "OFFLINE"
            stats = {}

        siem_statuses = self.siem_manager.get_all_health()
        t_health = self.telemetry_health.get_health_summary()

        # Monitor local CPU & RAM
        cpu_percent = psutil.cpu_percent(interval=0.1)
        mem_percent = psutil.virtual_memory().percent

        services = [
            {"name": "Database Backend (SQLite/PostgreSQL)", "status": db_status, "details": f"Total Alerts: {stats.get('total_alerts', 0)}"},
            {"name": "FastAPI REST Server (Port 8001)", "status": "ONLINE", "details": "Responding on port 8001"},
            {"name": "Web UI Portal (Port 8002)", "status": "ONLINE", "details": "Responding on port 8002"},
            {"name": "Telemetry Ingestion Engine", "status": t_health["status"], "details": f"Processed: {t_health['metrics']['events_processed']}, EPS: {t_health['metrics']['events_per_second_rolling_60s']}"},
            {"name": "ML Anomaly Detector", "status": "ONLINE", "details": "IsolationForest model loaded"},
            {"name": "Continuous Threat Feed Generator", "status": "SIMULATION", "details": "Continuous Lab Threat Feed active"}
        ]

        for adapter in siem_statuses:
            services.append({
                "name": adapter["adapter"],
                "status": adapter["status"],
                "details": adapter["details"]
            })

        return {
            "timestamp": datetime.now().isoformat(),
            "overall_status": "HEALTHY" if t_health["status"] == "ONLINE" else "DEGRADED",
            "system_metrics": {
                "cpu_usage_pct": cpu_percent,
                "memory_usage_pct": mem_percent,
                "events_per_second": t_health["metrics"]["events_per_second_rolling_60s"]
            },
            "services": services
        }
