"""
SOC Lab — Operational SOC Metrics Engine (Phase 9)
===================================================
Calculates real-time operational metrics strictly from stored platform database data:
  - Events/sec & total events
  - Alerts today & volume by severity
  - Open incidents & open cases
  - MTTD (Mean Time to Detect)
  - MTTR (Mean Time to Respond)
  - MTTR_resolve (Mean Time to Resolve)
  - False positive rate (%)
  - IOC matches & MITRE technique coverage
  - SOAR total executions & failed playbooks

Never fabricates metrics. If database tables are empty, honestly returns 0 / "NO DATA".
"""

from typing import Dict, List, Any
from datetime import datetime, timedelta
import json

from src.database import Database
from src.telemetry.health import TelemetryHealthMonitor


class SOCMetricsEngine:
    """
    Computes real operational SOC platform metrics from actual stored records.
    """

    def __init__(self, db: Database = None):
        self.db = db if db else Database()
        self.health_monitor = TelemetryHealthMonitor()

    def get_metrics(self) -> Dict[str, Any]:
        """
        Calculate complete real-time operational SOC metrics.
        """
        cursor = self.db.get_cursor()

        # 1. Telemetry Events Statistics
        cursor.execute("SELECT COUNT(*) FROM events")
        total_events = cursor.fetchone()[0]

        # Calculate Events Per Second (EPS) rolling 60s
        health_summary = self.health_monitor.get_health_summary()
        eps = health_summary["metrics"].get("events_per_second_rolling_60s", 0.0)

        # 2. Alerts Today & Severity Breakdown
        today_prefix = datetime.now().strftime("%Y-%m-%d")
        cursor.execute("SELECT COUNT(*) FROM alerts WHERE timestamp LIKE ?", (f"{today_prefix}%",))
        alerts_today = cursor.fetchone()[0]

        cursor.execute("SELECT severity, COUNT(*) FROM alerts GROUP BY severity")
        sev_rows = cursor.fetchall()
        severity_breakdown = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        critical_alerts = 0
        for r in sev_rows:
            sev_key = (r[0] or "medium").lower()
            count = r[1]
            severity_breakdown[sev_key] = count
            if sev_key == "critical":
                critical_alerts = count

        # 3. Incidents & Cases
        cursor.execute("SELECT COUNT(*) FROM incidents WHERE status IN ('OPEN', 'INVESTIGATING', 'IN_PROGRESS')")
        open_incidents = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM cases WHERE status IN ('OPEN', 'IN_PROGRESS', 'TRIAGE')")
        open_cases = cursor.fetchone()[0]

        # 4. False Positive Rate
        cursor.execute("SELECT COUNT(*) FROM alerts")
        total_alerts = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM alerts WHERE status IN ('FALSE_POSITIVE', 'FP', 'CLOSED_FP')")
        fp_alerts = cursor.fetchone()[0]
        fp_rate = round((fp_alerts / total_alerts * 100), 2) if total_alerts > 0 else 0.0

        # 5. MTTD (Mean Time to Detect) in Seconds
        # Calculated from diff between triggering event timestamp and alert creation timestamp
        cursor.execute("SELECT timestamp, first_seen FROM alerts WHERE timestamp IS NOT NULL AND timestamp != '' AND first_seen IS NOT NULL AND first_seen != '' LIMIT 100")
        mttd_rows = cursor.fetchall()
        mttd_diffs = []
        for r in mttd_rows:
            try:
                t_alert = datetime.fromisoformat(r[0])
                t_event = datetime.fromisoformat(r[1])
                diff = abs((t_alert - t_event).total_seconds())
                if diff < 86400:  # Reasonable sanity check < 24h
                    mttd_diffs.append(diff)
            except Exception:
                pass
        mttd_seconds = round(sum(mttd_diffs) / len(mttd_diffs), 1) if mttd_diffs else 0.0

        # 6. MTTR (Mean Time to Respond / Resolve)
        cursor.execute("SELECT created_at, closed_at FROM cases WHERE closed_at IS NOT NULL AND closed_at != '' LIMIT 100")
        mttr_rows = cursor.fetchall()
        mttr_diffs = []
        for r in mttr_rows:
            try:
                t_start = datetime.fromisoformat(r[0])
                t_end = datetime.fromisoformat(r[1])
                mttr_diffs.append(abs((t_end - t_start).total_seconds()))
            except Exception:
                pass
        mttr_seconds = round(sum(mttr_diffs) / len(mttr_diffs), 1) if mttr_diffs else 0.0

        # 7. IOC Matches & Threat Intel
        cursor.execute("SELECT COUNT(*) FROM iocs WHERE reputation = 'MALICIOUS'")
        ioc_matches = cursor.fetchone()[0]

        # 8. MITRE Technique Coverage
        cursor.execute("SELECT DISTINCT mitre_technique FROM alerts WHERE mitre_technique IS NOT NULL AND mitre_technique != ''")
        technique_rows = cursor.fetchall()
        mitre_coverage_count = len(technique_rows)
        mitre_techniques = [r[0] for r in technique_rows]

        # 9. SOAR Playbook Execution Metrics
        cursor.execute("SELECT COUNT(*) FROM playbook_executions")
        soar_total = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM playbook_executions WHERE status = 'FAILED'")
        soar_failed = cursor.fetchone()[0]

        # Format output payload
        return {
            "timestamp": datetime.now().isoformat(),
            "events_per_second": eps,
            "total_events": total_events,
            "alerts_today": alerts_today,
            "total_alerts": total_alerts,
            "critical_alerts": critical_alerts,
            "open_incidents": open_incidents,
            "open_cases": open_cases,
            "mttd_seconds": mttd_seconds,
            "mttd_display": f"{mttd_seconds}s" if mttd_seconds > 0 else "NO DATA",
            "mttr_seconds": mttr_seconds,
            "mttr_display": f"{mttr_seconds}s" if mttr_seconds > 0 else "NO DATA",
            "false_positive_rate_pct": fp_rate,
            "false_positive_rate_display": f"{fp_rate}%" if total_alerts > 0 else "NO DATA",
            "ioc_matches": ioc_matches,
            "mitre_technique_coverage": mitre_coverage_count,
            "mitre_techniques": mitre_techniques,
            "soar_executions": soar_total,
            "failed_playbooks": soar_failed,
            "alert_volume_by_severity": severity_breakdown,
            "has_data": total_events > 0 or total_alerts > 0
        }

    def get_metrics_timeline(self, days: int = 7) -> List[Dict[str, Any]]:
        """
        Get daily historical metrics trend timeline.
        """
        cursor = self.db.get_cursor()
        timeline = []
        now = datetime.now()

        for i in range(days - 1, -1, -1):
            day_dt = now - timedelta(days=i)
            day_str = day_dt.strftime("%Y-%m-%d")

            cursor.execute("SELECT COUNT(*) FROM events WHERE timestamp LIKE ?", (f"{day_str}%",))
            ev_cnt = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM alerts WHERE timestamp LIKE ?", (f"{day_str}%",))
            alt_cnt = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM incidents WHERE created_at LIKE ?", (f"{day_str}%",))
            inc_cnt = cursor.fetchone()[0]

            timeline.append({
                "date": day_str,
                "events": ev_cnt,
                "alerts": alt_cnt,
                "incidents": inc_cnt
            })

        return timeline
