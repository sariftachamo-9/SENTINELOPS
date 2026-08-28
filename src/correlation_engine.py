from datetime import datetime
from collections import defaultdict
from typing import List, Dict, Any, Optional

class CorrelationEngine:
    """
    Multi-Entity Correlation Engine for Enterprise SOC.
    Tracks state across user, host, source_ip, destination_ip, process, event_type, and time_window.
    Identifies attack patterns such as Brute Force and Account Compromise sequences.
    """
    def __init__(self, db=None):
        self.db = db
        # Structure: entity_key -> list of (timestamp_float, event_dict)
        self.entity_events = defaultdict(list)
        self.recent_correlations = []

    def process_event(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Process incoming normalized telemetry event and evaluate correlation rules.
        Returns list of correlated alert objects.
        """
        timestamp_str = event.get("timestamp") or datetime.now().isoformat()
        try:
            event_ts = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00")).timestamp()
        except Exception:
            event_ts = datetime.now().timestamp()

        # Add event to entity sliding buffers
        source_ip = event.get("source_ip") or "0.0.0.0"
        username = event.get("username") or "system"
        hostname = event.get("hostname") or "unknown-host"

        keys = []
        if source_ip != "0.0.0.0":
            keys.append(f"ip:{source_ip}")
        if username not in ("system", "N/A", ""):
            keys.append(f"user:{username}")
        if source_ip != "0.0.0.0" and username not in ("system", "N/A", ""):
            keys.append(f"ip_user:{source_ip}:{username}")
        if hostname != "unknown-host":
            keys.append(f"host:{hostname}")

        for key in keys:
            self.entity_events[key].append((event_ts, event))
            # Keep max 500 events per key, clean up > 600s old
            cutoff = event_ts - 600
            self.entity_events[key] = [item for item in self.entity_events[key] if item[0] >= cutoff]

        correlated_alerts = []

        # 1. Account Compromise Correlation Rule:
        # Multiple failed logins + 1 successful login from same source IP / user within 300s
        ip_user_key = f"ip_user:{source_ip}:{username}"
        if ip_user_key in self.entity_events:
            events_window = [e[1] for e in self.entity_events[ip_user_key] if e[0] >= event_ts - 300]
            is_success_login = event.get("event_type") in ["Successful Login", "SSH Success", "Accepted password"] or "successful" in str(event.get("event_type")).lower()
            
            if is_success_login:
                failed_logins = [
                    e for e in events_window 
                    if e.get("event_type") in ["Failed Login", "SSH Failed"] or "failed" in str(e.get("event_type")).lower()
                ]
                if len(failed_logins) >= 2:
                    all_ids = [e.get("event_id") for e in events_window if e.get("event_id")]
                    corr_alert = {
                        "id": f"CORR-COMP-{datetime.now().strftime('%Y%m%d%H%M%S')}",
                        "rule_id": "CORR-ACCOUNT-COMPROMISE",
                        "title": "Possible Account Compromise (Failed Logins + Successful Login)",
                        "severity": "critical",
                        "confidence": 95,
                        "description": "High-confidence compromise detected: Multiple failed login attempts were immediately followed by a successful login from the same source IP against the same user account.",
                        "reason": f"{len(failed_logins)} failed authentication attempts were followed by a successful authentication within 5 minutes for account '{username}' from source IP {source_ip}.",
                        "source": source_ip,
                        "destination": event.get("destination_ip", "0.0.0.0"),
                        "affected_asset": hostname,
                        "affected_user": username,
                        "mitre_tactic": "Credential Access / Initial Access",
                        "mitre_technique": "T1078 - Valid Accounts",
                        "mitre_technique_id": "T1078",
                        "mitre_technique_name": "Valid Accounts",
                        "detection_rule": "Account Compromise Correlation",
                        "timestamp": datetime.now().isoformat(),
                        "indicators": [source_ip, username, hostname],
                        "triggering_event_ids": all_ids,
                        "evidence": [
                            {
                                "event_id": e.get("event_id"),
                                "timestamp": e.get("timestamp"),
                                "event_type": e.get("event_type"),
                                "username": e.get("username"),
                                "source_ip": e.get("source_ip")
                            } for e in events_window
                        ]
                    }
                    correlated_alerts.append(corr_alert)
                    # Clear window for this ip_user key to prevent duplicate correlation firing
                    self.entity_events[ip_user_key] = []

        # 2. Multi-Host Reconnaissance / Scanning Rule:
        # Same source IP visiting > 3 distinct destination IPs / hosts within 120s
        ip_key = f"ip:{source_ip}"
        if ip_key in self.entity_events and source_ip != "0.0.0.0":
            recent_ip_events = [e[1] for e in self.entity_events[ip_key] if e[0] >= event_ts - 120]
            destinations = set(e.get("destination_ip") for e in recent_ip_events if e.get("destination_ip") not in ("0.0.0.0", "", None))
            if len(destinations) >= 3:
                all_ids = [e.get("event_id") for e in recent_ip_events if e.get("event_id")]
                corr_alert = {
                    "id": f"CORR-RECON-{datetime.now().strftime('%Y%m%d%H%M%S')}",
                    "rule_id": "CORR-MULTI-HOST-RECON",
                    "title": "Multi-Host Network Reconnaissance / Scan Correlation",
                    "severity": "high",
                    "confidence": 85,
                    "description": "Sequential connections detected from a single source IP targeting multiple distinct destination assets.",
                    "reason": f"Source IP {source_ip} targeted {len(destinations)} distinct destination IPs within 2 minutes: {', '.join(list(destinations)[:5])}.",
                    "source": source_ip,
                    "destination": list(destinations)[0],
                    "affected_asset": hostname,
                    "affected_user": username,
                    "mitre_tactic": "Reconnaissance",
                    "mitre_technique": "T1046 - Network Service Discovery",
                    "mitre_technique_id": "T1046",
                    "mitre_technique_name": "Network Service Discovery",
                    "detection_rule": "Multi-Host Recon Correlation",
                    "timestamp": datetime.now().isoformat(),
                    "indicators": [source_ip, list(destinations)[0]],
                    "triggering_event_ids": all_ids,
                    "evidence": [
                        {
                            "event_id": e.get("event_id"),
                            "timestamp": e.get("timestamp"),
                            "event_type": e.get("event_type"),
                            "destination_ip": e.get("destination_ip")
                        } for e in recent_ip_events[:10]
                    ]
                }
                correlated_alerts.append(corr_alert)
                self.entity_events[ip_key] = []

        return correlated_alerts

    def add_alert(self, alert: Dict[str, Any]):
        """Legacy helper method to store alert in history."""
        self.recent_correlations.append(alert)
        if len(self.recent_correlations) > 500:
            self.recent_correlations = self.recent_correlations[-500:]

    def find_patterns(self) -> List[Dict[str, Any]]:
        """Returns active patterns in alert history."""
        return self.recent_correlations
