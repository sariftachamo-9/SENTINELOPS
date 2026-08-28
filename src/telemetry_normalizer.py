import json
import uuid
from datetime import datetime

class TelemetryNormalizer:
    def __init__(self):
        pass

    def normalize(self, raw_event: dict, source_type: str = "auto") -> dict:
        """
        Normalizes arbitrary log telemetry into a standard SOC Event schema.
        Never discards the raw_event payload.
        """
        if not isinstance(raw_event, dict):
            try:
                raw_event = json.loads(raw_event)
            except Exception:
                raw_event = {"raw_text": str(raw_event)}

        now_str = datetime.now().isoformat()
        event_id = str(raw_event.get("event_id") or raw_event.get("id") or f"EVT-{uuid.uuid4().hex[:12]}")
        timestamp = str(raw_event.get("timestamp") or raw_event.get("@timestamp") or raw_event.get("time") or now_str)

        # Detect source type if auto
        if source_type == "auto":
            if "winlog" in raw_event or "EventID" in raw_event or "Sysmon" in str(raw_event):
                source_type = "windows"
            elif "suricata" in str(raw_event).lower() or "event_type" in raw_event and raw_event.get("event_type") in ["alert", "dns", "http", "tls"]:
                source_type = "network_ids"
            elif "zeek" in str(raw_event).lower() or "id.orig_h" in raw_event:
                source_type = "zeek"
            elif "sshd" in str(raw_event).lower() or "sudo" in str(raw_event).lower() or "auth" in str(raw_event).lower():
                source_type = "linux"
            else:
                source_type = raw_event.get("source_type", "generic")

        normalized = {
            "event_id": event_id,
            "timestamp": timestamp,
            "source_type": source_type,
            "source_product": raw_event.get("source_product", source_type),
            "hostname": raw_event.get("hostname") or raw_event.get("host") or raw_event.get("computer_name", "unknown-host"),
            "source_ip": raw_event.get("source_ip") or raw_event.get("src_ip") or raw_event.get("src_host") or raw_event.get("id.orig_h", "0.0.0.0"),
            "destination_ip": raw_event.get("destination_ip") or raw_event.get("dest_ip") or raw_event.get("dst_ip") or raw_event.get("id.resp_h", "0.0.0.0"),
            "source_port": int(raw_event.get("source_port") or raw_event.get("src_port") or raw_event.get("id.orig_p") or 0),
            "destination_port": int(raw_event.get("destination_port") or raw_event.get("dest_port") or raw_event.get("dst_port") or raw_event.get("id.resp_p") or 0),
            "username": raw_event.get("username") or raw_event.get("user") or raw_event.get("TargetUserName", "system"),
            "process_name": raw_event.get("process_name") or raw_event.get("process") or raw_event.get("Image", "N/A"),
            "event_type": raw_event.get("event_type") or raw_event.get("action") or raw_event.get("signature", "general_activity"),
            "severity": raw_event.get("severity") or self._calculate_default_severity(raw_event),
            "risk_score": int(raw_event.get("risk_score", 0)),
            "environment": raw_event.get("environment", "lab"),
            "raw_event": raw_event
        }

        # Source type specific normalization overlays
        if source_type == "windows":
            event_id_num = raw_event.get("EventID") or raw_event.get("event_id_num")
            if event_id_num in [4625, "4625"]:
                normalized["event_type"] = "Failed Login"
                normalized["severity"] = "high"
            elif event_id_num in [4624, "4624"]:
                normalized["event_type"] = "Successful Login"
                normalized["severity"] = "low"
            elif event_id_num in [4672, "4672"]:
                normalized["event_type"] = "Special Privileges Assigned"
                normalized["severity"] = "medium"
            elif event_id_num in [4688, "4688"]:
                normalized["event_type"] = "Process Creation"
                normalized["process_name"] = raw_event.get("NewProcessName", normalized["process_name"])

        elif source_type == "network_ids":
            alert_obj = raw_event.get("alert", {})
            if isinstance(alert_obj, dict) and "signature" in alert_obj:
                normalized["event_type"] = alert_obj["signature"]
                severity_num = alert_obj.get("severity", 3)
                normalized["severity"] = "critical" if severity_num == 1 else ("high" if severity_num == 2 else "medium")

        return normalized

    def _calculate_default_severity(self, raw_event: dict) -> str:
        text = str(raw_event).lower()
        if "critical" in text or "malware" in text or "ransomware" in text:
            return "critical"
        elif "failed" in text or "denied" in text or "unauthorized" in text or "scan" in text:
            return "high"
        elif "warning" in text or "sudo" in text or "privilege" in text:
            return "medium"
        return "low"
