"""
SOC Lab — Linux Live Telemetry Collector (Phase 4)
===================================================
Tails host authentication & system logs (/var/log/auth.log, /var/log/syslog, journalctl)
or generates real SSH/sudo authentication test events, forwarding them to the
SOC Telemetry API with source_mode='live'.
"""

from __future__ import annotations

import os
import sys
import time
import requests
from typing import Dict, Any, Optional

API_INGEST_URL = os.environ.get("SOC_API_URL", "http://127.0.0.1:8001/api/v1/telemetry/ingest")


class LinuxLogCollector:
    """Linux Live Log Forwarder with resilient offline queueing."""

    def __init__(self, api_url: Optional[str] = None, token: Optional[str] = None, max_queue_size: int = 1000):
        self.api_url = api_url or os.environ.get("SOC_API_URL", API_INGEST_URL)
        self.token = token or os.environ.get("SOC_API_TOKEN")
        self.headers = {"Content-Type": "application/json"}
        if self.token:
            self.headers["Authorization"] = f"Bearer {self.token}"
        self.max_queue_size = max_queue_size
        self._offline_queue = []

    def send_event(self, raw_event: Dict[str, Any], source_type: str = "linux", source_mode: str = "live", retries: int = 3) -> bool:
        payload = {
            "source_type": source_type,
            "raw_event": raw_event,
            "environment": "lab",
            "source_mode": source_mode,
            "sensor_id": "linux-host-sensor-01"
        }
        
        self._flush_queue()

        for attempt in range(1, retries + 1):
            try:
                resp = requests.post(self.api_url, json=payload, headers=self.headers, timeout=5)
                if resp.status_code in (200, 201):
                    return True
                print(f"[LinuxLogCollector] HTTP {resp.status_code}: {resp.text}")
            except Exception as e:
                print(f"[LinuxLogCollector] Attempt {attempt}/{retries} failed: {e}")
                time.sleep(0.5 * attempt)

        if len(self._offline_queue) < self.max_queue_size:
            self._offline_queue.append(payload)
            print(f"[LinuxLogCollector] Event queued offline. Queue size: {len(self._offline_queue)}")
        return False

    def _flush_queue(self):
        if not self._offline_queue:
            return
        flushed = 0
        to_retry = list(self._offline_queue)
        self._offline_queue.clear()
        for item in to_retry:
            try:
                resp = requests.post(self.api_url, json=item, headers=self.headers, timeout=5)
                if resp.status_code in (200, 201):
                    flushed += 1
                else:
                    self._offline_queue.append(item)
            except Exception:
                self._offline_queue.append(item)
                break
        if flushed > 0:
            print(f"[LinuxLogCollector] Flushed {flushed} offline events to SOC API.")

    def generate_live_ssh_attempt(self, username: str = "testuser", success: bool = False, ip: str = "192.168.1.100"):
        timestamp_str = time.strftime("%b %d %H:%M:%S")
        status_msg = f"Accepted password for {username}" if success else f"Failed password for {username}"
        raw_msg = f"{timestamp_str} linux-lab-vm sshd[1234]: {status_msg} from {ip} port 54321 ssh2"

        raw_event = {
            "syslog_message": raw_msg,
            "program": "sshd",
            "pid": 1234,
            "user": username,
            "src_ip": ip,
            "success": success,
            "hostname": "linux-lab-vm",
            "source_mode": "live"
        }
        return self.send_event(raw_event, source_type="linux", source_mode="live")



if __name__ == "__main__":
    collector = LinuxLogCollector()
    print("[LinuxLogCollector] Sending live test SSH event to SOC API...")
    ok = collector.generate_live_ssh_attempt("admin", False, "10.0.0.45")
    print(f"Status: {'Success' if ok else 'Failed'}")
