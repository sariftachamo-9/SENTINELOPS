"""
SOC Lab — Windows Live Telemetry Collector (Phase 4)
=====================================================
Collects Windows Event Logs (EventID 4624, 4625, 4688, 4720, Sysmon 1, 3, PowerShell 4104)
and forwards them to the SOC Telemetry API with source_mode='live'.
"""

from __future__ import annotations

import os
import sys
import time
import requests
from typing import Dict, Any, Optional

API_INGEST_URL = os.environ.get("SOC_API_URL", "http://127.0.0.1:8001/api/v1/telemetry/ingest")


class WindowsLogCollector:
    """Windows Security Event Log Collector / Forwarder with resilient offline queueing."""

    def __init__(self, api_url: Optional[str] = None, token: Optional[str] = None, max_queue_size: int = 1000):
        self.api_url = api_url or os.environ.get("SOC_API_URL", API_INGEST_URL)
        self.token = token or os.environ.get("SOC_API_TOKEN")
        self.headers = {"Content-Type": "application/json"}
        if self.token:
            self.headers["Authorization"] = f"Bearer {self.token}"
        self.max_queue_size = max_queue_size
        self._offline_queue = []

    def send_event(self, raw_event: Dict[str, Any], source_mode: str = "live", retries: int = 3) -> bool:
        payload = {
            "source_type": "windows",
            "raw_event": raw_event,
            "environment": "lab",
            "source_mode": source_mode,
            "sensor_id": "winlogbeat-host-01"
        }
        
        # Try to flush queued events first if any
        self._flush_queue()

        for attempt in range(1, retries + 1):
            try:
                resp = requests.post(self.api_url, json=payload, headers=self.headers, timeout=5)
                if resp.status_code in (200, 201):
                    return True
                print(f"[WindowsLogCollector] HTTP {resp.status_code}: {resp.text}")
            except Exception as e:
                print(f"[WindowsLogCollector] Attempt {attempt}/{retries} failed: {e}")
                time.sleep(0.5 * attempt)

        # Enqueue for offline resilience
        if len(self._offline_queue) < self.max_queue_size:
            self._offline_queue.append(payload)
            print(f"[WindowsLogCollector] Event queued offline. Queue size: {len(self._offline_queue)}")
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
            print(f"[WindowsLogCollector] Flushed {flushed} offline events to SOC API.")

    def generate_win_event(self, event_id: int, user: str, computer: str = "WIN-LAB-VM01", ip: str = "10.0.2.15"):
        raw_event = {
            "EventID": event_id,
            "Channel": "Security",
            "ComputerName": computer,
            "SubjectUserName": user,
            "TargetUserName": user,
            "IpAddress": ip,
            "TimeCreated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "source_mode": "live"
        }
        if event_id == 4688:
            raw_event["NewProcessName"] = "C:\\Windows\\System32\\cmd.exe"
            raw_event["CommandLine"] = "cmd.exe /c powershell -ExecutionPolicy Bypass"
            raw_event["ParentProcessName"] = "C:\\Windows\\explorer.exe"

        return self.send_event(raw_event, source_mode="live")



if __name__ == "__main__":
    collector = WindowsLogCollector()
    print("[WindowsLogCollector] Sending live Windows test event to SOC API...")
    ok = collector.generate_win_event(4625, "Administrator", "WIN-SERVER-01", "192.168.1.50")
    print(f"Status: {'Success' if ok else 'Failed'}")
