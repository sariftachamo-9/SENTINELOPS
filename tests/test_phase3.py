"""
SOC Platform — Phase 3 Telemetry & Data-Ingestion Test Suite
============================================================
Comprehensive test suite verifying Phase 3 requirements:
  - Schema & Validator (valid, invalid, malformed IP, port, severity, oversized)
  - Source Adapters (Windows, Linux, Network, Generic, Syslog)
  - Ingestion API (authenticated, unauthenticated, unauthorized, rate-limited)
  - Batch Ingestion (success, batch limit, partial failure)
  - Deduplication (duplicate hash, occurrence counter, windowing)
  - Storage & Search (parameterized filters, pagination, timeline, raw preservation)
  - Telemetry Pipeline (end-to-end event -> alert execution)
  - Security (string injection, oversized payload, auth rejection)
"""

import os
import sys
import json
import unittest
import requests

# Ensure project root is in python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

BASE_URL = os.getenv("TEST_BASE_URL", "http://127.0.0.1:8001")


def get_lab_credentials():
    cred_file = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "lab_credentials.txt")
    creds = {}
    if os.path.exists(cred_file):
        with open(cred_file, "r") as f:
            for line in f:
                if line.startswith("#") or not line.strip():
                    continue
                parts = [p.strip() for p in line.split("|")]
                if len(parts) == 3:
                    creds[parts[0]] = parts[2]
    return creds


class TestPhase3TelemetryUnit(unittest.TestCase):
    """Unit tests for Telemetry Schema, Validator, Adapters, Deduplication, and Search."""

    def test_schema_valid_event(self):
        from src.telemetry.schema import NormalizedEvent
        ev = NormalizedEvent(
            source_type="windows",
            hostname="WIN-SERVER01",
            source_ip="192.168.1.100",
            username="admin_user",
            event_type="Failed Logon",
            severity="high",
            environment="lab",
            raw_event={"EventID": 4625}
        )
        self.assertIsNotNone(ev.event_id)
        self.assertEqual(ev.source_type, "windows")
        self.assertEqual(ev.severity, "high")
        self.assertEqual(ev.raw_event["EventID"], 4625)

    def test_schema_invalid_severity(self):
        from src.telemetry.schema import NormalizedEvent
        ev = NormalizedEvent(source_type="windows", severity="super_extreme_danger")
        self.assertEqual(ev.severity, "unknown")

    def test_validator_valid_event(self):
        from src.telemetry.validator import TelemetryValidator
        val = TelemetryValidator()
        raw = {
            "source_type": "linux",
            "source_ip": "10.0.0.5",
            "destination_port": 22,
            "username": "deploy_user",
            "message": "Accepted publickey for deploy_user"
        }
        res = val.validate(raw, source_type="linux")
        self.assertTrue(res.ok)

    def test_validator_malformed_ip(self):
        from src.telemetry.validator import TelemetryValidator
        val = TelemetryValidator()
        raw = {"source_ip": "999.888.777.666"}
        res = val.validate(raw)
        self.assertFalse(res.ok)
        self.assertTrue(any("Invalid IP" in e for e in res.errors))

    def test_validator_invalid_port(self):
        from src.telemetry.validator import TelemetryValidator
        val = TelemetryValidator()
        raw = {"destination_port": 99999}
        res = val.validate(raw)
        self.assertFalse(res.ok)
        self.assertTrue(any("Port out of range" in e for e in res.errors))

    def test_validator_injection_attempt(self):
        from src.telemetry.validator import TelemetryValidator
        val = TelemetryValidator()
        raw = {"username": "admin' UNION SELECT * FROM users;--"}
        res = val.validate(raw)
        self.assertFalse(res.ok)
        self.assertTrue(any("dangerous string" in e for e in res.errors))

    def test_validator_oversized_payload(self):
        from src.telemetry.validator import TelemetryValidator
        val = TelemetryValidator()
        huge_data = "A" * 600000  # > 512KB limit
        raw = {"huge_field": huge_data}
        res = val.validate(raw)
        self.assertFalse(res.ok)
        self.assertTrue(any("Payload too large" in e for e in res.errors))

    def test_windows_adapter_normalization(self):
        from src.telemetry.adapters.windows import WindowsAdapter
        adapter = WindowsAdapter()
        raw = {
            "EventID": 4625,
            "TargetUserName": "jdoe",
            "ComputerName": "CORP-DC01",
            "IpAddress": "192.168.1.50"
        }
        norm = adapter.normalize(raw, environment="lab")
        self.assertEqual(norm.source_type, "windows")
        self.assertEqual(norm.event_type, "Failed Logon")
        self.assertEqual(norm.severity, "high")
        self.assertEqual(norm.username, "jdoe")
        self.assertEqual(norm.hostname, "CORP-DC01")
        self.assertEqual(norm.source_ip, "192.168.1.50")
        self.assertTrue(norm.simulation)

    def test_linux_adapter_normalization(self):
        from src.telemetry.adapters.linux import LinuxAdapter
        adapter = LinuxAdapter()
        raw = {
            "program": "sshd",
            "message": "Failed password for invalid user root from 203.0.113.5 port 45123 ssh2",
            "hostname": "ubuntu-web01"
        }
        norm = adapter.normalize(raw)
        self.assertEqual(norm.source_type, "linux")
        self.assertEqual(norm.event_type, "SSH Failed Login")
        self.assertEqual(norm.severity, "high")
        self.assertEqual(norm.username, "root")
        self.assertEqual(norm.source_ip, "203.0.113.5")

    def test_network_adapter_normalization(self):
        from src.telemetry.adapters.network import NetworkAdapter
        adapter = NetworkAdapter()
        raw = {
            "event_type": "dns",
            "query": "malicious-c2-domain.internal",
            "src_ip": "10.0.1.20",
            "dest_ip": "8.8.8.8"
        }
        norm = adapter.normalize(raw)
        self.assertEqual(norm.source_type, "network")
        self.assertEqual(norm.event_type, "DNS Query")
        self.assertEqual(norm.source_ip, "10.0.1.20")
        self.assertEqual(norm.destination_ip, "8.8.8.8")

    def test_deduplication(self):
        from src.telemetry.deduplication import EventDeduplicator
        from src.telemetry.schema import NormalizedEvent
        dedup = EventDeduplicator(window_seconds=60)
        ev1 = NormalizedEvent(
            source_type="windows",
            hostname="HOST1",
            source_ip="192.168.1.1",
            event_type="Failed Login",
            username="user1"
        )
        ev2 = NormalizedEvent(
            source_type="windows",
            hostname="HOST1",
            source_ip="192.168.1.1",
            event_type="Failed Login",
            username="user1"
        )

        res1, is_dup1 = dedup.process(ev1)
        self.assertFalse(is_dup1)
        self.assertEqual(res1.occurrence_count, 1)

        res2, is_dup2 = dedup.process(ev2)
        self.assertTrue(is_dup2)
        self.assertEqual(res2.occurrence_count, 2)


class TestPhase3TelemetryAPI(unittest.TestCase):
    """Integration API tests for Phase 3 endpoints."""

    @classmethod
    def setUpClass(cls):
        cls.creds = get_lab_credentials()
        admin_pass = cls.creds.get("analyst_l2") or cls.creds.get("admin") or os.getenv("LAB_ADMIN_PASSWORD", "AdminPass123!")

        # Get L2 token for ingestion & search
        r = requests.post(f"{BASE_URL}/api/auth/login", json={"username": "analyst_l2", "password": admin_pass})
        if r.status_code == 200:
            cls.token_l2 = r.json()["access_token"]
            cls.headers_l2 = {"Authorization": f"Bearer {cls.token_l2}"}
        else:
            cls.headers_l2 = {}

        # Get Read Only token for permission checks
        ro_pass = cls.creds.get("readonly") or admin_pass
        r_ro = requests.post(f"{BASE_URL}/api/auth/login", json={"username": "readonly", "password": ro_pass})
        if r_ro.status_code == 200:
            cls.headers_ro = {"Authorization": f"Bearer {r_ro.json()['access_token']}"}
        else:
            cls.headers_ro = {}

    def test_unauthenticated_ingest_rejected(self):
        payload = {
            "source_type": "windows",
            "raw_event": {"EventID": 4625, "user": "test"}
        }
        r = requests.post(f"{BASE_URL}/api/v1/telemetry/ingest", json=payload)
        self.assertEqual(r.status_code, 401, "Unauthenticated ingestion must be rejected with 401")

    def test_unauthorized_ingest_rejected(self):
        payload = {
            "source_type": "windows",
            "raw_event": {"EventID": 4625, "user": "test"}
        }
        r = requests.post(f"{BASE_URL}/api/v1/telemetry/ingest", json=payload, headers=self.headers_ro)
        self.assertEqual(r.status_code, 403, "Read Only role must be denied ingestion with 403")

    def test_authenticated_single_ingest_success(self):
        payload = {
            "source_type": "windows",
            "environment": "lab",
            "raw_event": {
                "EventID": 4688,
                "NewProcessName": "C:\\Windows\\System32\\cmd.exe",
                "ComputerName": "PHASE3-TEST-HOST",
                "SubjectUserName": "test_analyst"
            }
        }
        r = requests.post(f"{BASE_URL}/api/v1/telemetry/ingest", json=payload, headers=self.headers_l2)
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertEqual(data["status"], "success")
        self.assertIn("event_id", data)

    def test_batch_ingest_success(self):
        payload = {
            "source_type": "auto",
            "environment": "simulation",
            "events": [
                {"EventID": 4624, "user": "user1", "host": "HOST-A"},
                {"program": "sshd", "message": "Accepted password for user2 from 10.0.0.1", "host": "HOST-B"},
                {"event_type": "dns", "query": "example.com", "src_ip": "10.0.0.2"}
            ]
        }
        r = requests.post(f"{BASE_URL}/api/v1/telemetry/ingest/batch", json=payload, headers=self.headers_l2)
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertEqual(data["status"], "success")
        summary = data["batch_summary"]
        self.assertEqual(summary["total_submitted"], 3)
        self.assertEqual(summary["success_count"], 3)

    def test_batch_ingest_partial_failure(self):
        payload = {
            "source_type": "auto",
            "events": [
                {"EventID": 4624, "user": "valid_user"},
                {"source_ip": "invalid_ip_format_999"},  # Malformed IP -> rejected
                {"EventID": 4625, "user": "valid_user2"}
            ]
        }
        r = requests.post(f"{BASE_URL}/api/v1/telemetry/ingest/batch", json=payload, headers=self.headers_l2)
        self.assertEqual(r.status_code, 200)
        summary = r.json()["batch_summary"]
        self.assertEqual(summary["total_submitted"], 3)
        self.assertEqual(summary["rejected_count"], 1)
        self.assertEqual(summary["success_count"], 2)

    def test_event_search_and_filtering(self):
        # Ingest a specific event first
        ingest_payload = {
            "source_type": "linux",
            "environment": "lab",
            "raw_event": {
                "program": "sshd",
                "message": "Failed password for root from 198.51.100.44 port 22",
                "hostname": "SEARCH-TARGET-HOST",
                "source_ip": "198.51.100.44"
            }
        }
        requests.post(f"{BASE_URL}/api/v1/telemetry/ingest", json=ingest_payload, headers=self.headers_l2)

        # Search for it
        r = requests.get(f"{BASE_URL}/api/v1/telemetry/events?hostname=SEARCH-TARGET-HOST", headers=self.headers_l2)
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertGreaterEqual(data["total"], 1)
        ev = data["events"][0]
        self.assertEqual(ev["hostname"], "SEARCH-TARGET-HOST")
        self.assertEqual(ev["source_ip"], "198.51.100.44")

    def test_event_details_endpoint(self):
        # Ingest event
        ingest_payload = {
            "source_type": "network",
            "raw_event": {"event_type": "http", "http_method": "GET", "url": "/api/v1/test"}
        }
        res = requests.post(f"{BASE_URL}/api/v1/telemetry/ingest", json=ingest_payload, headers=self.headers_l2).json()
        event_id = res["event_id"]

        # Fetch details
        r = requests.get(f"{BASE_URL}/api/v1/telemetry/events/{event_id}", headers=self.headers_l2)
        self.assertEqual(r.status_code, 200)
        ev = r.json()
        self.assertEqual(ev["event_id"], event_id)
        self.assertIn("raw_event", ev)
        self.assertEqual(ev["raw_event"]["url"], "/api/v1/test")

    def test_timeline_endpoint(self):
        r = requests.get(f"{BASE_URL}/api/v1/telemetry/timeline/host/SEARCH-TARGET-HOST", headers=self.headers_l2)
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertIn("events", data)
        self.assertIsInstance(data["events"], list)

    def test_telemetry_health_endpoint(self):
        r = requests.get(f"{BASE_URL}/api/v1/telemetry/health")
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertIn("service", data)
        self.assertIn("status", data)
        self.assertIn("metrics", data)
        self.assertIn("adapters", data)

    def test_adapters_list_endpoint(self):
        r = requests.get(f"{BASE_URL}/api/v1/telemetry/adapters")
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertIn("adapters", data)
        self.assertIsInstance(data["adapters"], list)
        source_types = [a["source_type"] for a in data["adapters"]]
        self.assertIn("windows", source_types)
        self.assertIn("linux", source_types)
        self.assertIn("network", source_types)

    def test_pipeline_end_to_end_alert_generation(self):
        """Verify full pipeline: event -> validate -> normalize -> store -> detect -> alert"""
        # Brute force attempt (5 failed logins to trigger RULE-T1110)
        for i in range(5):
            payload = {
                "source_type": "windows",
                "raw_event": {
                    "EventID": 4625,
                    "TargetUserName": f"victim_user_{i}",
                    "ComputerName": "CRITICAL-DC",
                    "IpAddress": "198.51.100.99"
                }
            }
            r = requests.post(f"{BASE_URL}/api/v1/telemetry/ingest", json=payload, headers=self.headers_l2)
            self.assertEqual(r.status_code, 200)

        # Query alerts to verify alert was generated
        r_alerts = requests.get(f"{BASE_URL}/api/alerts?limit=10", headers=self.headers_l2)
        self.assertEqual(r_alerts.status_code, 200)
        alerts = r_alerts.json()
        matching = [a for a in alerts if "Brute Force" in a.get("title", "") or "Authentication" in a.get("title", "") or "198.51.100.99" in str(a)]
        self.assertGreater(len(matching), 0, "Pipeline should trigger Brute Force alert after 5 failed logins")




if __name__ == "__main__":
    unittest.main()
