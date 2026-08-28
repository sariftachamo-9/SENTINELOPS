#!/usr/bin/env python3
"""
Phase 1 Test Suite — Stability, Bug Fixes, Database Integrity, API/Frontend
Run with:  ./venv/bin/python tests/test_phase1.py
All tests must pass before proceeding to Phase 2.
"""

import sys
import os
import json
import time
import sqlite3
import requests
import unittest

BASE_URL = "http://localhost:8001"
DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "soc_data.db")

REQUIRED_TABLES = [
    "alerts", "incidents", "events", "assets", "users",
    "audit_logs", "threat_intel", "detection_rules", "playbooks", "cases"
]

REQUIRED_ALERT_COLUMNS = [
    "id", "title", "severity", "description", "source", "destination",
    "timestamp", "indicators", "status", "confidence", "risk_score",
    "affected_asset", "affected_user", "mitre_tactic", "mitre_technique",
    "detection_rule", "first_seen", "last_seen", "occurrence_count",
    "assignee", "evidence", "analyst_notes", "processed"
]

REQUIRED_INCIDENT_COLUMNS = [
    "id", "title", "severity", "status", "created_at", "alert_id",
    "description", "resolved_at", "priority", "category"
]


class TestDatabaseIntegrity(unittest.TestCase):

    def setUp(self):
        self.conn = sqlite3.connect(DB_PATH)
        self.conn.row_factory = sqlite3.Row

    def tearDown(self):
        self.conn.close()

    def test_all_required_tables_exist(self):
        c = self.conn.cursor()
        c.execute("SELECT name FROM sqlite_master WHERE type='table'")
        existing = {r["name"] for r in c.fetchall()}
        for table in REQUIRED_TABLES:
            with self.subTest(table=table):
                self.assertIn(table, existing, f"Missing table: {table}")

    def test_alerts_table_columns(self):
        c = self.conn.cursor()
        c.execute("PRAGMA table_info(alerts)")
        cols = {r["name"] for r in c.fetchall()}
        for col in REQUIRED_ALERT_COLUMNS:
            with self.subTest(col=col):
                self.assertIn(col, cols, f"Missing column alerts.{col}")

    def test_incidents_table_columns(self):
        c = self.conn.cursor()
        c.execute("PRAGMA table_info(incidents)")
        cols = {r["name"] for r in c.fetchall()}
        for col in REQUIRED_INCIDENT_COLUMNS:
            with self.subTest(col=col):
                self.assertIn(col, cols, f"Missing column incidents.{col}")

    def test_events_table_exists_with_schema(self):
        c = self.conn.cursor()
        c.execute("PRAGMA table_info(events)")
        cols = {r["name"] for r in c.fetchall()}
        for col in ["event_id", "timestamp", "source_type", "source_ip", "destination_ip", "severity", "environment"]:
            with self.subTest(col=col):
                self.assertIn(col, cols, f"Missing column events.{col}")

    def test_db_has_existing_data(self):
        c = self.conn.cursor()
        c.execute("SELECT COUNT(*) FROM alerts")
        count = c.fetchone()[0]
        self.assertGreater(count, 0, "Alerts table should have data from previous runs")

    def test_no_null_severity_alerts(self):
        c = self.conn.cursor()
        c.execute("SELECT COUNT(*) FROM alerts WHERE severity IS NULL OR severity = ''")
        count = c.fetchone()[0]
        self.assertEqual(count, 0, f"{count} alerts have NULL or empty severity")

    def test_indexes_exist(self):
        c = self.conn.cursor()
        c.execute("SELECT name FROM sqlite_master WHERE type='index'")
        indexes = {r["name"] for r in c.fetchall()}
        for idx in ["idx_events_ts", "idx_alerts_status", "idx_incidents_status"]:
            with self.subTest(idx=idx):
                self.assertIn(idx, indexes, f"Missing index: {idx}")


class TestAPIEndpoints(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Wait for API to be up (max 10s)
        for _ in range(10):
            try:
                r = requests.get(f"{BASE_URL}/health", timeout=2)
                if r.status_code == 200:
                    break
            except Exception:
                pass
            time.sleep(1)
        else:
            raise RuntimeError("API server not reachable at " + BASE_URL)

        # Authenticate as admin to get a valid token
        admin_pass = os.getenv("LAB_ADMIN_PASSWORD", "soc-lab-admin-change-me")
        r = requests.post(f"{BASE_URL}/api/auth/login", json={"username": "admin", "password": admin_pass}, timeout=5)
        if r.status_code == 200:
            cls.token = r.json().get("access_token")
            cls.headers = {"Authorization": f"Bearer {cls.token}"}
        else:
            cls.token = None
            cls.headers = {}

    def setUp(self):
        # Clear rate limiter before each test so that login limit checks in test_phase1 do not trigger 429
        try:
            requests.post(f"{BASE_URL}/api/test/clear_rate_limits", timeout=2)
        except Exception:
            pass

    def test_health_endpoint(self):
        r = requests.get(f"{BASE_URL}/health", timeout=5)
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertEqual(data["status"], "ok")
        self.assertIn("timestamp", data)

    def test_root_endpoint(self):
        r = requests.get(f"{BASE_URL}/", timeout=5)
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertIn("service", data)

    def test_stats_endpoint(self):
        r = requests.get(f"{BASE_URL}/api/stats", headers=self.headers, timeout=5)
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertIn("total_alerts", data)
        self.assertIn("total_incidents", data)
        self.assertIsInstance(data["total_alerts"], int)

    def test_alerts_returns_list(self):
        r = requests.get(f"{BASE_URL}/api/alerts?limit=5", headers=self.headers, timeout=5)
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertIsInstance(data, list, "GET /api/alerts must return a list")
        if data:
            alert = data[0]
            self.assertIn("id", alert)
            self.assertIn("title", alert)
            self.assertIn("severity", alert)

    def test_create_alert_post(self):
        payload = {
            "title": "Phase1 Test Alert",
            "severity": "medium",
            "description": "Created by Phase 1 test suite",
            "source": "127.0.0.1",
            "environment": "lab"
        }
        r = requests.post(f"{BASE_URL}/api/alerts", json=payload, headers=self.headers, timeout=5)
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertEqual(data["status"], "success")
        self.assertIn("alert_id", data)

    def test_incidents_returns_list(self):
        r = requests.get(f"{BASE_URL}/api/incidents?limit=5", headers=self.headers, timeout=5)
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertIsInstance(data, list, "GET /api/incidents must return a list")

    def test_assets_endpoint(self):
        r = requests.get(f"{BASE_URL}/api/assets", headers=self.headers, timeout=5)
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertIsInstance(data, list)
        self.assertGreater(len(data), 0, "Assets should be pre-seeded")

    def test_soc_health_endpoint(self):
        r = requests.get(f"{BASE_URL}/api/soc/health", headers=self.headers, timeout=5)
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertIn("services", data)
        self.assertIn("overall_status", data)
        # Verify no fake "ONLINE" for unconfigured integrations
        for svc in data["services"]:
            if svc["name"] in ["Wazuh", "Elastic/OpenSearch", "Suricata IDS", "Zeek NSM"]:
                self.assertNotEqual(
                    svc["status"], "ONLINE",
                    f"{svc['name']} should not show ONLINE when not configured"
                )

    def test_mitre_coverage_endpoint(self):
        r = requests.get(f"{BASE_URL}/api/mitre/coverage", headers=self.headers, timeout=5)
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertIn("coverage_percentage", data)
        self.assertIn("matrix", data)
        self.assertIsInstance(data["coverage_percentage"], float)

    def test_playbooks_endpoint(self):
        r = requests.get(f"{BASE_URL}/api/playbooks", headers=self.headers, timeout=5)
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertIsInstance(data, list)
        self.assertGreater(len(data), 0)

    def test_resolve_incident_endpoint(self):
        # Create an incident first
        r = requests.post(f"{BASE_URL}/api/incidents", json={
            "title": "Phase1 Test Incident",
            "severity": "high",
            "description": "Created by Phase 1 test"
        }, headers=self.headers, timeout=5)
        self.assertEqual(r.status_code, 200)
        inc_id = r.json()["incident_id"]
        # Now resolve it
        r2 = requests.post(f"{BASE_URL}/api/incidents/{inc_id}/resolve", headers=self.headers, timeout=5)
        self.assertEqual(r2.status_code, 200)
        self.assertEqual(r2.json()["status"], "success")

    def test_login_requires_env_password(self):
        # Attempt login with empty password should fail
        r = requests.post(f"{BASE_URL}/api/auth/login",
                          json={"username": "admin", "password": ""},
                          timeout=5)
        self.assertIn(r.status_code, [401, 422],
                      "Login with empty password should be rejected")

    def test_login_rejects_old_hardcoded_passwords(self):
        # These were previously hardcoded — must now be rejected
        for bad_pass in ["admin", "admin123", "password"]:
            r = requests.post(f"{BASE_URL}/api/auth/login",
                              json={"username": "admin", "password": bad_pass},
                              timeout=5)
            self.assertEqual(r.status_code, 401,
                             f"Password '{bad_pass}' must not be accepted (was hardcoded)")

    def test_telemetry_ingest_windows_event(self):
        payload = {
            "source_type": "windows",
            "raw_event": {
                "EventID": 4625,
                "user": "testuser",
                "host": "TESTHOST-01",
                "description": "Failed login attempt"
            }
        }
        r = requests.post(f"{BASE_URL}/api/v1/telemetry/ingest", json=payload, headers=self.headers, timeout=10)
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertEqual(data["status"], "success")
        self.assertIn("event_id", data)
        self.assertIn("alerts_triggered", data)


class TestModuleSyntax(unittest.TestCase):

    def _check_module(self, module_path):
        import py_compile
        try:
            py_compile.compile(module_path, doraise=True)
        except py_compile.PyCompileError as e:
            self.fail(f"Syntax error in {module_path}: {e}")

    def test_syntax_api(self):
        self._check_module("src/api.py")

    def test_syntax_database(self):
        self._check_module("src/database.py")

    def test_syntax_web_ui(self):
        self._check_module("src/web_ui.py")

    def test_syntax_security(self):
        self._check_module("src/security.py")

    def test_syntax_alert_rules(self):
        self._check_module("src/alert_rules.py")

    def test_syntax_ml_detector(self):
        self._check_module("src/ml_detector.py")

    def test_syntax_risk_engine(self):
        self._check_module("src/risk_engine.py")

    def test_syntax_telemetry_normalizer(self):
        self._check_module("src/telemetry_normalizer.py")

    def test_syntax_threat_intel(self):
        target = "src/threat_intel.py" if os.path.exists("src/threat_intel.py") else "src/threat_intel/__init__.py"
        self._check_module(target)

    def test_syntax_correlation_engine(self):
        self._check_module("src/correlation_engine.py")

    def test_syntax_notifications(self):
        self._check_module("src/notifications.py")


class TestFrontendReachable(unittest.TestCase):

    def test_web_ui_serves_html(self):
        try:
            r = requests.get("http://localhost:8002/", timeout=5)
            self.assertEqual(r.status_code, 200)
            self.assertIn("text/html", r.headers.get("content-type", ""))
            self.assertIn("SOC", r.text, "Web UI should contain 'SOC' in page title area")
        except requests.exceptions.ConnectionError:
            self.skipTest("Web UI not running on port 8002 — start with production_start.sh")


if __name__ == "__main__":
    print("=" * 70)
    print("SOC Platform — Phase 1 Test Suite")
    print("=" * 70)
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    suite.addTests(loader.loadTestsFromTestCase(TestModuleSyntax))
    suite.addTests(loader.loadTestsFromTestCase(TestDatabaseIntegrity))
    suite.addTests(loader.loadTestsFromTestCase(TestAPIEndpoints))
    suite.addTests(loader.loadTestsFromTestCase(TestFrontendReachable))
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
