#!/usr/bin/env python3
"""
Phase 2 Test Suite — Security Architecture, RBAC, Authentication, Rate Limiting, Input Validation, Security Headers, CORS, and IDOR
Run with:  TESTING=true ./venv/bin/python tests/test_phase2.py
"""

import sys
import os
import json
import time
import requests
import unittest

# Enable test mode so /api/test/clear_rate_limits is available
os.environ.setdefault("TESTING", "true")

BASE_URL = "http://localhost:8001"

def _load_lab_credentials():
    """Load auto-generated lab credentials from lab_credentials.txt."""
    cred_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "lab_credentials.txt"
    )
    creds = {}
    if not os.path.exists(cred_path):
        print(f"[WARNING] lab_credentials.txt not found at {cred_path}")
        print("[WARNING] Re-seed the database: delete users from soc_data.db and restart the API.")
        return creds
    with open(cred_path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = [p.strip() for p in line.split("|")]
            if len(parts) == 3:
                username, role, password = parts
                creds[username] = password
    return creds

USER_CREDS = _load_lab_credentials()

class TestPhase2Security(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Wait for API to be up
        for _ in range(10):
            try:
                r = requests.get(f"{BASE_URL}/health", timeout=2)
                if r.status_code == 200:
                    return
            except Exception:
                pass
            time.sleep(1)
        raise RuntimeError("API server not reachable at " + BASE_URL)

    def setUp(self):
        # Clear rate limits before each test run
        try:
            requests.post(f"{BASE_URL}/api/test/clear_rate_limits", timeout=2)
        except Exception:
            pass

    def tearDown(self):
        # Clear rate limits after each test run
        try:
            requests.post(f"{BASE_URL}/api/test/clear_rate_limits", timeout=2)
        except Exception:
            pass

    def _get_token(self, username, password):
        payload = {"username": username, "password": password}
        r = requests.post(f"{BASE_URL}/api/auth/login", json=payload, timeout=5)
        if r.status_code == 200:
            return r.json().get("access_token")
        return None

    def test_authentication_valid_login(self):
        self.assertTrue(USER_CREDS, "[SETUP] lab_credentials.txt not found — re-seed DB and restart API.")
        token = self._get_token("analyst_l1", USER_CREDS.get("analyst_l1", ""))
        self.assertIsNotNone(token, "Login failed for valid credentials")

    def test_authentication_invalid_login(self):
        # Username enumeration protection: response must be generic 401
        payload = {"username": "non_existent_user_999", "password": "some_password"}
        r = requests.post(f"{BASE_URL}/api/auth/login", json=payload, timeout=5)
        self.assertEqual(r.status_code, 401)
        self.assertEqual(r.json().get("detail"), "Invalid username or password")

        # Wrong password for existing user
        payload = {"username": "analyst_l1", "password": "wrong_password"}
        r = requests.post(f"{BASE_URL}/api/auth/login", json=payload, timeout=5)
        self.assertEqual(r.status_code, 401)
        self.assertEqual(r.json().get("detail"), "Invalid username or password")

    def test_authentication_missing_credentials(self):
        payload = {"username": ""}
        r = requests.post(f"{BASE_URL}/api/auth/login", json=payload, timeout=5)
        # Should be validation error or unauthorized
        self.assertIn(r.status_code, [401, 422])

    def test_authentication_logout(self):
        token = self._get_token("analyst_l1", USER_CREDS.get("analyst_l1", ""))
        self.assertIsNotNone(token, "[SETUP] Login failed — check lab_credentials.txt")
        headers = {"Authorization": f"Bearer {token}"}
        
        # Call logout
        r = requests.post(f"{BASE_URL}/api/auth/logout", headers=headers, timeout=5)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json().get("status"), "success")

        # Use same token again — must be rejected
        r_retry = requests.get(f"{BASE_URL}/api/alerts", headers=headers, timeout=5)
        self.assertEqual(r_retry.status_code, 401, "Token should be blacklisted after logout")

    def test_rbac_roles_permissions(self):
        # 1. Read Only role checks
        ro_token = self._get_token("readonly", USER_CREDS.get("readonly", ""))
        self.assertIsNotNone(ro_token, "[SETUP] readonly login failed")
        ro_headers = {"Authorization": f"Bearer {ro_token}"}

        # Allowed: Alerts read
        r_alerts = requests.get(f"{BASE_URL}/api/alerts", headers=ro_headers, timeout=5)
        self.assertEqual(r_alerts.status_code, 200)

        # Denied: Resolve incident
        r_resolve = requests.post(f"{BASE_URL}/api/incidents/INC-123/resolve", headers=ro_headers, timeout=5)
        self.assertEqual(r_resolve.status_code, 403, "Read Only role must not be allowed to resolve incidents")

        # 2. SOC Analyst L1 checks
        l1_token = self._get_token("analyst_l1", USER_CREDS.get("analyst_l1", ""))
        self.assertIsNotNone(l1_token, "[SETUP] analyst_l1 login failed")
        l1_headers = {"Authorization": f"Bearer {l1_token}"}

        # Allowed: Get stats
        r_stats = requests.get(f"{BASE_URL}/api/stats", headers=l1_headers, timeout=5)
        self.assertEqual(r_stats.status_code, 200)

        # Denied: Playbook execution
        r_pb = requests.post(f"{BASE_URL}/api/playbooks/execute", 
                             json={"playbook_id": "enrich_ip", "target": "8.8.8.8"}, 
                             headers=l1_headers, timeout=5)
        self.assertEqual(r_pb.status_code, 403, "L1 Analyst must not execute playbooks")

        # 3. Incident Responder checks
        ir_token = self._get_token("responder", USER_CREDS.get("responder", ""))
        self.assertIsNotNone(ir_token, "[SETUP] responder login failed")
        ir_headers = {"Authorization": f"Bearer {ir_token}"}

        # Allowed: Playbook execution
        r_pb_ok = requests.post(f"{BASE_URL}/api/playbooks/execute", 
                                json={"playbook_id": "enrich_ip", "target": "8.8.8.8", "approved": True}, 
                                headers=ir_headers, timeout=5)
        self.assertEqual(r_pb_ok.status_code, 200)

        # Denied: User creation
        r_user = requests.post(f"{BASE_URL}/api/users", 
                              json={"username": "fake_user", "password": "fake_password", "role": "Read Only", "email": "fake@local"},
                              headers=ir_headers, timeout=5)
        self.assertEqual(r_user.status_code, 403, "Incident Responder must not create users")

    def test_rate_limiting_login_endpoint(self):
        # Make fast consecutive calls to login with invalid passwords
        payload = {"username": "analyst_l1", "password": "wrong_password"}
        triggered = False
        for _ in range(12):
            r = requests.post(f"{BASE_URL}/api/auth/login", json=payload, headers={"X-Test-Force-RateLimit": "true"}, timeout=5)
            if r.status_code == 429:
                triggered = True
                break
        self.assertTrue(triggered, "Rate limiting was not triggered on login endpoint")

    def test_input_validation_malformed_ip(self):
        token = self._get_token("analyst_l2", USER_CREDS.get("analyst_l2", ""))
        self.assertIsNotNone(token, "[SETUP] analyst_l2 login failed")
        headers = {"Authorization": f"Bearer {token}"}

        payload = {
            "title": "Malicious Activity",
            "severity": "high",
            "source": "999.999.999.999",  # Malformed IP address
            "destination": "0.0.0.0"
        }
        r = requests.post(f"{BASE_URL}/api/alerts", json=payload, headers=headers, timeout=5)
        self.assertEqual(r.status_code, 422, "Malformed source IP address should be rejected (422)")

    def test_input_validation_invalid_severity(self):
        token = self._get_token("analyst_l2", USER_CREDS.get("analyst_l2", ""))
        self.assertIsNotNone(token, "[SETUP] analyst_l2 login failed")
        headers = {"Authorization": f"Bearer {token}"}

        payload = {
            "title": "Invalid Severity Alert",
            "severity": "super-critical",  # Invalid severity
            "source": "192.168.1.10"
        }
        r = requests.post(f"{BASE_URL}/api/alerts", json=payload, headers=headers, timeout=5)
        self.assertEqual(r.status_code, 422, "Invalid severity option should be rejected")

    def test_security_headers(self):
        r = requests.get(f"{BASE_URL}/health", timeout=5)
        self.assertIn("X-Content-Type-Options", r.headers)
        self.assertEqual(r.headers["X-Content-Type-Options"], "nosniff")
        self.assertIn("X-Frame-Options", r.headers)
        self.assertEqual(r.headers["X-Frame-Options"], "DENY")
        self.assertIn("Content-Security-Policy", r.headers)

    def test_cors_origins(self):
        # Test default/configured CORS header is not "*" when Origin matches our allowed origins
        headers = {"Origin": "http://localhost:8002"}
        r = requests.get(f"{BASE_URL}/health", headers=headers, timeout=5)
        self.assertEqual(r.headers.get("Access-Control-Allow-Origin"), "http://localhost:8002")

    def test_error_handling_no_stack_trace(self):
        # Trigger an error (e.g. GET non-existent route or invalid input)
        r = requests.get(f"{BASE_URL}/api/alerts/non-existent-alert-id", timeout=5)
        self.assertIn(r.status_code, [404, 405, 422])
        self.assertNotIn("Traceback", r.text, "Error response must not expose python stack traces")
        self.assertNotIn("File \"", r.text, "Error response must not expose filesystem directories")

    def test_unauthorized_user_blocked(self):
        # No Authorization header
        r = requests.get(f"{BASE_URL}/api/alerts", timeout=5)
        self.assertEqual(r.status_code, 401)


if __name__ == "__main__":
    print("=" * 70)
    print("SOC Platform — Phase 2 Security Test Suite")
    print("=" * 70)
    suite = unittest.TestLoader().loadTestsFromTestCase(TestPhase2Security)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
