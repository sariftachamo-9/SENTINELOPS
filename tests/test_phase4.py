"""
SOC Lab — Phase 4 Real SOC Integrations & Telemetry Verification Suite
========================================================================
Validates Phase 4 requirements:
1. Vendor adapters (Wazuh, Suricata, Zeek, Syslog).
2. Integration Health Management System (ONLINE, OFFLINE, SIMULATION, NOT_CONFIGURED).
3. Search Backend Abstraction (EventSearchBackend, SQLiteSearchBackend, OpenSearchBackend).
4. Live vs Simulation telemetry segregation (source_mode).
5. End-to-end pipeline ingestion flow.
"""

import os
import pytest
from fastapi.testclient import TestClient

# Enforce test mode
os.environ["TESTING"] = "true"

from src.api import app
from src.security import generate_token
from src.telemetry.pipeline import TelemetryPipeline
from src.telemetry.integration_health import IntegrationHealthManager
from src.telemetry.search_backend import SQLiteSearchBackend, OpenSearchBackend
from src.telemetry.adapters.wazuh import WazuhAdapter
from src.telemetry.adapters.suricata import SuricataAdapter
from src.telemetry.adapters.zeek import ZeekAdapter
from src.telemetry.schema import NormalizedEvent

client = TestClient(app)


def get_token(role="SOC Analyst L2"):
    return generate_token("test_analyst", role)


def auth_headers(role="SOC Analyst L2"):
    token = get_token(role)
    return {"Authorization": f"Bearer {token}"}


class TestPhase4VendorAdapters:

    def test_wazuh_adapter(self):
        adapter = WazuhAdapter()
        raw = {
            "agent": {"id": "001", "name": "win-agent-01", "ip": "10.0.0.15"},
            "rule": {
                "id": "5715",
                "level": 10,
                "description": "SSHD authentication failed.",
                "mitre": {"id": ["T1110"], "tactic": ["credential-access"]}
            },
            "data": {"srcip": "192.168.1.50", "srcuser": "root"},
            "source_mode": "live"
        }
        assert adapter.can_handle(raw) is True
        norm = adapter.normalize(raw, environment="lab")
        assert norm.source_type == "wazuh"
        assert norm.hostname == "win-agent-01"
        assert norm.source_ip == "192.168.1.50"
        assert norm.username == "root"
        assert norm.severity == "high"
        assert norm.source_mode == "live"
        assert norm.simulation is False

    def test_suricata_adapter(self):
        adapter = SuricataAdapter()
        raw = {
            "event_type": "alert",
            "src_ip": "1.2.3.4",
            "dest_ip": "10.0.0.20",
            "src_port": 44332,
            "dest_port": 80,
            "proto": "TCP",
            "alert": {
                "action": "allowed",
                "category": "Attempted Administrator Privilege Gain",
                "severity": 1,
                "signature": "ET EXPLOIT Apache Log4j RCE",
                "signature_id": 2034334
            },
            "host": "net-sensor-01",
            "source_mode": "live"
        }
        assert adapter.can_handle(raw) is True
        norm = adapter.normalize(raw, environment="lab")
        assert norm.source_type == "suricata"
        assert norm.severity == "high"
        assert norm.event_code == "2034334"
        assert norm.source_ip == "1.2.3.4"
        assert norm.destination_ip == "10.0.0.20"

    def test_zeek_adapter(self):
        adapter = ZeekAdapter()
        raw = {
            "_path": "conn",
            "id.orig_h": "10.0.0.50",
            "id.resp_h": "8.8.8.8",
            "id.orig_p": 52140,
            "id.resp_p": 53,
            "proto": "udp",
            "conn_state": "SF",
            "node": "zeek-sensor-01",
            "source_mode": "live"
        }
        assert adapter.can_handle(raw) is True
        norm = adapter.normalize(raw, environment="lab")
        assert norm.source_type == "zeek"
        assert norm.event_type == "zeek_conn"
        assert norm.source_ip == "10.0.0.50"
        assert norm.destination_ip == "8.8.8.8"


class TestPhase4IntegrationHealth:

    def test_integration_health_manager(self):
        mgr = IntegrationHealthManager()
        health_list = mgr.get_all_health()
        assert len(health_list) >= 6

        # Check default status is NOT_CONFIGURED (no fake ONLINE)
        wazuh_health = mgr.get_integration_health("wazuh")
        assert wazuh_health["status"] in ("NOT_CONFIGURED", "OFFLINE")

        # Process a live event -> status should become ONLINE
        mgr.record_event_processed("wazuh", success=True, latency_ms=12.5, source_mode="live")
        updated = mgr.get_integration_health("wazuh")
        assert updated["status"] == "ONLINE"
        assert updated["events_received"] == 1
        assert updated["events_processed"] == 1

        # Process a simulation event for suricata -> status should be SIMULATION if not ONLINE
        mgr.record_event_processed("suricata", success=True, latency_ms=5.0, source_mode="simulation")
        suri_health = mgr.get_integration_health("suricata")
        assert suri_health["status"] in ("SIMULATION", "ONLINE")

    def test_integration_health_api(self):
        res = client.get("/api/v1/integrations/health", headers=auth_headers())
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "success"
        assert isinstance(data["integrations"], list)
        assert len(data["integrations"]) >= 6


class TestPhase4SearchBackendAbstraction:

    def test_sqlite_search_backend(self):
        backend = SQLiteSearchBackend()
        events, total = backend.search_events({"source_mode": "live"}, limit=10)
        assert isinstance(events, list)
        assert isinstance(total, int)

    def test_opensearch_backend_fallback(self):
        backend = OpenSearchBackend()
        events, total = backend.search_events({"source_mode": "live"}, limit=10)
        assert isinstance(events, list)
        assert isinstance(total, int)


class TestPhase4LiveVsSimulatedSegregation:

    def test_live_telemetry_ingestion(self):
        raw_live = {
            "source_type": "linux",
            "message": "Failed password for root from 192.168.1.100 port 22 ssh2",
            "hostname": "linux-lab-vm",
            "source_ip": "192.168.1.100",
            "username": "root",
            "source_mode": "live"
        }
        res = client.post(
            "/api/v1/telemetry/ingest",
            json={
                "source_type": "linux",
                "raw_event": raw_live,
                "environment": "lab",
                "source_mode": "live"
            },
            headers=auth_headers()
        )
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "success"

        # Search specifically for live events
        search_res = client.get("/api/v1/telemetry/events?source_mode=live", headers=auth_headers())
        assert search_res.status_code == 200
        events = search_res.json()["events"]
        assert any(e["source_mode"] == "live" for e in events)

    def test_vendor_webhooks(self):
        # Wazuh Webhook
        wazuh_res = client.post(
            "/api/v1/integrations/wazuh/ingest",
            json={
                "rule": {"id": "5710", "level": 8, "description": "Attempt to login using failed password"},
                "agent": {"name": "WIN-LAB-VM01", "id": "002"},
                "source_mode": "live"
            },
            headers=auth_headers()
        )
        assert wazuh_res.status_code == 200
        assert wazuh_res.json()["status"] == "success"

        # Suricata Webhook
        suricata_res = client.post(
            "/api/v1/integrations/suricata/ingest",
            json={
                "event_type": "alert",
                "alert": {"signature": "ET SCAN Nmap Scripting Engine", "signature_id": 2009582, "severity": 2},
                "src_ip": "10.0.0.99",
                "dest_ip": "10.0.0.45",
                "host": "net-sensor-01",
                "source_mode": "live"
            },
            headers=auth_headers()
        )
        assert suricata_res.status_code == 200
        assert suricata_res.json()["status"] == "success"

        # Zeek Webhook
        zeek_res = client.post(
            "/api/v1/integrations/zeek/ingest",
            json={
                "_path": "http",
                "host": "malicious-domain.com",
                "uri": "/payload.bin",
                "id.orig_h": "10.0.0.45",
                "id.resp_h": "185.220.101.5",
                "source_mode": "live"
            },
            headers=auth_headers()
        )
        assert zeek_res.status_code == 200
        assert zeek_res.json()["status"] == "success"
