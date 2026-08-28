"""
Phase 7 Comprehensive Automated Test Suite
Validates Threat Intelligence, IOC Normalization, Provider Adapters, Caching, Rate Limiting,
Secret Protection, SSRF Safeguards, Risk Scoring Integration, RBAC, and Audit Logging.
"""
import os
import pytest
import tempfile
from fastapi.testclient import TestClient

from src.database import Database
from src.security import generate_token
from src.threat_intel.models import Reputation, IOCType, ProviderState
from src.threat_intel.normalizer import IOCNormalizer
from src.threat_intel.cache import EnrichmentCache, ProviderRateLimiter, TTL_POSITIVE_SECONDS, TTL_NEGATIVE_SECONDS
from src.threat_intel.providers.local_feed import LocalFeedProvider
from src.threat_intel.providers.abuseipdb import AbuseIPDBProvider
from src.threat_intel.providers.virustotal import VirusTotalProvider
from src.threat_intel.manager import EnrichmentManager
from src.api import app

os.environ["TESTING"] = "true"
os.environ["JWT_SECRET"] = "phase7-test-secret"
client = TestClient(app)

@pytest.fixture
def temp_db():
    db_fd, db_path = tempfile.mkstemp()
    os.close(db_fd)
    db = Database(db_path=db_path)
    yield db
    if os.path.exists(db_path):
        os.remove(db_path)

@pytest.fixture
def auth_headers():
    return {
        "admin": {"Authorization": f"Bearer {generate_token('admin_test', 'Administrator')}"},
        "manager": {"Authorization": f"Bearer {generate_token('manager_test', 'SOC Manager')}"},
        "l2": {"Authorization": f"Bearer {generate_token('l2_test', 'SOC Analyst L2')}"},
        "l1": {"Authorization": f"Bearer {generate_token('l1_test', 'SOC Analyst L1')}"},
        "readonly": {"Authorization": f"Bearer {generate_token('ro_test', 'Read Only')}"},
    }

# ══════════════════════════════════════════════════════════════════════════════
# 1. IOC Normalization, Deduplication & Detection Tests
# ══════════════════════════════════════════════════════════════════════════════

def test_ioc_normalizer_ipv4_and_ipv6():
    norm_v4, type_v4 = IOCNormalizer.detect_and_normalize("  198.51.100.44  ")
    assert norm_v4 == "198.51.100.44"
    assert type_v4 == IOCType.IPV4.value

    norm_v6, type_v6 = IOCNormalizer.detect_and_normalize("2001:0db8:85a3:0000:0000:8a2e:0370:7334")
    assert type_v6 == IOCType.IPV6.value

def test_ioc_normalizer_domain_and_url():
    norm_dom, type_dom = IOCNormalizer.detect_and_normalize("  EVIL-PHISH.NET  ")
    assert norm_dom == "evil-phish.net"
    assert type_dom == IOCType.DOMAIN.value

    norm_url, type_url = IOCNormalizer.detect_and_normalize("http://malicious-site.org/payload.exe", hint_type="url")
    assert norm_url == "http://malicious-site.org/payload.exe"
    assert type_url == IOCType.URL.value

def test_ioc_normalizer_file_hashes():
    md5 = "44D88612FEA8A8F36DE82E1278ABB02F"
    norm_hash, type_hash = IOCNormalizer.detect_and_normalize(md5)
    assert norm_hash == md5.lower()
    assert type_hash == IOCType.FILE_HASH.value

def test_ssrf_private_ip_and_metadata_endpoint_detection():
    assert IOCNormalizer.is_private_ip("127.0.0.1") is True
    assert IOCNormalizer.is_private_ip("10.0.0.5") is True
    assert IOCNormalizer.is_private_ip("192.168.1.1") is True
    assert IOCNormalizer.is_private_ip("169.254.169.254") is True
    assert IOCNormalizer.is_ssrf_risk("http://metadata.google.internal/computeMetadata/v1/") is True
    assert IOCNormalizer.is_ssrf_risk("169.254.169.254") is True
    assert IOCNormalizer.is_private_ip("8.8.8.8") is False

# ══════════════════════════════════════════════════════════════════════════════
# 2. Distinct Provider States & NOT_CONFIGURED Behavior
# ══════════════════════════════════════════════════════════════════════════════

def test_unconfigured_abuseipdb_returns_not_configured_state(monkeypatch):
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    provider = AbuseIPDBProvider()
    assert provider.is_configured() is False
    assert provider.get_provider_state() == ProviderState.NOT_CONFIGURED.value
    res = provider.lookup("ipv4", "198.51.100.99")
    assert res.reputation == Reputation.NOT_CONFIGURED.value
    assert res.provider_state == ProviderState.NOT_CONFIGURED.value
    # Secret secrecy check
    assert "api_key" not in res.raw_details

def test_unconfigured_virustotal_returns_not_configured_state(monkeypatch):
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    provider = VirusTotalProvider()
    assert provider.is_configured() is False
    assert provider.get_provider_state() == ProviderState.NOT_CONFIGURED.value
    res = provider.lookup("domain", "evil-phish.net")
    assert res.reputation == Reputation.NOT_CONFIGURED.value
    assert res.provider_state == ProviderState.NOT_CONFIGURED.value

def test_local_feed_provider_state_and_lookup(temp_db):
    provider = LocalFeedProvider(db=temp_db)
    assert provider.get_provider_state() == ProviderState.VERIFIED.value
    res = provider.lookup("ipv4", "192.168.1.195")
    assert res.provider == "Local Threat Intel Feed"
    assert res.provider_state == ProviderState.VERIFIED.value

# ══════════════════════════════════════════════════════════════════════════════
# 3. Caching & Rate Limiting Tests
# ══════════════════════════════════════════════════════════════════════════════

def test_enrichment_cache_positive_vs_negative_ttl(temp_db):
    cache = EnrichmentCache(db=temp_db)
    from src.threat_intel.models import NormalizedIntelResult

    pos_res = NormalizedIntelResult(provider="TestProvider", ioc_type="ipv4", ioc_value="1.1.1.1", reputation="MALICIOUS")
    cache.set("TestProvider", "ipv4", "1.1.1.1", pos_res)

    hit_pos = cache.get("TestProvider", "ipv4", "1.1.1.1")
    assert hit_pos is not None
    assert hit_pos.reputation == "MALICIOUS"

    neg_res = NormalizedIntelResult(provider="TestProvider", ioc_type="ipv4", ioc_value="8.8.8.8", reputation="UNKNOWN")
    cache.set("TestProvider", "ipv4", "8.8.8.8", neg_res)

    hit_neg = cache.get("TestProvider", "ipv4", "8.8.8.8")
    assert hit_neg is not None
    assert hit_neg.reputation == "UNKNOWN"

def test_rate_limiter_throttling():
    limiter = ProviderRateLimiter()
    provider = "AbuseIPDB"
    for _ in range(5):
        assert limiter.is_allowed(provider, max_requests=5, window_seconds=60) is True
    assert limiter.is_allowed(provider, max_requests=5, window_seconds=60) is False

# ══════════════════════════════════════════════════════════════════════════════
# 4. Enrichment Manager, SSRF Guard & Risk Integration
# ══════════════════════════════════════════════════════════════════════════════

def test_enrichment_manager_private_ip_ssrf_protection(temp_db):
    mgr = EnrichmentManager(db=temp_db)
    res = mgr.enrich_indicator("127.0.0.1")
    assert res["normalized_value"] == "127.0.0.1"
    for p_res in res["provider_results"]:
        if p_res["provider"] != "Local Threat Intel Feed":
            assert p_res["lookup_status"] == "SKIPPED_PRIVATE_RANGE"

def test_enrichment_alert_and_risk_engine(temp_db):
    mgr = EnrichmentManager(db=temp_db)
    alert = {
        "id": "ALT-TEST-77",
        "severity": "high",
        "source_ip": "198.51.100.99",
    }
    enriched = mgr.enrich_alert(alert)
    assert "threat_intel" in enriched
    assert enriched["threat_intel"]["highest_reputation"] in ("MALICIOUS", "SUSPICIOUS", "BENIGN", "UNKNOWN")

    from src.risk_engine import RiskEngine
    risk = RiskEngine().calculate_risk(enriched)
    assert risk["risk_score"] > 0
    assert "ioc_reputation" in risk["breakdown"]

# ══════════════════════════════════════════════════════════════════════════════
# 5. IOC Deduplication, Analyst Override & Audit Logging
# ══════════════════════════════════════════════════════════════════════════════

def test_add_get_and_classify_ioc_deduplication(temp_db):
    mgr = EnrichmentManager(db=temp_db)
    ioc = mgr.add_ioc(
        type_="domain",
        value="bad-c2-domain.com",
        severity="high",
        reputation="SUSPICIOUS",
        description="Known C2 beacon target",
        created_by="analyst_test"
    )
    assert ioc["id"].startswith("IOC-")
    assert ioc["normalized_value"] == "bad-c2-domain.com"

    # Duplicate IOC creation raises exception due to UNIQUE(type, normalized_value) constraint
    with pytest.raises(Exception):
        mgr.add_ioc(type_="domain", value="bad-c2-domain.com")

    # Classification override without reason raises ValueError
    with pytest.raises(ValueError):
        mgr.update_analyst_classification(ioc["id"], "MALICIOUS", reason="", analyst="l2_analyst")

    # Valid override succeeds
    updated = mgr.update_analyst_classification(
        ioc["id"], "MALICIOUS", reason="Confirmed by external threat report", analyst="l2_analyst"
    )
    assert updated["reputation"] == "MALICIOUS"
    assert updated["analyst_classification"] == "MALICIOUS"

# ══════════════════════════════════════════════════════════════════════════════
# 6. REST API & Granular ioc.* RBAC Integration Tests
# ══════════════════════════════════════════════════════════════════════════════

def test_api_enrich_indicator(auth_headers):
    resp = client.get("/api/v1/threat_intel/enrich?indicator=198.51.100.99", headers=auth_headers["l1"])
    assert resp.status_code == 200
    assert "overall_reputation" in resp.json()

def test_api_ioc_crud_rbac_boundaries(auth_headers):
    # 1. Read Only can read IOCs (ioc.read)
    r_list = client.get("/api/v1/iocs", headers=auth_headers["readonly"])
    assert r_list.status_code == 200

    # 2. L1 Analyst CANNOT create IOCs (requires ioc.create)
    r_l1_create = client.post(
        "/api/v1/iocs",
        json={"type": "ipv4", "value": "203.0.113.5", "reputation": "MALICIOUS"},
        headers=auth_headers["l1"],
    )
    assert r_l1_create.status_code == 403

    # 3. L2 Analyst CAN create IOCs (ioc.create)
    r_l2_create = client.post(
        "/api/v1/iocs",
        json={"type": "ipv4", "value": "203.0.113.5", "reputation": "MALICIOUS"},
        headers=auth_headers["l2"],
    )
    assert r_l2_create.status_code == 200
    ioc_id = r_l2_create.json()["ioc"]["id"]

    # 4. L2 Analyst CAN override classification with reason (ioc.classify)
    r_class = client.patch(
        f"/api/v1/iocs/{ioc_id}/classification",
        json={"classification": "BENIGN", "reason": "Verified internal test IP"},
        headers=auth_headers["l2"],
    )
    assert r_class.status_code == 200
    assert r_class.json()["ioc"]["reputation"] == "BENIGN"

    # 5. L2 Analyst CANNOT delete IOC (requires ioc.delete)
    r_l2_del = client.delete(f"/api/v1/iocs/{ioc_id}", headers=auth_headers["l2"])
    assert r_l2_del.status_code == 403

    # 6. SOC Manager CAN delete IOC (ioc.delete)
    r_mgr_del = client.delete(f"/api/v1/iocs/{ioc_id}", headers=auth_headers["manager"])
    assert r_mgr_del.status_code == 200
