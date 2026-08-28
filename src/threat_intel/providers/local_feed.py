"""
Phase 7 — Local Threat Feed Provider Adapter
Checks static local IOC database and local reputation tables.
"""
from datetime import datetime
from typing import Optional
from src.database import Database
from src.threat_intel.base_provider import BaseProvider
from src.threat_intel.models import NormalizedIntelResult, Reputation, IOCType, ProviderState

STATIC_LOCAL_FEED = {
    "ips": {
        "192.168.1.195": {"reputation": "MALICIOUS", "confidence": 95, "details": "Data Exfiltration Target", "tags": ["c2", "internal_exfil"]},
        "192.168.1.99": {"reputation": "SUSPICIOUS", "confidence": 75, "details": "Suspicious Network Scanner", "tags": ["recon"]},
        "185.220.101.5": {"reputation": "MALICIOUS", "confidence": 90, "details": "Known Tor Exit Node", "tags": ["tor", "anon"]},
        "198.51.100.99": {"reputation": "MALICIOUS", "confidence": 95, "details": "Brute Force Source IP", "tags": ["brute_force", "attacker"]},
        "198.51.100.44": {"reputation": "SUSPICIOUS", "confidence": 70, "details": "Failed SSH Attempt Source", "tags": ["ssh", "recon"]},
    },
    "domains": {
        "malicious-863.com": {"reputation": "MALICIOUS", "confidence": 95, "details": "C2 Command Server", "tags": ["c2", "malware"]},
        "evil-phish.net": {"reputation": "MALICIOUS", "confidence": 90, "details": "Phishing Landing Page", "tags": ["phishing"]},
    },
    "hashes": {
        "44d88612fea8a8f36de82e1278abb02f": {"reputation": "MALICIOUS", "confidence": 100, "details": "EICAR Test File", "tags": ["test", "eicar"]},
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": {"reputation": "BENIGN", "confidence": 100, "details": "Empty File Hash", "tags": ["empty"]},
    }
}

class LocalFeedProvider(BaseProvider):
    def __init__(self, db: Optional[Database] = None):
        super().__init__(name="Local Threat Intel Feed")
        self.db = db if db else Database()

    def is_configured(self) -> bool:
        return True

    def get_provider_state(self) -> str:
        return ProviderState.VERIFIED.value

    def lookup(self, ioc_type: str, normalized_value: str) -> NormalizedIntelResult:
        now_str = datetime.now().isoformat()

        # 1. Check SQLite `iocs` table
        cursor = self.db.get_cursor()
        cursor.execute(
            "SELECT * FROM iocs WHERE normalized_value = ? AND type = ?",
            (normalized_value, ioc_type)
        )
        row = cursor.fetchone()
        if row:
            rep = row["analyst_classification"] if row["analyst_classification"] not in ("NONE", "") else row["reputation"]
            tags = []
            try:
                import json
                tags = json.loads(row["tags"]) if row["tags"] else []
            except Exception:
                pass
            return NormalizedIntelResult(
                provider=self.name,
                ioc_type=ioc_type,
                ioc_value=normalized_value,
                reputation=rep,
                confidence=row["confidence"],
                categories=[row["source"]],
                tags=tags,
                first_seen=row["first_seen"],
                last_seen=row["last_seen"],
                provider_timestamp=now_str,
                provider_state=ProviderState.VERIFIED.value,
                lookup_status="SUCCESS",
                raw_details={"source": "database", "description": row["description"]}
            )

        # 2. Check Static Local Feed
        feed_map = None
        if ioc_type in (IOCType.IPV4.value, IOCType.IPV6.value):
            feed_map = STATIC_LOCAL_FEED["ips"]
        elif ioc_type == IOCType.DOMAIN.value:
            feed_map = STATIC_LOCAL_FEED["domains"]
        elif ioc_type == IOCType.FILE_HASH.value:
            feed_map = STATIC_LOCAL_FEED["hashes"]

        if feed_map and normalized_value in feed_map:
            entry = feed_map[normalized_value]
            return NormalizedIntelResult(
                provider=self.name,
                ioc_type=ioc_type,
                ioc_value=normalized_value,
                reputation=entry["reputation"],
                confidence=entry["confidence"],
                categories=["Static Local Feed"],
                tags=entry.get("tags", []),
                first_seen=now_str,
                last_seen=now_str,
                provider_timestamp=now_str,
                provider_state=ProviderState.VERIFIED.value,
                lookup_status="SUCCESS",
                raw_details={"details": entry.get("details", "")}
            )

        return NormalizedIntelResult(
            provider=self.name,
            ioc_type=ioc_type,
            ioc_value=normalized_value,
            reputation=Reputation.UNKNOWN.value,
            confidence=0,
            provider_timestamp=now_str,
            provider_state=ProviderState.VERIFIED.value,
            lookup_status="NOT_FOUND",
            raw_details={"message": "No match found in local feed"}
        )
