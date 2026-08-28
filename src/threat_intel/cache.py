"""
Phase 7 — DB-Backed Enrichment Cache & Rate Limiting Module
Caches provider lookup responses by (provider, ioc_type, normalized_value).
Implements separate TTLs for positive vs negative/unknown results and rate limiting.
"""
import json
import time
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from src.database import Database
from src.threat_intel.models import NormalizedIntelResult, Reputation

TTL_POSITIVE_SECONDS = 86400  # 24 hours for MALICIOUS, SUSPICIOUS, BENIGN
TTL_NEGATIVE_SECONDS = 300    # 5 minutes for UNKNOWN, NOT_FOUND, ERROR, NOT_CONFIGURED

class EnrichmentCache:
    def __init__(self, db: Optional[Database] = None):
        self.db = db if db else Database()

    def _make_key(self, provider: str, ioc_type: str, normalized_value: str) -> str:
        return f"{provider.lower()}:{ioc_type.lower()}:{normalized_value.lower()}"

    def get(self, provider: str, ioc_type: str, normalized_value: str) -> Optional[NormalizedIntelResult]:
        key = self._make_key(provider, ioc_type, normalized_value)
        cursor = self.db.get_cursor()
        cursor.execute(
            "SELECT response_json, status, expires_at FROM ioc_enrichment_cache WHERE cache_key = ?",
            (key,)
        )
        row = cursor.fetchone()
        if not row:
            return None

        # Check expiration
        expires_at_str = row["expires_at"]
        try:
            exp_time = datetime.fromisoformat(expires_at_str)
            if datetime.now() > exp_time:
                return None  # Expired
        except Exception:
            pass

        try:
            data = json.loads(row["response_json"])
            # Ensure secrets are never in cached objects
            data.get("raw_details", {}).pop("api_key", None)
            return NormalizedIntelResult(**data)
        except Exception:
            return None

    def set(self, provider: str, ioc_type: str, normalized_value: str, result: NormalizedIntelResult, ttl_seconds: Optional[int] = None):
        key = self._make_key(provider, ioc_type, normalized_value)
        now = datetime.now()

        if ttl_seconds is not None:
            ttl = ttl_seconds
        else:
            if result.reputation in (Reputation.MALICIOUS.value, Reputation.SUSPICIOUS.value, Reputation.BENIGN.value):
                ttl = TTL_POSITIVE_SECONDS
            else:
                ttl = TTL_NEGATIVE_SECONDS

        expires_at = (now + timedelta(seconds=ttl)).isoformat()
        cached_at = now.isoformat()

        res_dict = result.to_dict()
        # Ensure secret protection: strip any sensitive key from raw_details before caching
        if "raw_details" in res_dict and isinstance(res_dict["raw_details"], dict):
            res_dict["raw_details"].pop("api_key", None)

        res_json = json.dumps(res_dict)

        cursor = self.db.get_cursor()
        cursor.execute(
            """
            INSERT OR REPLACE INTO ioc_enrichment_cache
            (cache_key, provider, ioc_type, normalized_value, response_json, status, cached_at, expires_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (key, provider, ioc_type, normalized_value, res_json, result.reputation, cached_at, expires_at)
        )
        self.db.conn.commit()


class ProviderRateLimiter:
    """In-memory sliding-window rate limiter per provider."""
    def __init__(self):
        self._history: Dict[str, list] = {}

    def is_allowed(self, provider: str, max_requests: int = 10, window_seconds: int = 60) -> bool:
        now = time.time()
        timestamps = self._history.get(provider, [])
        cutoff = now - window_seconds
        timestamps = [t for t in timestamps if t > cutoff]
        self._history[provider] = timestamps

        if len(timestamps) < max_requests:
            timestamps.append(now)
            return True
        return False
