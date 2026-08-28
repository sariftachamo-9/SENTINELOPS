"""
Phase 7 — AbuseIPDB Provider Adapter
Integrates with AbuseIPDB API v2 for IP reputation lookups.
Returns NOT_CONFIGURED when ABUSEIPDB_API_KEY is not set.
Enforces distinct provider states: NOT_CONFIGURED, CONFIGURED, VERIFIED, OFFLINE, ERROR.
"""
import os
import requests
from datetime import datetime
from src.threat_intel.base_provider import BaseProvider
from src.threat_intel.models import NormalizedIntelResult, Reputation, IOCType, ProviderState

class AbuseIPDBProvider(BaseProvider):
    def __init__(self):
        super().__init__(name="AbuseIPDB")

    def _get_api_key(self) -> str:
        return os.getenv("ABUSEIPDB_API_KEY", "").strip()

    def is_configured(self) -> bool:
        key = self._get_api_key()
        return bool(key and key not in ("YOUR_ABUSEIPDB_KEY_HERE", "mock_key_unconfigured", "disabled"))

    def get_provider_state(self) -> str:
        if not self.is_configured():
            return ProviderState.NOT_CONFIGURED.value
        return ProviderState.CONFIGURED.value

    def lookup(self, ioc_type: str, normalized_value: str) -> NormalizedIntelResult:
        now_str = datetime.now().isoformat()

        if ioc_type not in (IOCType.IPV4.value, IOCType.IPV6.value):
            return NormalizedIntelResult(
                provider=self.name,
                ioc_type=ioc_type,
                ioc_value=normalized_value,
                reputation=Reputation.UNKNOWN.value,
                provider_state=self.get_provider_state(),
                lookup_status="UNSUPPORTED_TYPE",
                provider_timestamp=now_str
            )

        if not self.is_configured():
            return NormalizedIntelResult(
                provider=self.name,
                ioc_type=ioc_type,
                ioc_value=normalized_value,
                reputation=Reputation.NOT_CONFIGURED.value,
                confidence=0,
                provider_state=ProviderState.NOT_CONFIGURED.value,
                lookup_status=Reputation.NOT_CONFIGURED.value,
                provider_timestamp=now_str,
                raw_details={"message": "AbuseIPDB API key not configured in environment"}
            )

        api_key = self._get_api_key()
        url = "https://api.abuseipdb.com/api/v2/check"
        params = {"ipAddress": normalized_value, "maxAgeInDays": 90}
        headers = {"Key": api_key, "Accept": "application/json"}

        try:
            res = requests.get(url, params=params, headers=headers, timeout=3)
            if res.status_code == 200:
                data = res.json().get("data", {})
                score = data.get("abuseConfidenceScore", 0)
                reports = data.get("totalReports", 0)
                country = data.get("countryCode", "")
                isp = data.get("isp", "")

                if score >= 50:
                    rep = Reputation.MALICIOUS.value
                elif score >= 20:
                    rep = Reputation.SUSPICIOUS.value
                elif reports == 0:
                    rep = Reputation.BENIGN.value
                else:
                    rep = Reputation.UNKNOWN.value

                return NormalizedIntelResult(
                    provider=self.name,
                    ioc_type=ioc_type,
                    ioc_value=normalized_value,
                    reputation=rep,
                    confidence=score,
                    categories=[f"Abuse Score {score}%"],
                    tags=["ip_reputation", f"reports_{reports}"],
                    last_seen=data.get("lastReportedAt"),
                    provider_timestamp=now_str,
                    provider_state=ProviderState.VERIFIED.value,  # Only set VERIFIED on actual successful response
                    lookup_status="SUCCESS",
                    raw_details={
                        "score": score,
                        "total_reports": reports,
                        "country": country,
                        "isp": isp,
                    }
                )
            else:
                return NormalizedIntelResult(
                    provider=self.name,
                    ioc_type=ioc_type,
                    ioc_value=normalized_value,
                    reputation=Reputation.ERROR.value,
                    provider_state=ProviderState.ERROR.value,
                    lookup_status="ERROR",
                    provider_timestamp=now_str,
                    raw_details={"status_code": res.status_code}
                )
        except requests.exceptions.Timeout:
            return NormalizedIntelResult(
                provider=self.name,
                ioc_type=ioc_type,
                ioc_value=normalized_value,
                reputation=Reputation.ERROR.value,
                provider_state=ProviderState.OFFLINE.value,
                lookup_status="OFFLINE",
                provider_timestamp=now_str,
                raw_details={"error": "Connection timed out"}
            )
        except Exception as e:
            return NormalizedIntelResult(
                provider=self.name,
                ioc_type=ioc_type,
                ioc_value=normalized_value,
                reputation=Reputation.ERROR.value,
                provider_state=ProviderState.ERROR.value,
                lookup_status="ERROR",
                provider_timestamp=now_str,
                raw_details={"error": str(e)}
            )
