"""
Phase 7 — VirusTotal Provider Adapter
Integrates with VirusTotal API v3 for File Hash, Domain, and URL lookups.
Returns NOT_CONFIGURED when VIRUSTOTAL_API_KEY is not set.
Enforces distinct provider states: NOT_CONFIGURED, CONFIGURED, VERIFIED, OFFLINE, ERROR.
"""
import os
import requests
from datetime import datetime
from src.threat_intel.base_provider import BaseProvider
from src.threat_intel.models import NormalizedIntelResult, Reputation, IOCType, ProviderState

class VirusTotalProvider(BaseProvider):
    def __init__(self):
        super().__init__(name="VirusTotal")

    def _get_api_key(self) -> str:
        return os.getenv("VIRUSTOTAL_API_KEY", "").strip()

    def is_configured(self) -> bool:
        key = self._get_api_key()
        return bool(key and key not in ("YOUR_VIRUSTOTAL_KEY_HERE", "mock_key_unconfigured", "disabled"))

    def get_provider_state(self) -> str:
        if not self.is_configured():
            return ProviderState.NOT_CONFIGURED.value
        return ProviderState.CONFIGURED.value

    def lookup(self, ioc_type: str, normalized_value: str) -> NormalizedIntelResult:
        now_str = datetime.now().isoformat()

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
                raw_details={"message": "VirusTotal API key not configured in environment"}
            )

        api_key = self._get_api_key()

        if ioc_type == IOCType.FILE_HASH.value:
            endpoint = f"https://www.virustotal.com/api/v3/files/{normalized_value}"
        elif ioc_type == IOCType.DOMAIN.value:
            endpoint = f"https://www.virustotal.com/api/v3/domains/{normalized_value}"
        elif ioc_type in (IOCType.IPV4.value, IOCType.IPV6.value):
            endpoint = f"https://www.virustotal.com/api/v3/ip_addresses/{normalized_value}"
        else:
            return NormalizedIntelResult(
                provider=self.name,
                ioc_type=ioc_type,
                ioc_value=normalized_value,
                reputation=Reputation.UNKNOWN.value,
                provider_state=self.get_provider_state(),
                lookup_status="UNSUPPORTED_TYPE",
                provider_timestamp=now_str
            )

        headers = {"x-apikey": api_key, "Accept": "application/json"}

        try:
            res = requests.get(endpoint, headers=headers, timeout=3)
            if res.status_code == 200:
                attr = res.json().get("data", {}).get("attributes", {})
                stats = attr.get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                harmless = stats.get("harmless", 0)
                total = sum(stats.values()) if stats else 1

                if malicious >= 3:
                    rep = Reputation.MALICIOUS.value
                    confidence = min(95, 60 + (malicious * 5))
                elif malicious >= 1 or suspicious >= 2:
                    rep = Reputation.SUSPICIOUS.value
                    confidence = 50
                elif harmless > 0:
                    rep = Reputation.BENIGN.value
                    confidence = 80
                else:
                    rep = Reputation.UNKNOWN.value
                    confidence = 0

                meaningful_name = attr.get("meaningful_name") or attr.get("type_description", "")
                categories = list(attr.get("categories", {}).values())[:5]

                return NormalizedIntelResult(
                    provider=self.name,
                    ioc_type=ioc_type,
                    ioc_value=normalized_value,
                    reputation=rep,
                    confidence=confidence,
                    categories=categories,
                    tags=attr.get("tags", []),
                    malware_family=meaningful_name,
                    provider_timestamp=now_str,
                    provider_state=ProviderState.VERIFIED.value,  # Only set VERIFIED on actual successful response
                    lookup_status="SUCCESS",
                    raw_details={
                        "malicious_count": malicious,
                        "suspicious_count": suspicious,
                        "harmless_count": harmless,
                        "total_engines": total,
                    }
                )
            elif res.status_code == 404:
                return NormalizedIntelResult(
                    provider=self.name,
                    ioc_type=ioc_type,
                    ioc_value=normalized_value,
                    reputation=Reputation.UNKNOWN.value,
                    confidence=0,
                    provider_timestamp=now_str,
                    provider_state=ProviderState.VERIFIED.value,
                    lookup_status="NOT_FOUND",
                    raw_details={"message": "Not found in VirusTotal dataset"}
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
