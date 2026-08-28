"""
Backward-Compatible Facade for Threat Intelligence Subsystem
Delegates to Phase 7 EnrichmentManager while maintaining existing interface methods.
"""
from typing import Dict, Any, Optional
from src.threat_intel.manager import EnrichmentManager
from src.threat_intel.models import Reputation

class ThreatIntel:
    """
    Threat Intelligence Facade.
    Maintains compatibility with Phase 1-5 callers while using Phase 7 EnrichmentManager.
    """
    def __init__(self, manager: Optional[EnrichmentManager] = None):
        self.manager = manager if manager else EnrichmentManager()

    def check_ip(self, ip: str) -> Dict[str, Any]:
        res = self.manager.enrich_indicator(ip, hint_type="ipv4")
        overall_rep = res.get("overall_reputation")
        is_malicious = (overall_rep == Reputation.MALICIOUS.value)
        return {
            "malicious": is_malicious,
            "score": res.get("overall_confidence", 0),
            "source": "Phase 7 Threat Intel Layer",
            "details": f"Reputation: {overall_rep}",
            "full_result": res,
        }

    def check_domain(self, domain: str) -> Dict[str, Any]:
        res = self.manager.enrich_indicator(domain, hint_type="domain")
        overall_rep = res.get("overall_reputation")
        is_malicious = (overall_rep == Reputation.MALICIOUS.value)
        return {
            "malicious": is_malicious,
            "score": res.get("overall_confidence", 0),
            "source": "Phase 7 Threat Intel Layer",
            "details": f"Reputation: {overall_rep}",
            "full_result": res,
        }

    def check_hash(self, file_hash: str) -> Dict[str, Any]:
        res = self.manager.enrich_indicator(file_hash, hint_type="file_hash")
        overall_rep = res.get("overall_reputation")
        is_malicious = (overall_rep == Reputation.MALICIOUS.value)
        return {
            "malicious": is_malicious,
            "score": res.get("overall_confidence", 0),
            "source": "Phase 7 Threat Intel Layer",
            "details": f"Reputation: {overall_rep}",
            "full_result": res,
        }

    def enrich_alert(self, alert: dict) -> dict:
        return self.manager.enrich_alert(alert)
