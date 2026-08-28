"""
Phase 7 — Enrichment Manager Subsystem
Orchestrates IOC normalization, caching, multi-provider enrichment lookups,
rate limiting, SSRF protection, alert enrichment, transparent risk scoring,
and analyst-controlled IOC classification.
"""
import uuid
import json
from datetime import datetime
from typing import Optional, List, Dict, Any

from src.database import Database
from src.audit import AuditLogger
from src.threat_intel.models import NormalizedIntelResult, IOCRecord, Reputation, IOCType
from src.threat_intel.normalizer import IOCNormalizer
from src.threat_intel.cache import EnrichmentCache, ProviderRateLimiter
from src.threat_intel.base_provider import BaseProvider
from src.threat_intel.providers.local_feed import LocalFeedProvider
from src.threat_intel.providers.abuseipdb import AbuseIPDBProvider
from src.threat_intel.providers.virustotal import VirusTotalProvider

class EnrichmentManager:
    def __init__(self, db: Optional[Database] = None):
        self.db = db if db else Database()
        self.audit = AuditLogger(db=self.db)
        self.cache = EnrichmentCache(db=self.db)
        self.rate_limiter = ProviderRateLimiter()

        # Pluggable provider registration
        self.providers: List[BaseProvider] = [
            LocalFeedProvider(db=self.db),
            AbuseIPDBProvider(),
            VirusTotalProvider(),
        ]

    # ------------------------------------------------------------------
    # Core Indicator Enrichment
    # ------------------------------------------------------------------

    def enrich_indicator(
        self, raw_value: str, hint_type: Optional[str] = None, force_refresh: bool = False
    ) -> Dict[str, Any]:
        """
        Enrich a single IOC across all registered providers with caching and rate limiting.
        """
        norm_val, ioc_type = IOCNormalizer.detect_and_normalize(raw_value, hint_type)
        if not norm_val or not ioc_type:
            return {
                "raw_value": raw_value,
                "normalized_value": raw_value,
                "ioc_type": "unknown",
                "overall_reputation": Reputation.UNKNOWN.value,
                "overall_confidence": 0,
                "provider_results": [],
                "error": "Invalid or unparseable IOC format",
            }

        # SSRF Safety Check: If it's a private IP, do NOT query external providers
        is_private = False
        if ioc_type in (IOCType.IPV4.value, IOCType.IPV6.value):
            is_private = IOCNormalizer.is_private_ip(norm_val)

        results: List[NormalizedIntelResult] = []

        for provider in self.providers:
            # 1. SSRF Safety: skip external providers for private/loopback IPs
            if is_private and provider.name != "Local Threat Intel Feed":
                results.append(
                    NormalizedIntelResult(
                        provider=provider.name,
                        ioc_type=ioc_type,
                        ioc_value=norm_val,
                        reputation=Reputation.BENIGN.value,
                        confidence=100,
                        lookup_status="SKIPPED_PRIVATE_RANGE",
                        provider_timestamp=datetime.now().isoformat(),
                        raw_details={"message": "Private/Loopback IP excluded from external provider queries"}
                    )
                )
                continue

            # 2. Check Cache
            if not force_refresh:
                cached = self.cache.get(provider.name, ioc_type, norm_val)
                if cached:
                    results.append(cached)
                    continue

            # 3. Check Configuration & Rate Limits
            if not provider.is_configured():
                res = provider.lookup(ioc_type, norm_val)
                results.append(res)
                self.cache.set(provider.name, ioc_type, norm_val, res, ttl_seconds=86400)
                continue

            if not self.rate_limiter.is_allowed(provider.name):
                # Throttled
                res = NormalizedIntelResult(
                    provider=provider.name,
                    ioc_type=ioc_type,
                    ioc_value=norm_val,
                    reputation=Reputation.UNKNOWN.value,
                    confidence=0,
                    lookup_status="RATE_LIMITED",
                    provider_timestamp=datetime.now().isoformat(),
                    raw_details={"message": "Request throttled due to provider rate limit"}
                )
                results.append(res)
                continue

            # 4. Perform Lookup (non-blocking exception isolation)
            try:
                res = provider.lookup(ioc_type, norm_val)
            except Exception as exc:
                res = NormalizedIntelResult(
                    provider=provider.name,
                    ioc_type=ioc_type,
                    ioc_value=norm_val,
                    reputation=Reputation.ERROR.value,
                    lookup_status="ERROR",
                    provider_timestamp=datetime.now().isoformat(),
                    raw_details={"error": str(exc)}
                )

            # 5. Cache result
            results.append(res)
            self.cache.set(provider.name, ioc_type, norm_val, res)

        # Aggregate overall reputation
        overall_rep, max_conf = self._aggregate_reputation(results)

        return {
            "raw_value": raw_value,
            "normalized_value": norm_val,
            "ioc_type": ioc_type,
            "overall_reputation": overall_rep,
            "overall_confidence": max_conf,
            "provider_results": [r.to_dict() for r in results],
            "enriched_at": datetime.now().isoformat(),
        }

    def _aggregate_reputation(self, results: List[NormalizedIntelResult]) -> tuple:
        """
        Aggregate results across providers cleanly.
        Order of precedence: MALICIOUS > SUSPICIOUS > BENIGN > UNKNOWN / NOT_CONFIGURED / ERROR.
        Never treat UNKNOWN or NOT_CONFIGURED as BENIGN.
        """
        has_malicious = any(r.reputation == Reputation.MALICIOUS.value for r in results)
        has_suspicious = any(r.reputation == Reputation.SUSPICIOUS.value for r in results)
        has_benign = any(r.reputation == Reputation.BENIGN.value for r in results)

        confidences = [r.confidence for r in results if r.confidence > 0]
        max_conf = max(confidences) if confidences else 0

        if has_malicious:
            return Reputation.MALICIOUS.value, max_conf or 90
        elif has_suspicious:
            return Reputation.SUSPICIOUS.value, max_conf or 60
        elif has_benign:
            return Reputation.BENIGN.value, max_conf or 80
        else:
            return Reputation.UNKNOWN.value, 0

    # ------------------------------------------------------------------
    # Alert & Event Pipeline Enrichment
    # ------------------------------------------------------------------

    def enrich_alert(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract IOCs from an alert, enrich them, and attach threat intel without
        overwriting original evidence.
        """
        enriched_alert = dict(alert)
        extracted = IOCNormalizer.extract_iocs_from_dict(alert)

        intel_results = []
        highest_rep = Reputation.UNKNOWN.value

        for ioc_type, val_list in extracted.items():
            for val in val_list:
                res = self.enrich_indicator(val, hint_type=ioc_type)
                intel_results.append(res)
                rep = res.get("overall_reputation")
                if rep == Reputation.MALICIOUS.value:
                    highest_rep = Reputation.MALICIOUS.value
                elif rep == Reputation.SUSPICIOUS.value and highest_rep != Reputation.MALICIOUS.value:
                    highest_rep = Reputation.SUSPICIOUS.value

        enriched_alert["threat_intel"] = {
            "highest_reputation": highest_rep,
            "indicators_analyzed": len(intel_results),
            "results": intel_results,
            "enriched_at": datetime.now().isoformat(),
        }

        # Backwards compatibility flags for RiskEngine
        if highest_rep == Reputation.MALICIOUS.value:
            enriched_alert["threat_intel_matched"] = True
            enriched_alert["ioc_reputation"] = "MALICIOUS"
        elif highest_rep == Reputation.SUSPICIOUS.value:
            enriched_alert["threat_intel_matched"] = True
            enriched_alert["ioc_reputation"] = "SUSPICIOUS"
        else:
            enriched_alert["threat_intel_matched"] = False
            enriched_alert["ioc_reputation"] = "CLEAN"

        return enriched_alert

    # ------------------------------------------------------------------
    # Analyst IOC CRUD & Classification
    # ------------------------------------------------------------------

    def add_ioc(
        self,
        type_: str,
        value: str,
        confidence: int = 80,
        severity: str = "medium",
        reputation: str = Reputation.UNKNOWN.value,
        source: str = "Analyst Manual Add",
        tags: List[str] = None,
        description: str = "",
        created_by: str = "analyst",
    ) -> Dict[str, Any]:
        norm_val, detected_type = IOCNormalizer.detect_and_normalize(value, hint_type=type_)
        if not norm_val:
            raise ValueError(f"Invalid IOC value '{value}' for type '{type_}'")
        actual_type = detected_type or type_

        ioc_id = f"IOC-{datetime.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
        now_str = datetime.now().isoformat()

        cursor = self.db.get_cursor()
        cursor.execute(
            """
            INSERT INTO iocs
            (id, type, value, normalized_value, confidence, severity, reputation,
             analyst_classification, analyst_override_reason, classified_by, classified_at,
             source, tags, description, first_seen, last_seen, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'NONE', '', '', '', ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                ioc_id, actual_type, value, norm_val, confidence, severity.lower(), reputation.upper(),
                source, json.dumps(tags or []), description, now_str, now_str, now_str, now_str
            )
        )
        self.db.conn.commit()

        self.audit.log(
            username=created_by,
            role="analyst",
            action="IOC_CREATED",
            target_type="ioc",
            target_id=ioc_id,
            new_value={"value": norm_val, "type": actual_type, "reputation": reputation},
        )
        return self.get_ioc(ioc_id)

    def get_ioc(self, ioc_id: str) -> Optional[Dict[str, Any]]:
        cursor = self.db.get_cursor()
        cursor.execute("SELECT * FROM iocs WHERE id = ? OR (normalized_value = ?)", (ioc_id, ioc_id))
        row = cursor.fetchone()
        if not row:
            return None
        d = dict(row)
        try:
            d["tags"] = json.loads(d["tags"]) if d.get("tags") else []
        except Exception:
            d["tags"] = []
        return d

    def list_iocs(
        self,
        type_: Optional[str] = None,
        reputation: Optional[str] = None,
        search: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Dict[str, Any]:
        conditions, params = [], []
        if type_:
            conditions.append("type = ?")
            params.append(type_.lower())
        if reputation:
            conditions.append("reputation = ?")
            params.append(reputation.upper())
        if search:
            conditions.append("(value LIKE ? OR normalized_value LIKE ? OR description LIKE ?)")
            p_str = f"%{search}%"
            params.extend([p_str, p_str, p_str])

        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        cursor = self.db.get_cursor()

        cursor.execute(f"SELECT COUNT(*) FROM iocs {where}", params)
        total = cursor.fetchone()[0]

        cursor.execute(
            f"SELECT * FROM iocs {where} ORDER BY created_at DESC LIMIT ? OFFSET ?",
            params + [limit, offset]
        )
        items = []
        for r in cursor.fetchall():
            d = dict(r)
            try:
                d["tags"] = json.loads(d["tags"]) if d.get("tags") else []
            except Exception:
                d["tags"] = []
            items.append(d)

        return {"iocs": items, "total": total, "limit": limit, "offset": offset}

    def update_analyst_classification(
        self,
        ioc_id: str,
        classification: str,
        reason: str,
        analyst: str,
        role: str = "",
    ) -> Dict[str, Any]:
        """
        Allow analysts to manually classify an IOC (MALICIOUS, SUSPICIOUS, BENIGN, UNKNOWN)
        with a mandatory reason and audit log entry.
        """
        if not reason or not reason.strip():
            raise ValueError("Analyst classification override requires a non-empty reason.")

        classification = classification.upper()
        if classification not in (Reputation.MALICIOUS.value, Reputation.SUSPICIOUS.value, Reputation.BENIGN.value, Reputation.UNKNOWN.value):
            raise ValueError(f"Invalid classification '{classification}'. Must be MALICIOUS, SUSPICIOUS, BENIGN, or UNKNOWN.")

        ioc = self.get_ioc(ioc_id)
        if not ioc:
            raise ValueError(f"IOC '{ioc_id}' not found")

        old_class = ioc.get("analyst_classification", "NONE")
        now_str = datetime.now().isoformat()

        cursor = self.db.get_cursor()
        cursor.execute(
            """
            UPDATE iocs
            SET analyst_classification = ?, analyst_override_reason = ?,
                classified_by = ?, classified_at = ?, reputation = ?, updated_at = ?
            WHERE id = ?
            """,
            (classification, reason.strip(), analyst, now_str, classification, now_str, ioc["id"])
        )
        self.db.conn.commit()

        self.audit.log(
            username=analyst,
            role=role,
            action="IOC_CLASSIFICATION_OVERRIDDEN",
            target_type="ioc",
            target_id=ioc["id"],
            old_value={"classification": old_class, "reputation": ioc.get("reputation")},
            new_value={"classification": classification, "reason": reason.strip()},
        )
        return self.get_ioc(ioc["id"])

    def link_ioc_to_target(self, ioc_id: str, target_type: str, target_id: str) -> bool:
        """Link IOC to Alert, Incident, Case, Host, or User."""
        now_str = datetime.now().isoformat()
        rel_id = f"IOCREL-{uuid.uuid4().hex[:8].upper()}"
        cursor = self.db.get_cursor()
        try:
            cursor.execute(
                "INSERT INTO ioc_relationships (id, ioc_id, target_type, target_id, created_at) VALUES (?, ?, ?, ?, ?)",
                (rel_id, ioc_id, target_type.lower(), target_id, now_str)
            )
            self.db.conn.commit()
            return True
        except Exception:
            return False
