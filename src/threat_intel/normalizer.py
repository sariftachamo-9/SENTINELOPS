"""
Phase 7 — IOC Extractor, Normalizer & SSRF Guard Module
Provides deterministic normalization, type detection, length validation,
and SSRF safety checks for IP, Domain, URL, Hash, and Email indicators.
"""
import re
import ipaddress
from urllib.parse import urlparse
from typing import Optional, Tuple, Dict, List, Set
from src.threat_intel.models import IOCType

MAX_IOC_LENGTH = 2048

# Cloud metadata and internal SSRF blocklists
BLOCKED_HOSTNAMES = {
    "localhost", "metadata.google.internal", "metadata", "instance-data",
    "169.254.169.254", "0.0.0.0", "::", "::1"
}

class IOCNormalizer:

    @classmethod
    def is_private_ip(cls, ip_str: str) -> bool:
        """
        Check if an IP is private, loopback, link-local, carrier-grade NAT, or cloud metadata.
        """
        try:
            ip = ipaddress.ip_address(ip_str.strip())
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified:
                return True
            # Check 169.254.169.254 metadata explicitly
            if str(ip) == "169.254.169.254":
                return True
            # Carrier-grade NAT (100.64.0.0/10)
            if ip.version == 4:
                cgnat = ipaddress.ip_network("100.64.0.0/10")
                if ip in cgnat:
                    return True
            return False
        except ValueError:
            return False

    @classmethod
    def is_ssrf_risk(cls, raw_value: str) -> bool:
        """Return True if raw_value points to an internal/private/metadata destination."""
        val = raw_value.strip().lower()
        if any(h in val for h in BLOCKED_HOSTNAMES):
            return True

        # Extract host if URL
        if val.startswith("http://") or val.startswith("https://") or "/" in val:
            parsed = urlparse(val if "://" in val else f"http://{val}")
            hostname = parsed.hostname or ""
            if hostname in BLOCKED_HOSTNAMES:
                return True
            if cls.is_private_ip(hostname):
                return True
        elif cls.is_private_ip(val):
            return True

        return False

    @classmethod
    def normalize_ipv4(cls, val: str) -> Optional[str]:
        try:
            ip = ipaddress.IPv4Address(val.strip())
            return str(ip)
        except ValueError:
            return None

    @classmethod
    def normalize_ipv6(cls, val: str) -> Optional[str]:
        try:
            ip = ipaddress.IPv6Address(val.strip())
            return str(ip)
        except ValueError:
            return None

    @classmethod
    def normalize_domain(cls, val: str) -> Optional[str]:
        clean = val.strip().lower()
        if "://" in clean:
            clean = urlparse(clean).hostname or clean
        clean = clean.split("/")[0].split(":")[0]
        # Basic domain regex validation
        pattern = r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$"
        if re.match(pattern, clean):
            return clean
        return None

    @classmethod
    def normalize_url(cls, val: str) -> Optional[str]:
        clean = val.strip()
        if not clean.lower().startswith(("http://", "https://")):
            clean = "http://" + clean
        parsed = urlparse(clean)
        if not parsed.hostname:
            return None
        # Enforce lowercase scheme and host while keeping path case intact
        scheme = parsed.scheme.lower()
        host = parsed.hostname.lower()
        port = f":{parsed.port}" if parsed.port and parsed.port not in (80, 443) else ""
        path = parsed.path or "/"
        query = f"?{parsed.query}" if parsed.query else ""
        return f"{scheme}://{host}{port}{path}{query}"

    @classmethod
    def normalize_hash(cls, val: str) -> Optional[str]:
        clean = val.strip().lower()
        if len(clean) in (32, 40, 64) and re.match(r"^[a-f0-9]+$", clean):
            return clean
        return None

    @classmethod
    def normalize_email(cls, val: str) -> Optional[str]:
        clean = val.strip().lower()
        pattern = r"^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$"
        if re.match(pattern, clean):
            return clean
        return None

    @classmethod
    def detect_and_normalize(cls, raw_value: str, hint_type: Optional[str] = None) -> Tuple[Optional[str], Optional[str]]:
        if not raw_value or len(raw_value) > MAX_IOC_LENGTH:
            return None, None

        val = raw_value.strip()

        # Check explicit hint first
        if hint_type:
            ht = hint_type.lower()
            if ht == IOCType.IPV4.value:
                n = cls.normalize_ipv4(val)
                return (n, IOCType.IPV4.value) if n else (None, None)
            elif ht == IOCType.IPV6.value:
                n = cls.normalize_ipv6(val)
                return (n, IOCType.IPV6.value) if n else (None, None)
            elif ht == IOCType.DOMAIN.value:
                n = cls.normalize_domain(val)
                return (n, IOCType.DOMAIN.value) if n else (None, None)
            elif ht == IOCType.URL.value:
                n = cls.normalize_url(val)
                return (n, IOCType.URL.value) if n else (None, None)
            elif ht == IOCType.FILE_HASH.value:
                n = cls.normalize_hash(val)
                return (n, IOCType.FILE_HASH.value) if n else (None, None)
            elif ht == IOCType.EMAIL.value:
                n = cls.normalize_email(val)
                return (n, IOCType.EMAIL.value) if n else (None, None)

        # Automatic detection order: IPv4 -> IPv6 -> Hash -> Email -> URL (with scheme/path) -> Domain
        n_v4 = cls.normalize_ipv4(val)
        if n_v4:
            return n_v4, IOCType.IPV4.value

        n_v6 = cls.normalize_ipv6(val)
        if n_v6:
            return n_v6, IOCType.IPV6.value

        n_hash = cls.normalize_hash(val)
        if n_hash:
            return n_hash, IOCType.FILE_HASH.value

        n_email = cls.normalize_email(val)
        if n_email:
            return n_email, IOCType.EMAIL.value

        if val.lower().startswith(("http://", "https://")):
            n_url = cls.normalize_url(val)
            if n_url:
                return n_url, IOCType.URL.value

        n_dom = cls.normalize_domain(val)
        if n_dom:
            return n_dom, IOCType.DOMAIN.value

        return None, None

    @classmethod
    def extract_iocs_from_dict(cls, data: Dict) -> Dict[str, List[str]]:
        extracted: Dict[str, Set[str]] = {
            IOCType.IPV4.value: set(),
            IOCType.IPV6.value: set(),
            IOCType.DOMAIN.value: set(),
            IOCType.URL.value: set(),
            IOCType.FILE_HASH.value: set(),
            IOCType.EMAIL.value: set(),
        }

        def _scan_str(s: str):
            if not isinstance(s, str) or len(s) > MAX_IOC_LENGTH:
                return
            norm_val, ioc_type = cls.detect_and_normalize(s)
            if norm_val and ioc_type:
                extracted[ioc_type].add(norm_val)

        def _traverse(obj):
            if isinstance(obj, str):
                _scan_str(obj)
            elif isinstance(obj, dict):
                for k, v in obj.items():
                    _scan_str(k)
                    _traverse(v)
            elif isinstance(obj, list):
                for item in obj:
                    _traverse(item)

        _traverse(data)
        return {k: list(v) for k, v in extracted.items() if v}
