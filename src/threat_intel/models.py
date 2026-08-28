"""
Phase 7 — Threat Intelligence Data Models
Defines common data structures, reputation enums, and provider states.
"""
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional
from enum import Enum

class Reputation(str, Enum):
    MALICIOUS = "MALICIOUS"
    SUSPICIOUS = "SUSPICIOUS"
    BENIGN = "BENIGN"
    UNKNOWN = "UNKNOWN"
    NOT_CONFIGURED = "NOT_CONFIGURED"
    ERROR = "ERROR"

class ProviderState(str, Enum):
    NOT_CONFIGURED = "NOT_CONFIGURED"
    CONFIGURED = "CONFIGURED"
    VERIFIED = "VERIFIED"
    OFFLINE = "OFFLINE"
    ERROR = "ERROR"

class IOCType(str, Enum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    FILE_HASH = "file_hash"
    EMAIL = "email"

@dataclass
class NormalizedIntelResult:
    provider: str
    ioc_type: str
    ioc_value: str
    reputation: str = Reputation.UNKNOWN.value
    confidence: int = 0
    categories: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    malware_family: Optional[str] = None
    threat_type: Optional[str] = None
    references: List[str] = field(default_factory=list)
    provider_timestamp: Optional[str] = None
    provider_state: str = ProviderState.NOT_CONFIGURED.value
    lookup_status: str = Reputation.UNKNOWN.value
    raw_details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

@dataclass
class IOCRecord:
    id: str
    type: str
    value: str
    normalized_value: str
    confidence: int = 80
    severity: str = "medium"
    reputation: str = Reputation.UNKNOWN.value
    analyst_classification: str = "NONE"
    analyst_override_reason: str = ""
    classified_by: str = ""
    classified_at: str = ""
    source: str = "Local"
    tags: List[str] = field(default_factory=list)
    description: str = ""
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
