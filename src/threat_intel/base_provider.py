"""
Phase 7 — Abstract Base Provider Interface
All pluggable threat intelligence adapters must inherit from BaseProvider.
"""
from abc import ABC, abstractmethod
from typing import Optional
from src.threat_intel.models import NormalizedIntelResult

class BaseProvider(ABC):
    def __init__(self, name: str):
        self.name = name

    @abstractmethod
    def is_configured(self) -> bool:
        """Return True if credentials and configuration required for this provider are available."""
        pass

    @abstractmethod
    def lookup(self, ioc_type: str, normalized_value: str) -> NormalizedIntelResult:
        """
        Perform intelligence lookup for the given normalized IOC.
        If not configured, must return NormalizedIntelResult with lookup_status="NOT_CONFIGURED".
        """
        pass
