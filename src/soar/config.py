import os
from typing import Set

class SOARConfig:
    """
    Server-side Configuration & Feature Gate for SOAR Execution Modes & Target Allowlisting.
    """
    SIMULATION_ENABLED: bool = True
    LAB_ENABLED: bool = os.getenv("SOAR_LAB_ENABLED", "true").lower() == "true"  # Lab mode enabled in lab env
    LIVE_RESPONSE_ENABLED: bool = os.getenv("SOAR_LIVE_ENABLED", "false").lower() == "true"  # LIVE response disabled by default

    # Allowed targets for LAB mode execution
    DEFAULT_LAB_TARGETS: Set[str] = {
        "10.0.0.15", "10.0.0.16", "10.0.0.100", "10.0.0.45", "10.0.0.50", "10.0.0.99", "10.0.0.200",
        "127.0.0.1", "localhost", "lab-host-01", "john_doe", "suspect_user", "1.2.3.4"
    }

    @classmethod
    def get_lab_allowed_targets(cls) -> Set[str]:
        env_targets = os.getenv("SOAR_LAB_TARGETS", "")
        if env_targets:
            return set(t.strip() for t in env_targets.split(",") if t.strip())
        return cls.DEFAULT_LAB_TARGETS

    @classmethod
    def validate_execution_mode(cls, mode: str) -> str:
        mode_upper = (mode or "SIMULATION").upper()
        if mode_upper == "LIVE":
            if not cls.LIVE_RESPONSE_ENABLED:
                return "LIVE_MODE_DISABLED"
        elif mode_upper == "LAB":
            if not cls.LAB_ENABLED:
                return "LAB_MODE_DISABLED"
        elif mode_upper == "SIMULATION":
            if not cls.SIMULATION_ENABLED:
                return "SIMULATION_MODE_DISABLED"
        else:
            return "INVALID_EXECUTION_MODE"
        return "OK"

    @classmethod
    def validate_target_authorization(cls, target: str, mode: str) -> str:
        mode_upper = (mode or "SIMULATION").upper()
        if mode_upper == "LAB":
            allowed = cls.get_lab_allowed_targets()
            if target not in allowed:
                return "LAB_TARGET_NOT_AUTHORIZED"
        return "OK"
