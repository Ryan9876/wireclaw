"""Administrator policy, never selected through API input."""

from dataclasses import dataclass, field
from enum import StrEnum
from ipaddress import ip_address
from typing import Protocol

from wireclaw_analyzer import DiagnosticLimits, Limits


class ProviderMode(StrEnum):
    NONE = "none"
    CLOUD = "openai_compatible_cloud"
    LOCAL = "openai_compatible_local"


class ReasoningProvider(Protocol):
    """Future adapters receive normalized context only; Gate 3 never calls one."""

    mode: ProviderMode

    async def propose(self, context: dict) -> dict: ...


@dataclass(frozen=True)
class Policy:
    host: str = "127.0.0.1"
    port: int = 8765
    max_cases: int = 100
    max_json_bytes: int = 16_384
    max_symptom_chars: int = 4_096
    max_runs: int = 64
    max_evidence_items: int = 5_000
    max_evidence_bytes: int = 32 * 1024 * 1024
    max_result_items: int = 100
    upload_timeout_seconds: float = 60
    analyzer: Limits = field(default_factory=Limits)
    diagnostics: DiagnosticLimits = field(default_factory=DiagnosticLimits)

    def __post_init__(self):
        if not ip_address(self.host).is_loopback:
            raise ValueError("loopback_required")
        if type(self.port) is not int or not 1 <= self.port <= 65535:
            raise ValueError("invalid_port")
        for key, value in vars(self).items():
            if key in ("host", "port", "analyzer", "diagnostics"):
                continue
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValueError("invalid_policy")
            if not 0 < value < float("inf"):
                raise ValueError("invalid_policy")
            if key != "upload_timeout_seconds" and type(value) is not int:
                raise ValueError("invalid_policy")
