"""Administrator policy, never selected through API input."""

from dataclasses import dataclass, field
from enum import StrEnum
from ipaddress import ip_address
from urllib.parse import urlsplit

from wireclaw_analyzer import DiagnosticLimits, Limits


class ProviderMode(StrEnum):
    NONE = "none"
    CLOUD = "openai_compatible_cloud"
    LOCAL = "openai_compatible_local"
    EMBEDDED = "embedded_local"


EMBEDDED_MODEL_ID = "wireclaw-qwen3-4b-instruct-2507-q4_k_m"
EMBEDDED_FAILURE_CODES = frozenset(
    {
        "invalid-bundle",
        "port-in-use",
        "port-conflict",
        "invalid-port",
        "secret-generation-failed",
        "log-init-failed",
        "runtime-start-failed",
        "runtime-unhealthy",
        "docker-connectivity",
        "unsafe-state",
        "state-write-failed",
        "not-ready",
    }
)


def effective_ai_status(policy):
    """Return a public, normalized AI state without provider plumbing or secrets."""
    import os

    mode = policy.provider_mode.value
    raw = os.environ.get("WIRECLAW_EMBEDDED_AI_STATUS", "not_applicable")
    embedded_selected = policy.provider_mode is ProviderMode.EMBEDDED
    launcher_fallback = mode == ProviderMode.NONE.value and raw.startswith("unavailable:")
    if not embedded_selected and not launcher_fallback:
        return {
            "effective_provider_mode": mode,
            "embedded_availability": "not_applicable",
            "model": None,
            "failure_code": None,
        }
    failure = None
    if raw == "ready" and embedded_selected:
        availability = "ready"
    else:
        availability = "unavailable"
        candidate = raw.partition(":")[2] if raw.startswith("unavailable:") else "not-ready"
        failure = candidate if candidate in EMBEDDED_FAILURE_CODES else "not-ready"
    return {
        "effective_provider_mode": mode if availability == "ready" else ProviderMode.NONE.value,
        "embedded_availability": availability,
        "model": EMBEDDED_MODEL_ID,
        "failure_code": failure,
    }


@dataclass(frozen=True)
class Policy:
    host: str = "127.0.0.1"
    container_network: bool = False
    port: int = 8765
    bridge_port: int = 8766
    max_cases: int = 100
    max_json_bytes: int = 16_384
    max_symptom_chars: int = 4_096
    max_runs: int = 64
    max_evidence_items: int = 5_000
    max_evidence_bytes: int = 32 * 1024 * 1024
    max_evidence_capture_bytes: int = 16 * 1024 * 1024
    max_evidence_captures: int = 32
    max_bridge_grants: int = 64
    bridge_grant_ttl_seconds: int = 30
    max_display_filter_chars: int = 2_048
    max_result_items: int = 100
    upload_timeout_seconds: float = 60
    provider_mode: ProviderMode = ProviderMode.NONE
    provider_base_url: str | None = None
    provider_model: str | None = None
    provider_timeout_seconds: float = 60
    provider_api_key: str | None = field(default=None, repr=False, compare=False)
    max_reasoning_steps: int = 8
    max_provider_request_bytes: int = 131_072
    max_provider_response_bytes: int = 65_536
    max_reasoning_evidence_items: int = 200
    max_identical_capability_request_count: int = 1
    analyzer: Limits = field(default_factory=Limits)
    diagnostics: DiagnosticLimits = field(default_factory=DiagnosticLimits)

    def __post_init__(self):
        if type(self.container_network) is not bool or not (
            ip_address(self.host).is_loopback or (self.container_network and self.host == "0.0.0.0")
        ):
            raise ValueError("loopback_required")
        for port in (self.port, self.bridge_port):
            if type(port) is not int or not 1 <= port <= 65535:
                raise ValueError("invalid_port")
        for key, value in vars(self).items():
            if key in (
                "host",
                "container_network",
                "port",
                "bridge_port",
                "analyzer",
                "diagnostics",
                "provider_mode",
                "provider_base_url",
                "provider_model",
                "provider_api_key",
            ):
                continue
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValueError("invalid_policy")
            if not 0 < value < float("inf"):
                raise ValueError("invalid_policy")
            if (
                key not in ("upload_timeout_seconds", "provider_timeout_seconds")
                and type(value) is not int
            ):
                raise ValueError("invalid_policy")
        try:
            mode = ProviderMode(self.provider_mode)
        except ValueError:
            raise ValueError("invalid_provider_mode") from None
        object.__setattr__(self, "provider_mode", mode)
        if (
            self.provider_timeout_seconds > 300
            or self.max_reasoning_steps > 32
            or self.max_provider_request_bytes > 1_048_576
            or self.max_provider_response_bytes > 1_048_576
            or self.max_reasoning_evidence_items > 1_000
            or self.max_identical_capability_request_count != 1
        ):
            raise ValueError("provider_resource_limit")
        if mode is ProviderMode.NONE:
            return
        if (
            not isinstance(self.provider_base_url, str)
            or len(self.provider_base_url) > 2048
            or any(ord(char) < 33 or ord(char) == 127 for char in self.provider_base_url)
            or not isinstance(self.provider_model, str)
        ):
            raise ValueError("provider_configuration_required")
        parsed = urlsplit(self.provider_base_url)
        try:
            port = parsed.port
        except ValueError:
            raise ValueError("invalid_provider_url") from None
        if (
            parsed.scheme not in ({"https"} if mode is ProviderMode.CLOUD else {"http", "https"})
            or not parsed.hostname
            or (port is not None and not 1 <= port <= 65535)
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or len(parsed.path) > 256
            or any(part in (".", "..") for part in parsed.path.split("/"))
        ):
            raise ValueError("invalid_provider_url")
        if mode is ProviderMode.CLOUD and parsed.scheme != "https":
            raise ValueError("cloud_provider_https_required")
        if not 1 <= len(self.provider_model) <= 128 or any(
            ord(char) < 32 or ord(char) == 127 for char in self.provider_model
        ):
            raise ValueError("invalid_provider_model")
        if self.provider_api_key is not None and (
            not isinstance(self.provider_api_key, str) or len(self.provider_api_key) > 4096
        ):
            raise ValueError("invalid_provider_key")
        if self.provider_api_key is not None and any(
            ord(char) < 33 or ord(char) == 127 for char in self.provider_api_key
        ):
            raise ValueError("invalid_provider_key")
        if mode is ProviderMode.EMBEDDED:
            if (
                parsed.scheme != "http"
                or parsed.hostname != "host.docker.internal"
                or port != 8767
                or parsed.path != "/v1"
            ):
                raise ValueError("invalid_provider_url")
            if self.provider_model != "wireclaw-qwen3-4b-instruct-2507-q4_k_m":
                raise ValueError("invalid_provider_model")
            if not isinstance(self.provider_api_key, str) or len(self.provider_api_key) < 32:
                raise ValueError("invalid_provider_key")

    @classmethod
    def from_environment(cls, **overrides):
        """Read provider policy only at process startup; request bodies cannot alter it."""
        import os

        values = {
            "port": int(os.environ.get("WIRECLAW_PUBLIC_PORT", "8765")),
            "bridge_port": int(os.environ.get("WIRECLAW_BRIDGE_PORT", "8766")),
            "provider_mode": os.environ.get("WIRECLAW_PROVIDER_MODE", "none"),
            "provider_base_url": os.environ.get("WIRECLAW_PROVIDER_BASE_URL"),
            "provider_model": os.environ.get("WIRECLAW_PROVIDER_MODEL"),
            "provider_api_key": os.environ.get("WIRECLAW_PROVIDER_API_KEY"),
        }
        values.update(overrides)
        return cls(**values)
