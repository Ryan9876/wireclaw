"""Semantic capability registry and case-evidence parameter authorization."""

from dataclasses import dataclass

from wireclaw_analyzer import Capability

from ..storage import ApiError


@dataclass(frozen=True)
class CapabilitySpec:
    name: str
    stream_scoped: bool
    result_limit: int = 5_000
    timeout_seconds: int = 120
    artifact_side_effect: bool = False


REGISTRY = {
    capability.value: CapabilitySpec(
        capability.value,
        stream_scoped=capability
        not in (Capability.DNS, Capability.FRAGMENTATION, Capability.PMTUD),
    )
    for capability in Capability
}
REGISTRY["analyze_http_timing"] = CapabilitySpec("analyze_http_timing", stream_scoped=True)


def validate_request(
    name: str, parameters: dict, evidence: list[dict]
) -> tuple[CapabilitySpec, dict]:
    spec = REGISTRY.get(name)
    if spec is None:
        raise ApiError("reasoning_capability_unsupported", 422)
    if not isinstance(parameters, dict) or set(parameters) - {"tcp_stream"}:
        raise ApiError("reasoning_parameters_invalid", 422)
    stream = parameters.get("tcp_stream")
    if stream is not None and (type(stream) is not int or not 0 <= stream <= 2**31 - 1):
        raise ApiError("reasoning_parameters_invalid", 422)
    if stream is not None and not spec.stream_scoped:
        raise ApiError("reasoning_parameters_invalid", 422)
    streams = set()
    for item in evidence:
        scope = item.get("scope") if isinstance(item.get("scope"), dict) else {}
        candidate = scope.get("tcp_stream")
        if type(candidate) is int and candidate >= 0:
            streams.add(candidate)
        value = item.get("value") if isinstance(item.get("value"), dict) else {}
        conversations = value.get("conversations")
        if isinstance(conversations, list):
            streams.update(
                row["stream"]
                for row in conversations
                if isinstance(row, dict)
                and row.get("transport") == "tcp"
                and type(row.get("stream")) is int
                and row["stream"] >= 0
            )
    if stream is not None and stream not in streams:
        raise ApiError("reasoning_stream_unavailable", 422)
    return spec, {"tcp_stream": stream} if stream is not None else {}
