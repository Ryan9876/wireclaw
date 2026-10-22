"""Strict request contracts: no paths, executable names, flags or filters."""

import unicodedata
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from wireclaw_analyzer import Capability


class State(StrEnum):
    NEW = "NEW"
    INGESTING = "INGESTING"
    VALIDATING_CAPTURE = "VALIDATING_CAPTURE"
    BASELINE_ANALYSIS = "BASELINE_ANALYSIS"
    INVESTIGATING = "INVESTIGATING"
    ASSEMBLING_REPORT = "ASSEMBLING_REPORT"
    COMPLETE = "COMPLETE"
    FAILED = "FAILED"


class CaptureVantage(StrEnum):
    UNKNOWN = "unknown"
    CLIENT = "client"
    NETWORK = "network"
    SERVER = "server"
    OTHER = "other"


class CaptureNetworkSubtype(StrEnum):
    FIREWALL = "Firewall"
    ROUTER = "Router"
    SWITCH = "Switch"
    LOAD_BALANCER = "Load balancer"
    PROXY = "Proxy"
    WIRELESS = "Wireless"
    OTHER_NETWORK_DEVICE = "Other network device"


class CaptureStatus(StrEnum):
    WAITING = "waiting"
    PREPARING = "preparing"
    ANALYZING = "analyzing"
    ANALYZED = "analyzed"
    CORRELATING = "correlating"
    NEEDS_ATTENTION = "needs_attention"


TRANSITIONS = {
    State.NEW: {State.INGESTING, State.FAILED},
    State.INGESTING: {State.VALIDATING_CAPTURE, State.FAILED},
    State.VALIDATING_CAPTURE: {State.BASELINE_ANALYSIS, State.FAILED},
    State.BASELINE_ANALYSIS: {State.INVESTIGATING, State.FAILED},
    State.INVESTIGATING: {State.ASSEMBLING_REPORT, State.FAILED},
    State.ASSEMBLING_REPORT: {State.COMPLETE, State.FAILED},
    State.COMPLETE: {State.BASELINE_ANALYSIS},
    State.FAILED: {State.INGESTING, State.BASELINE_ANALYSIS},
}


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


def plain_label(value):
    if any(unicodedata.category(char).startswith("C") for char in value):
        raise ValueError("invalid_display_label")
    value = value.strip()
    if not value:
        raise ValueError("invalid_display_label")
    return value


def safe_capture_name(value):
    value = plain_label(value).replace("\\", "/").rsplit("/", 1)[-1].strip()
    if not value or value in (".", ".."):
        raise ValueError("invalid_capture_name")
    return value


class CreateCase(StrictModel):
    symptom: Annotated[str, Field(max_length=4096)]
    capture_name: Annotated[str, Field(max_length=255)] | None = None

    @field_validator("capture_name")
    @classmethod
    def safe_capture_name(cls, value):
        if value is None:
            return value
        return safe_capture_name(value)


class RenameCase(StrictModel):
    display_name: Annotated[str, Field(max_length=120)]

    @field_validator("display_name")
    @classmethod
    def safe_display_name(cls, value):
        return plain_label(value)


class CreateCapture(StrictModel):
    capture_name: Annotated[str, Field(max_length=255)]
    vantage_type: Annotated[CaptureVantage, Field(strict=False)] = CaptureVantage.UNKNOWN
    vantage_subtype: Annotated[CaptureNetworkSubtype, Field(strict=False)] | None = None

    @field_validator("capture_name")
    @classmethod
    def validate_capture_name(cls, value):
        return safe_capture_name(value)

    @model_validator(mode="after")
    def validate_subtype(self):
        if self.vantage_subtype is not None and self.vantage_type != CaptureVantage.NETWORK:
            raise ValueError("invalid_vantage_subtype")
        return self


class UpdateCapture(StrictModel):
    display_name: Annotated[str, Field(max_length=120)] | None = None
    vantage_type: Annotated[CaptureVantage, Field(strict=False)] | None = None
    vantage_subtype: Annotated[CaptureNetworkSubtype, Field(strict=False)] | None = None

    @field_validator("display_name")
    @classmethod
    def validate_display_name(cls, value):
        return plain_label(value) if value is not None else None

    @model_validator(mode="after")
    def validate_subtype(self):
        if self.vantage_subtype is not None and self.vantage_type not in (
            None,
            CaptureVantage.NETWORK,
        ):
            raise ValueError("invalid_vantage_subtype")
        return self


class FollowupRequest(StrictModel):
    question: Annotated[str, Field(min_length=1, max_length=2000)]

    @field_validator("question", mode="before")
    @classmethod
    def trim_question(cls, value):
        return value.strip() if isinstance(value, str) else value


class FollowupResponse(StrictModel):
    answer: Annotated[str, Field(min_length=1, max_length=4000)]
    evidence_ids: Annotated[
        list[Annotated[str, Field(min_length=1, max_length=256)]], Field(max_length=200)
    ]

    @field_validator("answer")
    @classmethod
    def nonblank_answer(cls, value):
        if not value.strip():
            raise ValueError("invalid_answer")
        return value

    @field_validator("evidence_ids")
    @classmethod
    def unique_evidence_ids(cls, value):
        return list(dict.fromkeys(value))


class RecentCaseResponse(StrictModel):
    id: str
    name: str
    capture_bytes: int | None
    created: str
    updated: str
    state: str


BASELINE = (
    "get_capture_metadata",
    "assess_capture_quality",
    "list_protocols",
    "list_endpoints",
    "list_conversations",
)
CAPABILITIES = (*BASELINE, *(c.value for c in Capability), "analyze_http_timing")


class CapabilityRequest(StrictModel):
    artifact_id: Annotated[str, Field(pattern=r"^[a-f0-9]{32}$")]
    capability: Annotated[str, Field(max_length=64, json_schema_extra={"enum": list(CAPABILITIES)})]
    tcp_stream: Annotated[int, Field(ge=0, le=2**31 - 1)] | None = None

    @model_validator(mode="after")
    def valid_capability(self):
        if self.capability not in CAPABILITIES:
            raise ValueError("invalid_capability")
        if self.tcp_stream is not None and self.capability in (
            *BASELINE,
            "analyze_dns",
            "analyze_fragmentation",
            "analyze_pmtud_signals",
        ):
            raise ValueError("invalid_stream_parameter")
        return self


FindingId = Annotated[str, Field(pattern=r"^[A-Za-z0-9_.-]{1,128}$")]
ArtifactId = Annotated[str, Field(pattern=r"^[a-f0-9]{32}$")]


class CaptureResponse(StrictModel):
    id: ArtifactId
    case_id: ArtifactId
    capture_name: Annotated[str, Field(max_length=255)]
    display_name: Annotated[str, Field(max_length=120)] | None
    original_artifact_id: ArtifactId | None
    sha256: Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")] | None
    bytes: Annotated[int, Field(ge=0)] | None
    vantage_type: Annotated[CaptureVantage, Field(strict=False)]
    vantage_subtype: Annotated[CaptureNetworkSubtype, Field(strict=False)] | None
    status: Annotated[CaptureStatus, Field(strict=False)]
    last_error: Annotated[str, Field(max_length=256)] | None
    created: Annotated[str, Field(max_length=64)]
    updated: Annotated[str, Field(max_length=64)]

    @field_validator("capture_name")
    @classmethod
    def validate_capture_name(cls, value):
        return safe_capture_name(value)

    @field_validator("display_name")
    @classmethod
    def validate_display_name(cls, value):
        return plain_label(value) if value is not None else None

    @model_validator(mode="after")
    def validate_subtype(self):
        if self.vantage_subtype is not None and self.vantage_type != CaptureVantage.NETWORK:
            raise ValueError("invalid_vantage_subtype")
        return self


class EvidenceCaptureRequest(StrictModel):
    finding_id: FindingId


class BridgeGrantRequest(StrictModel):
    artifact_id: ArtifactId
    finding_id: FindingId


class EvidenceCaptureProvenance(StrictModel):
    artifact_id: str
    parent_sha256: str
    case_id: str
    finding_id: str
    related_finding_ids: list[str]
    evidence_ids: list[str]
    extraction_mode: str
    extraction_rule: dict
    display_filter: str
    created: str
    tool_versions: dict[str, str]


class EvidenceCaptureResponse(StrictModel):
    artifact_id: str
    sha256: str
    bytes: int
    provenance: EvidenceCaptureProvenance


class BridgeGrantResponse(StrictModel):
    request_id: str
    token: str
    bridge_origin: str
    expires_unix: int


class ArtifactResponse(StrictModel):
    id: str
    kind: str
    sha256: str
    bytes: int
    parent_sha: str


class HistoryResponse(StrictModel):
    seq: int
    state: str
    at: str


class RunResponse(StrictModel):
    id: str
    case_id: str
    request_key: str
    capability: str
    parameters: dict
    status: str
    error: str | None
    versions: dict | None
    configuration: dict | None
    evidence_ids: list[str]
    created: str


class AIStatusResponse(StrictModel):
    effective_provider_mode: Literal[
        "none", "openai_compatible_cloud", "openai_compatible_local", "embedded_local"
    ]
    embedded_availability: Literal["ready", "unavailable", "not_applicable"]
    model: str | None
    failure_code: str | None


class CaseResponse(StrictModel):
    id: str
    name: str
    capture_name: str | None
    display_name: str | None
    symptom: str
    state: str
    created: str
    updated: str
    capture_sha: str | None
    original_id: str | None
    quality: str | None
    last_error: str | None
    history: list[HistoryResponse]
    runs: list[RunResponse]
    artifacts: list[ArtifactResponse]
    evidence_count: int
    gate_boundary: str
    provider_mode: str
    ai_status: AIStatusResponse


class HealthResponse(StrictModel):
    status: str
    gate: int
    provider_mode: str
    ai: AIStatusResponse


class CapabilitiesResponse(StrictModel):
    capabilities: list[str]
    provider_mode: str
    provider_modes_supported_by_interface: list[str]
    bridge: dict[str, str]
    limits: dict[str, int | float]
    ai: AIStatusResponse


class DeletionResponse(StrictModel):
    deleted: bool
    original_deleted: bool
    registered_artifacts_deleted: bool
    cleanup_pending: bool
