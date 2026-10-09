"""Strict request contracts: no paths, executable names, flags or filters."""

from enum import StrEnum
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, model_validator
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


class CreateCase(StrictModel):
    symptom: Annotated[str, Field(max_length=4096)]


BASELINE = (
    "get_capture_metadata",
    "assess_capture_quality",
    "list_protocols",
    "list_endpoints",
    "list_conversations",
)
CAPABILITIES = (*BASELINE, *(c.value for c in Capability))


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


class CaseResponse(StrictModel):
    id: str
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


class DeletionResponse(StrictModel):
    deleted: bool
    original_deleted: bool
    registered_artifacts_deleted: bool
    cleanup_pending: bool
