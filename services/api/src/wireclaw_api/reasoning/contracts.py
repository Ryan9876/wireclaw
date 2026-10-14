"""Strict provider action schemas. Provider text never represents evidence."""

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, field_validator

from ..models import CAPABILITIES

EVIDENCE_ID = r"^ev_[a-f0-9]{64}_[a-z0-9_]+$"


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class CapabilityParameters(StrictModel):
    tcp_stream: Annotated[int, Field(ge=0, le=2**31 - 1)] | None = None


class CapabilityAction(StrictModel):
    action: Literal["request_capability"]
    capability: Annotated[str, Field(min_length=1, max_length=64)]
    parameters: CapabilityParameters

    @field_validator("capability")
    @classmethod
    def known_capability(cls, value):
        if value not in CAPABILITIES:
            raise ValueError("unknown_capability")
        return value


FaultDomain = Literal[
    "client",
    "local_network",
    "network_path",
    "server_application",
    "dns",
    "capture_observability",
    "unknown",
]


class HypothesisProposal(StrictModel):
    category: Annotated[str, Field(min_length=1, max_length=64)]
    evidence_ids: Annotated[list[Annotated[str, Field(pattern=EVIDENCE_ID)]], Field(max_length=32)]
    fault_domains: Annotated[list[FaultDomain], Field(max_length=7)]
    summary: Annotated[str, Field(max_length=512)]


class RemainingProposal(StrictModel):
    category: Annotated[str, Field(min_length=1, max_length=64)]
    evidence_ids: Annotated[list[Annotated[str, Field(pattern=EVIDENCE_ID)]], Field(max_length=32)]
    fault_domains: Annotated[list[FaultDomain], Field(max_length=7)]
    next_evidence: Annotated[list[Annotated[str, Field(max_length=180)]], Field(max_length=4)]


class FinalizeAction(StrictModel):
    action: Literal["finalize"]
    hypotheses: Annotated[list[HypothesisProposal], Field(max_length=16)]
    remaining_hypotheses: Annotated[list[RemainingProposal], Field(max_length=8)]


ModelAction = Annotated[CapabilityAction | FinalizeAction, Field(discriminator="action")]
ACTION_ADAPTER = TypeAdapter(ModelAction)
