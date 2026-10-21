"""Provider-neutral bounded request and result values."""

from dataclasses import dataclass


@dataclass(frozen=True)
class ReasoningRequest:
    model: str
    context_json: str
    system_instruction: str
    max_request_bytes: int
    max_response_bytes: int
    response_schema: dict | None = None


@dataclass(frozen=True)
class ProviderResult:
    content: str | None = None
    failure_code: str | None = None


class ProviderFailure(Exception):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)
