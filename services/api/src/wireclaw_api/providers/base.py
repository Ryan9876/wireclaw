"""Narrow provider abstraction; vendor and HTTP types do not escape this module."""

from typing import Protocol

from .models import ProviderResult, ReasoningRequest


class ReasoningProvider(Protocol):
    mode: str
    model: str

    def propose(self, request: ReasoningRequest) -> ProviderResult: ...
