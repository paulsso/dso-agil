"""Base provider interfaces for model-agnostic execution."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class ProviderResponse:
    """Response normalized across model providers."""

    raw_text: str
    provider: str
    model: str


class LLMProvider(Protocol):
    """Minimal provider interface for prompt-to-text completion."""

    provider_name: str

    def complete(self, prompt: str) -> ProviderResponse:
        """Return a provider response for a prompt."""


class ProviderError(RuntimeError):
    """Raised when provider configuration or invocation fails."""
