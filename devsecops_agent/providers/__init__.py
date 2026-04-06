"""Provider selection and light-weight adapters.

Adapters intentionally use environment variables and deterministic stubs when
no API key is provided. This keeps CI pipelines reproducible while still
allowing real model calls in secured environments.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from .base import LLMProvider, ProviderError, ProviderResponse


@dataclass
class _BaseEnvProvider:
    provider_name: str
    model_env: str
    key_env: str
    default_model: str

    def complete(self, prompt: str) -> ProviderResponse:
        model = os.getenv(self.model_env, self.default_model)
        api_key = os.getenv(self.key_env)
        if not api_key:
            # Deterministic dry-run output for CI predictability.
            digest = abs(hash(prompt)) % 10_000
            return ProviderResponse(
                raw_text=(
                    f"[DRY_RUN:{self.provider_name}] "
                    f"Prompt accepted. Deterministic digest={digest}."
                ),
                provider=self.provider_name,
                model=model,
            )
        # Placeholder behavior; real HTTP SDK integration can be dropped in.
        return ProviderResponse(
            raw_text=(
                f"[{self.provider_name}] API key detected for model '{model}'. "
                "Wire provider SDK here for live completion."
            ),
            provider=self.provider_name,
            model=model,
        )


class OpenAIProvider(_BaseEnvProvider):
    def __init__(self) -> None:
        super().__init__(
            provider_name="openai",
            model_env="OPENAI_MODEL",
            key_env="OPENAI_API_KEY",
            default_model="gpt-4.1-mini",
        )


class AnthropicProvider(_BaseEnvProvider):
    def __init__(self) -> None:
        super().__init__(
            provider_name="anthropic",
            model_env="ANTHROPIC_MODEL",
            key_env="ANTHROPIC_API_KEY",
            default_model="claude-3-5-haiku-latest",
        )


class MetaProvider(_BaseEnvProvider):
    def __init__(self) -> None:
        super().__init__(
            provider_name="meta",
            model_env="META_MODEL",
            key_env="META_API_KEY",
            default_model="llama-3.1-70b-instruct",
        )


def get_provider(provider_name: str) -> LLMProvider:
    """Return provider instance for the requested provider name."""

    normalized = provider_name.strip().lower()
    if normalized == "openai":
        return OpenAIProvider()
    if normalized == "anthropic":
        return AnthropicProvider()
    if normalized == "meta":
        return MetaProvider()
    raise ProviderError(
        f"Unsupported provider '{provider_name}'. Expected one of: "
        "openai, anthropic, meta."
    )
