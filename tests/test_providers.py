from devsecops_agent.providers import get_provider
from devsecops_agent.providers.base import ProviderError


def test_get_provider_supported():
    assert get_provider("openai").provider_name == "openai"
    assert get_provider("anthropic").provider_name == "anthropic"
    assert get_provider("meta").provider_name == "meta"


def test_get_provider_unsupported():
    try:
        get_provider("unknown")
    except ProviderError:
        assert True
        return
    assert False, "Expected ProviderError"
