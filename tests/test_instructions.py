from devsecops_agent.instructions import compose_instructions
from devsecops_agent.tooling.common import ensure_url


def test_compose_append_mode():
    out = compose_instructions("base", "custom", "append")
    assert out.startswith("base")
    assert out.endswith("custom")


def test_compose_prepend_mode():
    out = compose_instructions("base", "custom", "prepend")
    assert out.startswith("custom")
    assert out.endswith("base")


def test_compose_replace_mode():
    out = compose_instructions("base", "custom", "replace")
    assert out == "custom"


def test_ensure_url_defaults_to_http_for_local_targets():
    out = ensure_url("127.0.0.1:8080")
    assert out == "http://127.0.0.1:8080"
