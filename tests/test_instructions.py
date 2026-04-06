from devsecops_agent.instructions import compose_instructions


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
