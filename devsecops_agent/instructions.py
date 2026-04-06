"""Instruction loading and deterministic composition."""

from __future__ import annotations

from pathlib import Path
from typing import Iterable


def load_markdown(path: str | Path) -> str:
    """Load markdown text from disk."""

    return Path(path).read_text(encoding="utf-8")


def compose_instructions(
    base_instructions: str,
    custom_instructions: str | None = None,
    mode: str = "append",
) -> str:
    """Compose base and custom instructions using explicit strategy.

    mode:
      - append: base first, custom last
      - prepend: custom first, base last
      - replace: custom only (if provided), else base
    """

    custom = (custom_instructions or "").strip()
    base = base_instructions.strip()

    if mode == "replace":
        return custom or base
    if not custom:
        return base
    if mode == "prepend":
        return f"{custom}\n\n---\n\n{base}"
    if mode == "append":
        return f"{base}\n\n---\n\n{custom}"
    raise ValueError("mode must be one of: append, prepend, replace")


def flatten_sections(sections: Iterable[str]) -> str:
    """Join logical sections with stable separators."""

    cleaned = [s.strip() for s in sections if s and s.strip()]
    return "\n\n---\n\n".join(cleaned)
