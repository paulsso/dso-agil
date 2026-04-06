"""Probe risky HTTP methods using OPTIONS."""

from __future__ import annotations

from dataclasses import dataclass

import requests

from .common import DEFAULT_TIMEOUT, DEFAULT_UA, ensure_url


RISKY_METHODS = {"TRACE", "CONNECT"}


@dataclass(frozen=True)
class MethodIssue:
    method: str
    message: str


def run(target: str) -> list[MethodIssue]:
    url = ensure_url(target)
    response = requests.options(
        url,
        timeout=DEFAULT_TIMEOUT,
        headers={"User-Agent": DEFAULT_UA},
        allow_redirects=True,
    )
    allow = response.headers.get("Allow", "")
    methods = {m.strip().upper() for m in allow.split(",") if m.strip()}

    issues: list[MethodIssue] = []
    for method in sorted(RISKY_METHODS):
        if method in methods:
            issues.append(
                MethodIssue(
                    method=method,
                    message=f"Method {method} is enabled and may increase attack surface.",
                )
            )
    return issues
