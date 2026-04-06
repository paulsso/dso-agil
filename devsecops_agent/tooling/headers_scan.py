"""Check for baseline security headers."""

from __future__ import annotations

from dataclasses import dataclass

from .common import ensure_url, get


RECOMMENDED_HEADERS = {
    "strict-transport-security": "Enforce HTTPS with HSTS.",
    "content-security-policy": "Mitigate XSS with CSP.",
    "x-content-type-options": "Prevent MIME sniffing.",
    "x-frame-options": "Prevent clickjacking.",
    "referrer-policy": "Reduce referrer data leakage.",
}


@dataclass(frozen=True)
class HeaderIssue:
    header: str
    message: str


def run(target: str) -> list[HeaderIssue]:
    url = ensure_url(target)
    result = get(url)
    missing = []
    for header, message in RECOMMENDED_HEADERS.items():
        if header not in result.headers:
            missing.append(HeaderIssue(header=header, message=message))
    return missing
