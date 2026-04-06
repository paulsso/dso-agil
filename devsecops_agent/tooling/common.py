"""Common helpers for web security scanners."""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

import requests


DEFAULT_TIMEOUT = 10
DEFAULT_UA = "devsecops-agent-loop/0.1"


@dataclass(frozen=True)
class HttpResult:
    url: str
    status_code: int
    headers: dict[str, str]
    body_preview: str


def ensure_url(value: str) -> str:
    if not value.startswith(("http://", "https://")):
        # Pre-deploy targets are expected to be local by default.
        value = f"http://{value}"
    parsed = urlparse(value)
    if not parsed.netloc:
        raise ValueError(f"Invalid URL: {value}")
    return value


def get(url: str, timeout: int = DEFAULT_TIMEOUT) -> HttpResult:
    response = requests.get(
        url,
        timeout=timeout,
        headers={"User-Agent": DEFAULT_UA},
        allow_redirects=True,
    )
    preview = response.text[:500].replace("\n", " ")
    return HttpResult(
        url=response.url,
        status_code=response.status_code,
        headers={k.lower(): v for k, v in response.headers.items()},
        body_preview=preview,
    )
