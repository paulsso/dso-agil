"""Small deterministic crawler for endpoint discovery."""

from __future__ import annotations

import re
from collections import deque
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

import requests

from .common import DEFAULT_TIMEOUT, DEFAULT_UA, ensure_url


HREF_RE = re.compile(r'href=["\\\']([^"\\\'#]+)')


@dataclass(frozen=True)
class CrawledPage:
    url: str
    status_code: int


def run(target: str, max_pages: int = 15) -> list[CrawledPage]:
    root = ensure_url(target)
    root_host = urlparse(root).netloc

    seen: set[str] = set()
    queue: deque[str] = deque([root])
    pages: list[CrawledPage] = []

    while queue and len(pages) < max_pages:
        url = queue.popleft()
        if url in seen:
            continue
        seen.add(url)

        try:
            response = requests.get(
                url,
                timeout=DEFAULT_TIMEOUT,
                headers={"User-Agent": DEFAULT_UA},
                allow_redirects=True,
            )
        except requests.RequestException:
            continue

        final_url = response.url
        pages.append(CrawledPage(url=final_url, status_code=response.status_code))

        content_type = response.headers.get("Content-Type", "")
        if "text/html" not in content_type.lower():
            continue

        for match in HREF_RE.findall(response.text):
            joined = urljoin(final_url, match)
            parsed = urlparse(joined)
            if parsed.scheme not in {"http", "https"}:
                continue
            if parsed.netloc != root_host:
                continue
            if joined not in seen:
                queue.append(joined)

    return pages
