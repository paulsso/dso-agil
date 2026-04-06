"""Light-weight non-destructive input probes for common issues."""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

import requests

from .common import DEFAULT_TIMEOUT, DEFAULT_UA, ensure_url


PAYLOADS = {
    "xss": "<script>alert('x')</script>",
    "sqli": "' OR '1'='1",
}


@dataclass(frozen=True)
class ProbeIssue:
    vector: str
    evidence: str
    recommendation: str


def _inject(url: str, payload: str) -> str:
    parsed = urlparse(url)
    query = parse_qs(parsed.query, keep_blank_values=True)
    if not query:
        query = {"q": [payload]}
    else:
        for key in list(query.keys()):
            query[key] = [payload]
    injected_qs = urlencode(query, doseq=True)
    return urlunparse(parsed._replace(query=injected_qs))


def run(target: str) -> list[ProbeIssue]:
    url = ensure_url(target)
    findings: list[ProbeIssue] = []

    for vector, payload in PAYLOADS.items():
        probe_url = _inject(url, payload)
        try:
            response = requests.get(
                probe_url,
                timeout=DEFAULT_TIMEOUT,
                headers={"User-Agent": DEFAULT_UA},
                allow_redirects=True,
            )
        except requests.RequestException:
            continue

        body = response.text.lower()
        if vector == "xss" and payload.lower() in body:
            findings.append(
                ProbeIssue(
                    vector="reflected-xss",
                    evidence=f"Reflected payload observed at {response.url}",
                    recommendation="HTML-encode user-controlled content in responses.",
                )
            )
        if vector == "sqli":
            sql_errors = [
                "sql syntax",
                "unterminated string",
                "odbc",
                "postgresql",
                "mysql",
            ]
            if any(token in body for token in sql_errors):
                findings.append(
                    ProbeIssue(
                        vector="possible-sql-injection",
                        evidence=f"Database error-like response at {response.url}",
                        recommendation="Use parameterized queries and suppress DB error output.",
                    )
                )

    return findings
