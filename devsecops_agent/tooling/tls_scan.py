"""Inspect TLS posture for a target host."""

from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass
from urllib.parse import urlparse

from .common import ensure_url


@dataclass(frozen=True)
class TlsIssue:
    title: str
    detail: str


def _hostname_from_target(target: str) -> str:
    parsed = urlparse(ensure_url(target))
    if not parsed.hostname:
        raise ValueError("Target hostname cannot be resolved.")
    return parsed.hostname


def run(target: str, port: int = 443) -> list[TlsIssue]:
    hostname = _hostname_from_target(target)
    context = ssl.create_default_context()

    with socket.create_connection((hostname, port), timeout=8) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
            cipher = tls_sock.cipher()
            cert = tls_sock.getpeercert()

    issues: list[TlsIssue] = []

    if cipher and "RC4" in cipher[0].upper():
        issues.append(TlsIssue("Weak cipher", f"Negotiated cipher: {cipher[0]}"))

    not_after = cert.get("notAfter") if cert else None
    if not not_after:
        issues.append(TlsIssue("Certificate metadata missing", "No notAfter field found."))

    return issues
