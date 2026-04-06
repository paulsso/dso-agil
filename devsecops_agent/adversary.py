"""Standalone adversarial security agent for sandbox testing."""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable
from urllib.parse import urlencode, urljoin, urlparse
from uuid import uuid4

import requests

from .providers import get_provider
from .report import Finding, score_findings, should_block
from .tooling import crawler, source_audit

ADVERSARY_STAGES = [
    "LOAD_SCOPE",
    "GATHER_INTELLIGENCE",
    "GENERATE_ATTACK_HYPOTHESES",
    "PROBE_ENDPOINTS",
    "TRIAGE_ZERO_DAY_CANDIDATES",
    "GENERATE_REPORT",
    "EXIT_GATE",
]

FRAMEWORK_PACKAGE_MAP = {
    "React": "react",
    "Vue": "vue",
    "Angular": "@angular/core",
    "Next.js": "next",
    "Nuxt": "nuxt",
    "Svelte": "svelte",
}

SOURCE_ROUTE_RE = re.compile(
    r"(?:app|router)\.(?:get|post|put|delete|patch|use)\(\s*['\"]([^'\"]+)['\"]"
)
API_LITERAL_RE = re.compile(r"['\"](\/api\/[A-Za-z0-9_\-\/{\}\.:]+)['\"]")

SQL_ERROR_TOKENS = ("sql syntax", "unterminated string", "postgresql", "mysql", "odbc")
CMD_ERROR_TOKENS = ("/bin/sh", "not found", "command not recognized", "permission denied")
PASSWD_TOKENS = ("root:x:0:0", "daemon:x:1:1", "/bin/bash")


@dataclass(frozen=True)
class AdversaryConfig:
    target: str
    source_path: str
    provider: str
    output_json: str
    block_threshold: int = 80
    max_pages: int = 15
    max_endpoints: int = 20
    enable_online_intel: bool = True
    local_only: bool = True


@dataclass(frozen=True)
class AdversaryReport:
    workflow_id: str
    provider: str
    model: str
    target: str
    source_path: str
    hypotheses: str
    findings: list[Finding]
    score: int
    blocked: bool
    stages: list[str]


def _is_local_target(target: str) -> bool:
    parsed = urlparse(target if target.startswith(("http://", "https://")) else f"http://{target}")
    host = (parsed.hostname or "").lower()
    return host in {"localhost", "127.0.0.1", "::1"}


def _iter_js_ts_files(root: Path) -> list[Path]:
    exts = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
    skip = {"node_modules", "dist", "build", ".next", ".nuxt", ".git"}
    out: list[Path] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if any(part in skip for part in path.parts):
            continue
        if path.suffix.lower() in exts:
            out.append(path)
    return out


def _extract_source_routes(source_path: str, target: str, max_routes: int = 40) -> list[str]:
    root = Path(source_path).resolve()
    base = target if target.startswith(("http://", "https://")) else f"http://{target}"
    routes: set[str] = set()

    for file_path in _iter_js_ts_files(root):
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        for match in SOURCE_ROUTE_RE.findall(content):
            if not match.startswith("/"):
                continue
            routes.add(urljoin(base.rstrip("/") + "/", match.lstrip("/")))
        for match in API_LITERAL_RE.findall(content):
            routes.add(urljoin(base.rstrip("/") + "/", match.lstrip("/")))

        if len(routes) >= max_routes:
            break

    return sorted(routes)[:max_routes]


def _severity_from_cvss_string(score: str) -> str:
    match = re.search(r"CVSS:\d\.\d\/AV:[^/]+/AC:[^/]+/PR:[^/]+/UI:[^/]+/S:[^/]+/C:[^/]+/I:[^/]+/A:[^/]+(?:\/E:[^/]+)?", score)
    if not match:
        return "high"
    base_match = re.search(r"/A:[A-Z]", match.group(0))
    if not base_match:
        return "high"
    # OSV may not always include numeric base score; use conservative severity fallback.
    return "high"


def _query_framework_intel(frameworks: list[str], timeout: int = 4) -> list[Finding]:
    findings: list[Finding] = []
    for framework in frameworks:
        package_name = FRAMEWORK_PACKAGE_MAP.get(framework)
        if not package_name:
            continue
        payload = {"package": {"name": package_name, "ecosystem": "npm"}}
        try:
            response = requests.post("https://api.osv.dev/v1/query", json=payload, timeout=timeout)
            response.raise_for_status()
        except requests.RequestException as exc:
            findings.append(
                Finding(
                    scanner="adversary_intel",
                    title=f"Framework intelligence unavailable for {framework}",
                    severity="info",
                    evidence=str(exc),
                    recommendation="Ensure sandbox has internet egress if online intelligence is required.",
                )
            )
            continue

        for vuln in response.json().get("vulns", [])[:2]:
            vuln_id = vuln.get("id", "unknown-id")
            summary = vuln.get("summary") or "No summary provided"
            severity_entries = vuln.get("severity") or []
            severity = "high"
            if severity_entries:
                severity = _severity_from_cvss_string(str(severity_entries[0].get("score", "")))
            findings.append(
                Finding(
                    scanner="adversary_intel",
                    title=f"Critical framework intelligence: {framework}",
                    severity=severity,
                    evidence=f"{vuln_id}: {summary}",
                    recommendation=f"Review '{framework}' usage paths and patch affected versions quickly.",
                )
            )
    return findings


def _probe_endpoints(endpoints: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    payloads = {
        "xss": "<svg/onload=alert(1)>",
        "sqli": "' OR '1'='1",
        "cmdi": ";id",
        "path_traversal": "../../../../etc/passwd",
    }

    for endpoint in endpoints:
        for vector, payload in payloads.items():
            params = {"q": payload} if vector != "path_traversal" else {"file": payload}
            probe_url = f"{endpoint}?{urlencode(params)}"
            try:
                response = requests.get(probe_url, timeout=6, allow_redirects=True)
            except requests.RequestException:
                continue

            body = response.text.lower()
            if response.status_code >= 500:
                findings.append(
                    Finding(
                        scanner="adversary_probe",
                        title="Server error under adversarial input",
                        severity="high",
                        evidence=f"{response.url} -> HTTP {response.status_code}",
                        recommendation="Inspect stack traces/logs and harden input handling on this path.",
                    )
                )

            if vector == "xss" and payload.lower() in body:
                findings.append(
                    Finding(
                        scanner="adversary_probe",
                        title="Potential reflected XSS zero-day candidate",
                        severity="critical",
                        evidence=f"Payload reflected at {response.url}",
                        recommendation="Apply output encoding and context-specific sanitization.",
                    )
                )

            if vector == "sqli" and any(token in body for token in SQL_ERROR_TOKENS):
                findings.append(
                    Finding(
                        scanner="adversary_probe",
                        title="Potential SQL injection zero-day candidate",
                        severity="critical",
                        evidence=f"Database error-like response at {response.url}",
                        recommendation="Use parameterized queries and suppress DB error messages.",
                    )
                )

            if vector == "cmdi" and any(token in body for token in CMD_ERROR_TOKENS):
                findings.append(
                    Finding(
                        scanner="adversary_probe",
                        title="Potential command injection zero-day candidate",
                        severity="critical",
                        evidence=f"Shell error-like output at {response.url}",
                        recommendation="Remove shell execution on untrusted inputs.",
                    )
                )

            if vector == "path_traversal" and any(token in body for token in PASSWD_TOKENS):
                findings.append(
                    Finding(
                        scanner="adversary_probe",
                        title="Potential path traversal zero-day candidate",
                        severity="critical",
                        evidence=f"Sensitive file-like content at {response.url}",
                        recommendation="Constrain file access to allowlisted directories and canonicalized paths.",
                    )
                )

    return findings


def _report_to_dict(report: AdversaryReport) -> dict:
    payload = asdict(report)
    payload["findings"] = [asdict(f) for f in report.findings]
    return payload


def run_adversary(config: AdversaryConfig, logger: Callable[[str], None] | None = None) -> AdversaryReport:
    """Run standalone adversarial workflow and emit report JSON."""

    log = logger or (lambda _: None)
    workflow_id = str(uuid4())

    if config.local_only and not _is_local_target(config.target):
        raise ValueError("Adversary agent local_only mode requires a localhost/loopback target.")

    log(f"[{workflow_id}] Stage: {ADVERSARY_STAGES[0]}")

    log(f"[{workflow_id}] Stage: {ADVERSARY_STAGES[1]}")
    source_issues = source_audit.run(
        source_path=config.source_path,
        enable_online_intel=config.enable_online_intel,
    )
    findings: list[Finding] = [
        Finding(
            scanner="source_audit",
            title=issue.title,
            severity=issue.severity,
            evidence=issue.evidence,
            recommendation=issue.recommendation,
        )
        for issue in source_issues
    ]
    frameworks = [
        issue.title.split(":", 1)[1].strip()
        for issue in source_issues
        if issue.title.startswith("Framework detected:")
    ]
    if config.enable_online_intel:
        findings.extend(_query_framework_intel(frameworks))

    log(f"[{workflow_id}] Stage: {ADVERSARY_STAGES[2]}")
    provider = get_provider(config.provider)
    page_urls = [p.url for p in crawler.run(config.target, max_pages=config.max_pages)]
    source_routes = _extract_source_routes(config.source_path, config.target)
    endpoints = sorted({*page_urls, *source_routes})[: config.max_endpoints]
    prompt = (
        "You are an adversarial security tester in a sandbox. "
        "Generate compact exploit hypotheses from this intelligence.\n\n"
        f"TARGET={config.target}\n"
        f"ENDPOINTS={endpoints}\n"
        f"SOURCE_FINDING_COUNT={len(source_issues)}\n"
        "Return only concise bullet hypotheses."
    )
    hypotheses_response = provider.complete(prompt)

    log(f"[{workflow_id}] Stage: {ADVERSARY_STAGES[3]}")
    findings.extend(_probe_endpoints(endpoints))

    log(f"[{workflow_id}] Stage: {ADVERSARY_STAGES[4]}")
    score = score_findings(findings)
    blocked = should_block(score, config.block_threshold)

    log(f"[{workflow_id}] Stage: {ADVERSARY_STAGES[5]}")
    report = AdversaryReport(
        workflow_id=workflow_id,
        provider=hypotheses_response.provider,
        model=hypotheses_response.model,
        target=config.target,
        source_path=config.source_path,
        hypotheses=hypotheses_response.raw_text,
        findings=findings,
        score=score,
        blocked=blocked,
        stages=ADVERSARY_STAGES,
    )
    Path(config.output_json).write_text(json.dumps(_report_to_dict(report), indent=2), encoding="utf-8")

    log(f"[{workflow_id}] Stage: {ADVERSARY_STAGES[6]}")
    return report
