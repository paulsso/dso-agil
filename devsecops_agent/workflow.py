"""Predictable workflow execution for every run."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Callable
from uuid import uuid4

from .constants import WORKFLOW_STAGES
from .instructions import compose_instructions, load_markdown
from .providers import get_provider
from .report import Finding, RunReport, now_utc_iso, score_findings, should_block, to_dict
from .tooling import crawler, headers_scan, methods_scan, probes, tls_scan


@dataclass(frozen=True)
class WorkflowConfig:
    target: str
    provider: str
    base_instructions_path: str
    custom_instructions_path: str | None
    custom_mode: str
    block_threshold: int
    output_json: str


def _to_finding(scanner: str, severity: str, title: str, evidence: str, rec: str) -> Finding:
    return Finding(
        scanner=scanner,
        severity=severity,
        title=title,
        evidence=evidence,
        recommendation=rec,
    )


def _scan_all(target: str) -> list[Finding]:
    findings: list[Finding] = []

    for issue in headers_scan.run(target):
        findings.append(
            _to_finding(
                "headers_scan",
                "medium",
                f"Missing security header: {issue.header}",
                issue.message,
                "Set the recommended security header at ingress or app layer.",
            )
        )

    for issue in methods_scan.run(target):
        findings.append(
            _to_finding(
                "methods_scan",
                "medium",
                f"Risky HTTP method enabled: {issue.method}",
                issue.message,
                "Disable unnecessary HTTP methods at the web server/reverse proxy.",
            )
        )

    for issue in tls_scan.run(target):
        findings.append(
            _to_finding(
                "tls_scan",
                "high",
                issue.title,
                issue.detail,
                "Harden TLS configuration and certificate lifecycle monitoring.",
            )
        )

    crawled = crawler.run(target)
    error_pages = [p for p in crawled if p.status_code >= 500]
    for page in error_pages:
        findings.append(
            _to_finding(
                "crawler",
                "low",
                "Server error discovered during crawl",
                f"Endpoint {page.url} returned HTTP {page.status_code}",
                "Inspect upstream logs and stabilize endpoint behavior.",
            )
        )

    for issue in probes.run(target):
        severity = "high" if "sql" in issue.vector else "critical"
        findings.append(
            _to_finding(
                "probes",
                severity,
                f"Input handling issue: {issue.vector}",
                issue.evidence,
                issue.recommendation,
            )
        )

    return findings


def run_workflow(config: WorkflowConfig, logger: Callable[[str], None] | None = None) -> RunReport:
    """Run all workflow stages in fixed order and emit a JSON report."""

    log = logger or (lambda _: None)
    workflow_id = str(uuid4())

    log(f"[{workflow_id}] Stage: {WORKFLOW_STAGES[0]}")
    base = load_markdown(config.base_instructions_path)
    custom = load_markdown(config.custom_instructions_path) if config.custom_instructions_path else None

    log(f"[{workflow_id}] Stage: {WORKFLOW_STAGES[1]}")
    combined = compose_instructions(base, custom, config.custom_mode)

    log(f"[{workflow_id}] Stage: {WORKFLOW_STAGES[2]}")
    provider = get_provider(config.provider)
    plan_prompt = (
        "Generate a concise security scan plan for the target and required evidence.\n\n"
        f"TARGET: {config.target}\n\n"
        f"INSTRUCTIONS:\n{combined}"
    )

    plan_response = provider.complete(plan_prompt)
    log(f"[{workflow_id}] provider_plan={plan_response.raw_text}")

    log(f"[{workflow_id}] Stage: {WORKFLOW_STAGES[3]}")
    findings = _scan_all(config.target)

    log(f"[{workflow_id}] Stage: {WORKFLOW_STAGES[4]}")
    score = score_findings(findings)
    blocked = should_block(score, config.block_threshold)

    log(f"[{workflow_id}] Stage: {WORKFLOW_STAGES[5]}")
    report = RunReport(
        workflow_id=workflow_id,
        provider=plan_response.provider,
        model=plan_response.model,
        target=config.target,
        findings=findings,
        score=score,
        blocked=blocked,
        generated_at=now_utc_iso(),
    )

    Path(config.output_json).write_text(
        json.dumps(to_dict(report), indent=2),
        encoding="utf-8",
    )

    log(f"[{workflow_id}] Stage: {WORKFLOW_STAGES[6]}")
    return report
