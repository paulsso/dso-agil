"""Report and scoring utilities."""

from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Iterable

from .constants import SEVERITY_WEIGHTS


@dataclass(frozen=True)
class Finding:
    scanner: str
    title: str
    severity: str
    evidence: str
    recommendation: str


@dataclass(frozen=True)
class RunReport:
    workflow_id: str
    provider: str
    model: str
    target: str
    findings: list[Finding]
    score: int
    blocked: bool
    generated_at: str


def score_findings(findings: Iterable[Finding]) -> int:
    """Compute risk score from finding severities."""

    return sum(SEVERITY_WEIGHTS.get(f.severity.lower(), 0) for f in findings)


def should_block(score: int, threshold: int) -> bool:
    """Determine if release should be blocked."""

    return score >= threshold


def to_dict(report: RunReport) -> dict:
    payload = asdict(report)
    payload["findings"] = [asdict(f) for f in report.findings]
    return payload


def now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
