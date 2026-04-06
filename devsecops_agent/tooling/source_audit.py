"""Static source-code audit for JavaScript/TypeScript web applications."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

import requests

JS_EXTENSIONS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
SKIP_DIRS = {
    ".git",
    "node_modules",
    "dist",
    "build",
    ".next",
    ".nuxt",
    "coverage",
}

FRAMEWORK_PACKAGES = {
    "react": "React",
    "vue": "Vue",
    "@angular/core": "Angular",
    "next": "Next.js",
    "nuxt": "Nuxt",
    "svelte": "Svelte",
}

CODE_PATTERNS: list[tuple[str, re.Pattern[str], str, str]] = [
    (
        "high",
        re.compile(r"\beval\s*\("),
        "Dynamic code execution via eval",
        "Avoid eval; use structured parsing and safe dispatch tables.",
    ),
    (
        "high",
        re.compile(r"\bnew\s+Function\s*\("),
        "Dynamic code execution via Function constructor",
        "Avoid dynamic code generation and refactor to static functions.",
    ),
    (
        "high",
        re.compile(r"\bchild_process\.(exec|execSync)\s*\("),
        "Process execution from application code",
        "Validate/whitelist inputs and avoid shell execution paths.",
    ),
    (
        "medium",
        re.compile(r"\bdangerouslySetInnerHTML\b"),
        "Potential unsafe HTML rendering",
        "Sanitize HTML and avoid rendering untrusted markup.",
    ),
    (
        "medium",
        re.compile(r"\binnerHTML\s*="),
        "Potential DOM XSS sink via innerHTML",
        "Use textContent/templating safeguards and sanitize content.",
    ),
]

SECRET_PATTERNS: list[tuple[str, re.Pattern[str], str, str]] = [
    (
        "critical",
        re.compile(r"-----BEGIN (RSA |EC )?PRIVATE KEY-----"),
        "Private key material in source tree",
        "Remove keys from source control and rotate exposed credentials.",
    ),
    (
        "high",
        re.compile(r"(?i)(api[_-]?key|secret|token)\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]"),
        "Possible hardcoded credential",
        "Move secrets to managed secret storage and rotate exposed values.",
    ),
]

OSV_QUERY_URL = "https://api.osv.dev/v1/query"


@dataclass(frozen=True)
class SourceIssue:
    severity: str
    title: str
    evidence: str
    recommendation: str


def _iter_source_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.suffix.lower() in JS_EXTENSIONS:
            files.append(path)
    return files


def _detect_package_managers(root: Path) -> list[str]:
    markers = {
        "npm": ["package-lock.json", "npm-shrinkwrap.json"],
        "yarn": ["yarn.lock"],
        "pnpm": ["pnpm-lock.yaml"],
        "bun": ["bun.lockb", "bun.lock"],
    }
    found: list[str] = []
    for manager, files in markers.items():
        if any((root / marker).exists() for marker in files):
            found.append(manager)
    return sorted(found)


def _load_package_json_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for path in sorted(root.rglob("package.json")):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        files.append(path)
    return files


def _collect_dependencies(package_json_files: list[Path]) -> set[str]:
    deps: set[str] = set()
    sections = ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies")
    for pkg_file in package_json_files:
        try:
            payload = json.loads(pkg_file.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        for section in sections:
            section_values = payload.get(section, {})
            if isinstance(section_values, dict):
                deps.update(section_values.keys())
    return deps


def _detect_frameworks(dependencies: set[str]) -> list[str]:
    found = [framework for dep, framework in FRAMEWORK_PACKAGES.items() if dep in dependencies]
    return sorted(found)


def _scan_source_patterns(source_files: list[Path]) -> list[SourceIssue]:
    issues: list[SourceIssue] = []
    for file_path in source_files:
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        for severity, regex, title, recommendation in CODE_PATTERNS:
            match = regex.search(content)
            if not match:
                continue
            line = content.count("\n", 0, match.start()) + 1
            issues.append(
                SourceIssue(
                    severity=severity,
                    title=title,
                    evidence=f"{file_path}:{line}",
                    recommendation=recommendation,
                )
            )

        for severity, regex, title, recommendation in SECRET_PATTERNS:
            match = regex.search(content)
            if not match:
                continue
            line = content.count("\n", 0, match.start()) + 1
            issues.append(
                SourceIssue(
                    severity=severity,
                    title=title,
                    evidence=f"{file_path}:{line}",
                    recommendation=recommendation,
                )
            )

    return issues


def _severity_from_osv(vuln: dict) -> str:
    severities = vuln.get("severity") or []
    for item in severities:
        score = item.get("score", "")
        if isinstance(score, str) and score.startswith("CVSS:"):
            try:
                cvss = float(score.split("/")[1])
            except (IndexError, ValueError):
                continue
            if cvss >= 9.0:
                return "critical"
            if cvss >= 7.0:
                return "high"
            if cvss >= 4.0:
                return "medium"
            return "low"
    return "high"


def _query_osv_for_package(package_name: str, timeout: int = 4) -> list[SourceIssue]:
    payload = {"package": {"name": package_name, "ecosystem": "npm"}}
    response = requests.post(OSV_QUERY_URL, json=payload, timeout=timeout)
    response.raise_for_status()
    data = response.json()

    issues: list[SourceIssue] = []
    for vuln in data.get("vulns", [])[:3]:
        vuln_id = vuln.get("id", "unknown-id")
        summary = vuln.get("summary") or "No summary provided"
        severity = _severity_from_osv(vuln)
        issues.append(
            SourceIssue(
                severity=severity,
                title=f"Known dependency vulnerability: {package_name}",
                evidence=f"{vuln_id} - {summary}",
                recommendation=f"Upgrade '{package_name}' to a patched version and review transitive dependencies.",
            )
        )
    return issues


def run(
    source_path: str,
    enable_online_intel: bool = True,
    max_online_packages: int = 10,
) -> list[SourceIssue]:
    root = Path(source_path).resolve()
    if not root.exists() or not root.is_dir():
        raise ValueError(f"Invalid source path: {source_path}")

    source_files = _iter_source_files(root)
    package_json_files = _load_package_json_files(root)
    dependencies = _collect_dependencies(package_json_files)
    frameworks = _detect_frameworks(dependencies)
    managers = _detect_package_managers(root)

    issues = _scan_source_patterns(source_files)

    if package_json_files:
        issues.append(
            SourceIssue(
                severity="info",
                title="JavaScript dependency manifests detected",
                evidence=f"package.json files={len(package_json_files)}; managers={','.join(managers) or 'unknown'}",
                recommendation="Ensure dependency lock files are committed and dependency review runs in CI.",
            )
        )

    for framework in frameworks:
        issues.append(
            SourceIssue(
                severity="info",
                title=f"Framework detected: {framework}",
                evidence="Framework-specific checks can be extended via custom instructions.",
                recommendation="Track framework security advisories and update promptly.",
            )
        )

    if enable_online_intel and dependencies:
        online_errors = 0
        for package_name in sorted(dependencies)[:max_online_packages]:
            try:
                issues.extend(_query_osv_for_package(package_name))
            except requests.RequestException as exc:
                online_errors += 1
                if online_errors == 1:
                    issues.append(
                        SourceIssue(
                            severity="info",
                            title="Online vulnerability intelligence unavailable",
                            evidence=str(exc),
                            recommendation="Check network egress/policy and rerun with online intel enabled.",
                        )
                    )

    return issues
