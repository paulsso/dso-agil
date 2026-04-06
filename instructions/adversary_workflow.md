# Standalone Adversary Workflow Contract

The adversary agent runs in sandbox mode and follows this exact stage order:

1. `LOAD_SCOPE`
2. `GATHER_INTELLIGENCE`
3. `GENERATE_ATTACK_HYPOTHESES`
4. `PROBE_ENDPOINTS`
5. `TRIAGE_ZERO_DAY_CANDIDATES`
6. `GENERATE_REPORT`
7. `EXIT_GATE`

## Scope and Safety
- Default scope is local targets only (`localhost` / loopback).
- Remote targets require explicit override via CLI option.
- This workflow is for authorized sandbox validation only.

## Intelligence Sources
- Static source-code intelligence from JS/TS files and dependency manifests.
- Runtime endpoint discovery from crawl + route extraction.
- Optional online vulnerability intelligence from OSV.

## Zero-Day Candidate Triage
- Candidate findings require runtime evidence and reproducible endpoint details.
- Prioritize high-impact classes: RCE/CMDi, SQLi, XSS, path traversal.
- Always include remediation guidance and risk gating output.
