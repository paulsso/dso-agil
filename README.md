# DevSecOps Agent in the Loop

A modular, model-agnostic security gate that can run as a CI/CD stage on any platform.

## What this project provides

- Predictable workflow contract for every run.
- Markdown instruction packs for base policy and customization.
- Python web security tooling modules and CLI scripts.
- Model-specific Dockerfiles for OpenAI, Anthropic, and Meta providers.
- Machine-readable JSON output for pipeline gating and auditability.

## Repository layout

- `instructions/`
  - `base_security_agent.md`
  - `predictable_workflow.md`
  - `customization_guide.md`
  - `custom_instructions_example.md`
- `devsecops_agent/`
  - `workflow.py` deterministic execution orchestration
  - `instructions.py` base/custom composition logic
  - `providers/` model-agnostic adapter interface + provider selection
  - `tooling/` reusable web security scanners
  - `report.py` stable scoring and reporting utilities
- `scripts/` stand-alone scanner wrappers and CI entrypoint
- `docker/` provider-specific Dockerfiles

## Predictable workflow (always fixed)

The workflow always runs these stages in this exact order:

1. `LOAD_CONTEXT`
2. `COMPOSE_INSTRUCTIONS`
3. `PLAN_SCAN`
4. `ANALYZE_SOURCE_CODE`
5. `RUN_SCANNERS`
6. `RISK_SCORE`
7. `GENERATE_REPORT`
8. `EXIT_GATE`

See `instructions/predictable_workflow.md`.

## Local usage

Install locally:

`pip install -e .`

Run the full workflow against a local pre-deploy target:

`devsecops-agent --target http://127.0.0.1:8080 --provider openai --source-path . --output-json devsecops_report.json`

Run with custom instructions prepended:

`devsecops-agent --target http://127.0.0.1:8080 --custom-instructions instructions/custom_instructions_example.md --custom-mode prepend`

Exit codes:

- `0` pass gate
- `2` blocked by security risk threshold

## Source-code stage (`ANALYZE_SOURCE_CODE`)

This stage audits JS/TS web application source code before runtime scans:

- Package-manager agnostic: detects npm/yarn/pnpm/bun markers.
- JavaScript variant agnostic: scans `.js`, `.jsx`, `.ts`, `.tsx`, `.mjs`, `.cjs`.
- Framework agnostic: works without requiring framework-specific parsers.
- Framework-aware: identifies common frameworks (React/Vue/Angular/Next/Nuxt/Svelte) from dependencies and emits informational findings.
- Online intelligence (optional): queries OSV for npm package vulnerabilities.

CLI flags:

- `--source-path` source directory to analyze (default `.`)
- `--disable-online-intel` disable OSV online dependency vulnerability lookups

## Standalone adversary agent (sandbox)

Use `devsecops-adversary` to run an attacker-mode workflow in a local sandbox.

Workflow stages:

1. `LOAD_SCOPE`
2. `GATHER_INTELLIGENCE`
3. `GENERATE_ATTACK_HYPOTHESES`
4. `PROBE_ENDPOINTS`
5. `TRIAGE_ZERO_DAY_CANDIDATES`
6. `GENERATE_REPORT`
7. `EXIT_GATE`

Capabilities:

- Uses source code + runtime endpoint intelligence together.
- Generates exploit hypotheses using selected model provider.
- Probes endpoints for high-signal zero-day candidate behaviors (XSS/SQLi/CMDi/path traversal indicators).
- Local-target safety by default (`localhost`/loopback only unless explicitly overridden).
- Optional online intelligence from OSV for framework/dependency advisories.

Example:

`devsecops-adversary --target http://127.0.0.1:8080 --source-path . --output-json adversary_report.json`

Script wrapper:

- `scripts/run_adversary_agent.py`

## Security tooling scripts

Individual scanners:

- `scripts/web_headers_scan.py`
- `scripts/web_methods_scan.py`
- `scripts/web_tls_scan.py`
- `scripts/web_crawler_scan.py`
- `scripts/web_input_probes.py`

Combined scanner run:

- `scripts/web_pentest_bundle.py --target http://127.0.0.1:8080`

## Docker images

Provider-specific Dockerfiles:

- `docker/Dockerfile.openai`
- `docker/Dockerfile.anthropic`
- `docker/Dockerfile.meta`

Example builds:

- `docker build -f docker/Dockerfile.openai -t devsecops-agent:openai .`
- `docker build -f docker/Dockerfile.anthropic -t devsecops-agent:anthropic .`
- `docker build -f docker/Dockerfile.meta -t devsecops-agent:meta .`

Example run:

`docker run --rm --network host devsecops-agent:openai --provider openai --target http://127.0.0.1:8080`

## CI/CD integration pattern

Use as one job/stage:

1. Build or pull image for selected provider.
2. Run `devsecops-agent` against a local pre-deploy target (for example `http://127.0.0.1:8080`).
3. Persist `devsecops_report.json` as artifact.
4. Fail gate automatically when command exits with code `2`.

This pattern works across GitHub Actions, GitLab CI, Jenkins, Azure DevOps, CircleCI, and others.

## Notes on model providers

Provider adapters are environment-based and deterministic in dry-run mode (no API key), which keeps pipelines reproducible in restricted environments.

Environment variables used:

- OpenAI: `OPENAI_API_KEY`, `OPENAI_MODEL`
- Anthropic: `ANTHROPIC_API_KEY`, `ANTHROPIC_MODEL`
- Meta: `META_API_KEY`, `META_MODEL`

## Tests

Run targeted tests:

`python -m pytest tests -q`
