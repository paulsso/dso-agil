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
4. `RUN_SCANNERS`
5. `RISK_SCORE`
6. `GENERATE_REPORT`
7. `EXIT_GATE`

See `instructions/predictable_workflow.md`.

## Local usage

Install locally:

`pip install -e .`

Run the full workflow:

`devsecops-agent --target https://example.com --provider openai --output-json devsecops_report.json`

Run with custom instructions prepended:

`devsecops-agent --target https://example.com --custom-instructions instructions/custom_instructions_example.md --custom-mode prepend`

Exit codes:

- `0` pass gate
- `2` blocked by security risk threshold

## Security tooling scripts

Individual scanners:

- `scripts/web_headers_scan.py`
- `scripts/web_methods_scan.py`
- `scripts/web_tls_scan.py`
- `scripts/web_crawler_scan.py`
- `scripts/web_input_probes.py`

Combined scanner run:

- `scripts/web_pentest_bundle.py --target https://example.com`

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

`docker run --rm devsecops-agent:openai --provider openai --target https://example.com`

## CI/CD integration pattern

Use as one job/stage:

1. Build or pull image for selected provider.
2. Run `devsecops-agent` against preview/staging target.
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
