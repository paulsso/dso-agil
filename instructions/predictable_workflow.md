# Predictable Workflow Contract

Every run MUST execute the same stages in this exact order:

1. `LOAD_CONTEXT`
2. `COMPOSE_INSTRUCTIONS`
3. `PLAN_SCAN`
4. `RUN_SCANNERS`
5. `RISK_SCORE`
6. `GENERATE_REPORT`
7. `EXIT_GATE`

## Stage Definitions

### 1) LOAD_CONTEXT
Load base instructions and optional custom instructions.

### 2) COMPOSE_INSTRUCTIONS
Combine base and custom instructions using one explicit mode:
- `append`
- `prepend`
- `replace`

### 3) PLAN_SCAN
Request a concise scan plan from selected model provider.
This stage influences planning text only, not stage ordering.

### 4) RUN_SCANNERS
Execute all scanner modules in deterministic sequence:
1. headers scanner
2. methods scanner
3. tls scanner
4. crawler
5. input probes

### 5) RISK_SCORE
Map findings to severities and compute aggregate score.

### 6) GENERATE_REPORT
Emit JSON report with immutable workflow metadata.

### 7) EXIT_GATE
Exit with pipeline-compatible status:
- `0`: pass
- `2`: blocked by security threshold

## Determinism Rules
- Stage order is fixed and cannot be skipped.
- Scanner ordering is fixed.
- Report schema is stable between runs.
- Dry-run model mode is deterministic when API keys are absent.
