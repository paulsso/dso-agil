# Custom Instruction Composition Guide

The agent supports organization-specific policy injection without code changes.

## Composition Modes

### append
Use platform defaults first, then add organization overrides.

### prepend
Inject organization policy first so it has highest visibility.

### replace
Fully replace default policy for strict internal policy sets.

## Example
Run with a custom policy appended:

`devsecops-agent --target http://127.0.0.1:8080 --custom-instructions instructions/custom_instructions_example.md --custom-mode append`

## Recommended Practice
- Keep base instructions generic and reusable.
- Keep custom instructions focused on compliance and architecture specifics.
- Version-control custom instruction files with application code.
