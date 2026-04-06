"""Static constants used across the project."""

WORKFLOW_STAGES = [
    "LOAD_CONTEXT",
    "COMPOSE_INSTRUCTIONS",
    "PLAN_SCAN",
    "RUN_SCANNERS",
    "RISK_SCORE",
    "GENERATE_REPORT",
    "EXIT_GATE",
]

SEVERITY_WEIGHTS = {
    "critical": 100,
    "high": 40,
    "medium": 15,
    "low": 5,
    "info": 1,
}
