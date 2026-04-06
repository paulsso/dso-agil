"""CLI entrypoint for DevSecOps Agent in the loop."""

from __future__ import annotations

import argparse
import json
import sys

from .workflow import WorkflowConfig, run_workflow


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="DevSecOps Agent in the Loop")
    parser.add_argument(
        "--target",
        required=True,
        help="Local pre-deploy target URL or hostname (for example: 127.0.0.1:8080)",
    )
    parser.add_argument(
        "--provider",
        default="openai",
        choices=["openai", "anthropic", "meta"],
        help="Model provider adapter",
    )
    parser.add_argument(
        "--base-instructions",
        default="instructions/base_security_agent.md",
        help="Path to base markdown instructions",
    )
    parser.add_argument(
        "--custom-instructions",
        default=None,
        help="Optional custom markdown instructions",
    )
    parser.add_argument(
        "--custom-mode",
        default="append",
        choices=["append", "prepend", "replace"],
        help="How to apply custom instructions",
    )
    parser.add_argument(
        "--block-threshold",
        default=80,
        type=int,
        help="Risk score threshold to block pipeline",
    )
    parser.add_argument(
        "--output-json",
        default="devsecops_report.json",
        help="Path for machine-readable report",
    )
    parser.add_argument(
        "--source-path",
        default=".",
        help="Path to application source code for JS/TS source security audit",
    )
    parser.add_argument(
        "--disable-online-intel",
        action="store_true",
        help="Disable online vulnerability intelligence lookups (OSV)",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    config = WorkflowConfig(
        target=args.target,
        provider=args.provider,
        base_instructions_path=args.base_instructions,
        custom_instructions_path=args.custom_instructions,
        custom_mode=args.custom_mode,
        block_threshold=args.block_threshold,
        output_json=args.output_json,
        source_path=args.source_path,
        enable_online_intel=not args.disable_online_intel,
    )

    report = run_workflow(config, logger=print)
    print(json.dumps({"score": report.score, "blocked": report.blocked}, indent=2))

    if report.blocked:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
