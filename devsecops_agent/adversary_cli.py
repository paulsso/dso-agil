"""CLI for standalone adversarial sandbox agent."""

from __future__ import annotations

import argparse
import json
import sys

from .adversary import AdversaryConfig, run_adversary


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="DevSecOps Adversary Agent")
    parser.add_argument(
        "--target",
        required=True,
        help="Local sandbox target URL/hostname (for example: http://127.0.0.1:8080)",
    )
    parser.add_argument(
        "--source-path",
        default=".",
        help="Path to application source code for intelligence gathering",
    )
    parser.add_argument(
        "--provider",
        default="openai",
        choices=["openai", "anthropic", "meta"],
        help="Model provider adapter",
    )
    parser.add_argument(
        "--output-json",
        default="adversary_report.json",
        help="Path for machine-readable adversary report",
    )
    parser.add_argument(
        "--block-threshold",
        default=80,
        type=int,
        help="Risk score threshold to block pipeline",
    )
    parser.add_argument(
        "--max-pages",
        default=15,
        type=int,
        help="Max pages to crawl for endpoint intelligence",
    )
    parser.add_argument(
        "--max-endpoints",
        default=20,
        type=int,
        help="Max endpoints to probe adversarially",
    )
    parser.add_argument(
        "--disable-online-intel",
        action="store_true",
        help="Disable online vulnerability intelligence lookups",
    )
    parser.add_argument(
        "--allow-remote-target",
        action="store_true",
        help="Allow non-local targets (disabled by default for sandbox safety)",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    config = AdversaryConfig(
        target=args.target,
        source_path=args.source_path,
        provider=args.provider,
        output_json=args.output_json,
        block_threshold=args.block_threshold,
        max_pages=args.max_pages,
        max_endpoints=args.max_endpoints,
        enable_online_intel=not args.disable_online_intel,
        local_only=not args.allow_remote_target,
    )

    report = run_adversary(config, logger=print)
    print(json.dumps({"score": report.score, "blocked": report.blocked}, indent=2))

    if report.blocked:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
