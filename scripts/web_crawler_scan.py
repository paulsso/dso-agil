#!/usr/bin/env python3
"""CLI wrapper for deterministic crawler scanner."""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict

from devsecops_agent.tooling import crawler


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--max-pages", default=15, type=int)
    args = parser.parse_args()

    pages = crawler.run(args.target, max_pages=args.max_pages)
    print(json.dumps([asdict(i) for i in pages], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
