#!/usr/bin/env python3
"""CLI wrapper for HTTP methods scanner."""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict

from devsecops_agent.tooling import methods_scan


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    args = parser.parse_args()

    issues = methods_scan.run(args.target)
    print(json.dumps([asdict(i) for i in issues], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
