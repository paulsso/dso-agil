#!/usr/bin/env python3
"""CLI wrapper for lightweight input probes."""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict

from devsecops_agent.tooling import probes


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    args = parser.parse_args()

    issues = probes.run(args.target)
    print(json.dumps([asdict(i) for i in issues], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
