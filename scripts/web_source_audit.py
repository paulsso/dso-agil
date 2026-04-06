#!/usr/bin/env python3
"""CLI wrapper for JS/TS source security audit."""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict

from devsecops_agent.tooling import source_audit


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-path", default=".")
    parser.add_argument("--disable-online-intel", action="store_true")
    args = parser.parse_args()

    issues = source_audit.run(
        source_path=args.source_path,
        enable_online_intel=not args.disable_online_intel,
    )
    print(json.dumps([asdict(i) for i in issues], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
