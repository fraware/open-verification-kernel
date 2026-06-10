#!/usr/bin/env python
"""Run OVK local release preflight checks."""

from __future__ import annotations

import sys

from ovk.core.release_preflight_report import build_release_preflight_report, main as structured_main


def main() -> int:
    failures: list[str] = []
    report = build_release_preflight_report()
    failures.extend(report.failures)

    for failure in failures:
        print(failure)
    if failures:
        return 1
    print("OVK release preflight checks passed")
    return 0


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--output":
        raise SystemExit(structured_main())
    raise SystemExit(main())
