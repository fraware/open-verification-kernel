#!/usr/bin/env python
"""Run the OVK authorization reachability demo."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from ovk.adapters.z3 import evaluate_authorization_reachability


EXIT_CODES = {
    "allow": 0,
    "allow_with_warning": 0,
    "block": 1,
    "require_human_review": 2,
    "require_stronger_check": 2,
}


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: run_authorization_demo.py <input.json> [output.json]", file=sys.stderr)
        return 2

    input_path = Path(sys.argv[1])
    output_path = Path(sys.argv[2]) if len(sys.argv) > 2 else None
    data = json.loads(input_path.read_text(encoding="utf-8"))

    evidence = evaluate_authorization_reachability(
        data,
        repo="fraware/open-verification-kernel-demo",
        pull_request=43,
        head_sha="demo-head",
        base_sha="demo-base",
    )
    payload = evidence.model_dump(mode="json")
    rendered = json.dumps(payload, indent=2)

    if output_path:
        output_path.write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)

    decision = evidence.decision.get("merge_recommendation", "require_human_review")
    return EXIT_CODES.get(str(decision), 2)


if __name__ == "__main__":
    raise SystemExit(main())
