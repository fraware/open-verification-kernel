#!/usr/bin/env python
"""Run the first OVK end-to-end demo.

Usage:
    python scripts/run_self_protection_demo.py \
      examples/no_agent_self_approval/input_gate_removed.json

The script emits normalized OVK evidence as JSON and exits with:
- 0 when the merge recommendation is allow;
- 1 when the merge recommendation is block;
- 2 when human review is required.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from ovk.adapters.opa import evaluate_self_protection


EXIT_CODES = {
    "allow": 0,
    "allow_with_warning": 0,
    "block": 1,
    "require_human_review": 2,
    "require_stronger_check": 2,
}


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: run_self_protection_demo.py <input.json> [output.json]", file=sys.stderr)
        return 2

    input_path = Path(sys.argv[1])
    output_path = Path(sys.argv[2]) if len(sys.argv) > 2 else None
    data = json.loads(input_path.read_text(encoding="utf-8"))

    evidence = evaluate_self_protection(
        data,
        repo="fraware/open-verification-kernel-demo",
        pull_request=42,
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
