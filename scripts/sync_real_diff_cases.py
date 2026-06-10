#!/usr/bin/env python
"""Generate benchmarks/formal_pr_bench/real_diff_cases.json from manifest."""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
manifest = json.loads((ROOT / "benchmarks/real_diffs/manifest.json").read_text(encoding="utf-8"))
cases = [
    {
        "case_id": item["case_id"],
        "category": "real_diff",
        "input_fixture": f"benchmarks/real_diffs/{item['diff']}",
        "expected_lanes": item["expected_lanes"],
        "expected_intents": item.get("expected_intents", []),
        "expected_merge_recommendation": item["expected_recommendation"],
    }
    for item in manifest["cases"]
]
output = {"schema_version": "formal_pr_bench.real_diff.v1", "cases": cases}
(ROOT / "benchmarks/formal_pr_bench/real_diff_cases.json").write_text(
    json.dumps(output, indent=2) + "\n",
    encoding="utf-8",
)
