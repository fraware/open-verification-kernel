#!/usr/bin/env python
"""Score infrastructure exposure seed cases."""

from __future__ import annotations

import json
from pathlib import Path

from ovk.adapters.infra.evidence import evaluate_infra_exposure


ROOT = Path(__file__).resolve().parents[2]


def score_fixture(path: Path, expected_status: str, expected_recommendation: str) -> bool:
    data = json.loads(path.read_text(encoding="utf-8"))
    evidence = evaluate_infra_exposure(data, repo="bench/repo", head_sha="seed")
    status = evidence.backend_claims[0].status.value
    recommendation = str(evidence.decision["merge_recommendation"])
    return status == expected_status and recommendation == expected_recommendation


def main() -> int:
    cases = [
        (ROOT / "examples/infrastructure_exposure/input_public_sensitive_resource.json", "fail", "block"),
        (ROOT / "examples/infrastructure_exposure/input_private_sensitive_resource.json", "pass", "allow"),
    ]
    failures = []
    for path, expected_status, expected_recommendation in cases:
        ok = score_fixture(path, expected_status, expected_recommendation)
        print(f"{path.name}: {'PASS' if ok else 'FAIL'}")
        if not ok:
            failures.append(path.name)
    if failures:
        print(json.dumps({"failures": failures}, indent=2))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
