"""Z3 native path coverage for real_diff authorization corpus."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

from ovk.adapters.z3.route_extract import authorization_inputs_from_diff
from ovk.adapters.z3.validated_path import evaluate_validated_authorization_path


DIFF_ROOT = Path("benchmarks/real_diffs")
AUTH_CASES = [
    ("auth_admin_route_unguarded.diff", "fail"),
    ("auth_admin_route_guarded.diff", "pass"),
    ("auth_route_partial_hunk.diff", "fail"),
]


def _provenance_backend(evidence) -> str | None:
    for artifact in evidence.generated_artifacts:
        if artifact.get("kind") == "backend_provenance":
            return str(artifact.get("backend"))
    return None


@pytest.mark.skipif(importlib.util.find_spec("z3") is None, reason="z3-solver is not installed")
@pytest.mark.parametrize(("diff_name", "expected_status"), AUTH_CASES)
def test_z3_native_path_on_real_diff_auth_cases(diff_name: str, expected_status: str) -> None:
    diff_text = (DIFF_ROOT / diff_name).read_text(encoding="utf-8")
    inputs = authorization_inputs_from_diff(diff_text)
    assert inputs, f"no authorization inputs extracted from {diff_name}"
    evidence = evaluate_validated_authorization_path(
        inputs[0],
        repo="bench/repo",
        head_sha="z3-real-diff",
    )
    assert evidence.backend_claims[0].status.value == expected_status
    assert _provenance_backend(evidence) == "z3"
