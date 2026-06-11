from pathlib import Path

import pytest

from ovk.adapters.z3.validated_path import evaluate_validated_authorization_path
from tests.native_ci import skip_unless_z3


def _provenance_backend(evidence) -> str | None:
    for artifact in evidence.generated_artifacts:
        if artifact.get("kind") == "backend_provenance":
            return str(artifact.get("backend"))
    return None


@pytest.mark.skipif(skip_unless_z3(), reason="Z3 integration runs in tier-1 workflow")
def test_z3_native_path_blocks_admin_bypass_when_z3_installed() -> None:
    payload = Path("examples/auth_regression/input_admin_bypass.json").read_text(encoding="utf-8")
    import json

    data = json.loads(payload)
    evidence = evaluate_validated_authorization_path(data, repo="test/repo", head_sha="abc12345")
    assert evidence.backend_claims[0].status.value == "fail"
    assert evidence.decision.get("merge_recommendation") == "block"
    assert _provenance_backend(evidence) == "z3"


@pytest.mark.skipif(skip_unless_z3(), reason="Z3 integration runs in tier-1 workflow")
def test_z3_native_path_allows_protected_admin_route_when_z3_installed() -> None:
    payload = Path("examples/auth_regression/input_admin_protected.json").read_text(encoding="utf-8")
    import json

    data = json.loads(payload)
    evidence = evaluate_validated_authorization_path(data, repo="test/repo", head_sha="abc12345")
    assert evidence.backend_claims[0].status.value == "pass"
    assert evidence.decision.get("merge_recommendation") == "allow"
    assert _provenance_backend(evidence) == "z3"
