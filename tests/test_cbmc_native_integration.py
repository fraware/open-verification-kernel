import json
import shutil
from pathlib import Path

import pytest

from ovk.adapters.cbmc.evidence import evaluate_cbmc_harness


@pytest.mark.skipif(shutil.which("cbmc") is None, reason="CBMC binary is not installed")
def test_cbmc_harness_pass_fixture_when_cbmc_installed() -> None:
    data = json.loads(Path("examples/backends/cbmc_pass.json").read_text(encoding="utf-8"))
    evidence = evaluate_cbmc_harness(data, repo="test/repo", head_sha="abc12345")
    assert evidence.backend_claims[0].status.value == "pass"
    assert evidence.backend_claims[0].guarantee_type == "deterministic_fallback"
    assumptions = " ".join(evidence.backend_claims[0].assumptions).lower()
    assert "deterministic oracle" in assumptions


@pytest.mark.skipif(shutil.which("cbmc") is None, reason="CBMC binary is not installed")
def test_cbmc_harness_fail_fixture_when_cbmc_installed() -> None:
    data = json.loads(Path("examples/backends/cbmc_fail.json").read_text(encoding="utf-8"))
    evidence = evaluate_cbmc_harness(data, repo="test/repo", head_sha="abc12345")
    assert evidence.backend_claims[0].status.value == "fail"
    assert evidence.decision.get("merge_recommendation") == "block"
    assumptions = " ".join(evidence.backend_claims[0].assumptions).lower()
    assert "deterministic oracle" in assumptions
