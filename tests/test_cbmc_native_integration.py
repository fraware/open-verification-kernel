import json
import shutil
from pathlib import Path

import pytest

from ovk.adapters.cbmc.diff_extract import cbmc_inputs_from_diff
from ovk.adapters.cbmc.evidence import evaluate_cbmc_harness
from ovk.adapters.cbmc.harness_compiler import compile_cbmc_harness
from ovk.core.kernel import execute_kernel


def test_cbmc_diff_extracts_auth_cache_input() -> None:
    diff_text = Path("benchmarks/real_diffs/cbmc_use_after_free_auth_cache.diff").read_text(encoding="utf-8")
    inputs = cbmc_inputs_from_diff(diff_text)
    assert len(inputs) == 1
    assert inputs[0]["intent_id"] == "cbmc-no-use-after-free-auth-cache"
    assert inputs[0]["findings"]
    assert inputs[0].get("expect_violation") is True
    assert inputs[0].get("failed_assertions")


def test_harness_compiler_resolves_all_templates() -> None:
    templates = [
        "cbmc-buffer-bounds",
        "cbmc-no-integer-overflow-quota",
        "cbmc-no-unchecked-buffer-copy",
        "cbmc-no-use-after-free-auth-cache",
    ]
    for intent_id in templates:
        compiled = compile_cbmc_harness({"intent_id": intent_id})
        assert Path(str(compiled["harness_path"])).is_file()


@pytest.mark.skipif(shutil.which("cbmc") is None, reason="CBMC binary is not installed")
def test_cbmc_harness_pass_fixture_uses_native_path_when_installed() -> None:
    data = json.loads(Path("examples/backends/cbmc_pass.json").read_text(encoding="utf-8"))
    evidence = evaluate_cbmc_harness(data, repo="test/repo", head_sha="abc12345")
    assert evidence.backend_claims[0].status.value == "pass"
    assert evidence.backend_claims[0].guarantee_type == "bounded_model_checking"
    assert any(item.get("kind") == "backend_provenance" for item in evidence.generated_artifacts)


@pytest.mark.skipif(shutil.which("cbmc") is None, reason="CBMC binary is not installed")
def test_cbmc_harness_fail_fixture_uses_native_path_when_installed() -> None:
    data = json.loads(Path("examples/backends/cbmc_fail.json").read_text(encoding="utf-8"))
    evidence = evaluate_cbmc_harness(data, repo="test/repo", head_sha="abc12345")
    assert evidence.backend_claims[0].status.value == "fail"
    assert evidence.backend_claims[0].guarantee_type == "bounded_model_checking"
    assert evidence.counterexamples


def test_cbmc_oracle_fallback_without_harness_path() -> None:
    data = {"intent_id": "cbmc-legacy-oracle", "failed_assertions": ["bounds violated"]}
    evidence = evaluate_cbmc_harness(data, repo="test/repo", head_sha="abc12345")
    assert evidence.backend_claims[0].status.value == "fail"
    assert evidence.backend_claims[0].guarantee_type == "deterministic_fallback"


def test_kernel_check_on_c_diff_compiles_cbmc_obligations() -> None:
    diff_text = Path("benchmarks/real_diffs/cbmc_use_after_free_auth_cache.diff").read_text(encoding="utf-8")
    result = execute_kernel(diff_text=diff_text, use_cache=False, repo="test/repo", head_sha="deadbeef")
    lanes = {obligation["lane"] for obligation in result.obligations}
    assert "backend" in lanes
    assert "cbmc-no-use-after-free-auth-cache" in result.plan.get("candidate_intents", [])
