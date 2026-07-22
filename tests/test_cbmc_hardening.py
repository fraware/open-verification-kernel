import subprocess
from pathlib import Path

from ovk.adapters.cbmc import evidence as cbmc_evidence
from ovk.adapters.cbmc.harness_compiler import compile_cbmc_harness
from ovk.adapters.cbmc.optional_runner import run_cbmc_harness


def test_generated_integer_overflow_pass_harness_constrains_delta(tmp_path: Path) -> None:
    compiled = compile_cbmc_harness(
        {
            "intent_id": "cbmc-no-integer-overflow-quota",
            "quota_limit": 1000,
            "force_generate": True,
        },
        output_dir=tmp_path,
    )
    source = Path(str(compiled["harness_path"])).read_text(encoding="utf-8")
    assert "__CPROVER_assume(used <= 1000);" in source
    assert "__CPROVER_assume(delta <= 1000 - used);" in source
    assert compiled["harness_origin"] == "generated"


def test_cbmc_timeout_is_native_unknown_not_fallback(monkeypatch, tmp_path: Path) -> None:
    harness = tmp_path / "harness.c"
    harness.write_text("void harness(void) {}\n", encoding="utf-8")
    monkeypatch.setattr("ovk.adapters.cbmc.optional_runner.shutil.which", lambda _name: "/usr/bin/cbmc")

    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=args[0], timeout=kwargs.get("timeout", 60))

    monkeypatch.setattr("ovk.adapters.cbmc.optional_runner.subprocess.run", timeout)
    result = run_cbmc_harness(harness_path=harness, timeout_seconds=1)
    assert result["status"] == "unknown"
    assert result["native_attempted"] is True
    assert result["used_native_binary"] is True


def test_synthetic_cbmc_harness_is_not_labeled_as_project_source_proof(monkeypatch) -> None:
    monkeypatch.setattr(
        cbmc_evidence,
        "run_cbmc_harness",
        lambda **_kwargs: {
            "status": "pass",
            "reason": "synthetic harness passed",
            "native_attempted": True,
            "used_native_binary": True,
            "counterexamples": [],
        },
    )
    evidence = cbmc_evidence.evaluate_cbmc_harness(
        {"intent_id": "cbmc-buffer-bounds"},
        repo="test/repo",
        head_sha="abc12345",
    )
    claim = evidence.backend_claims[0]
    assert claim.guarantee_type == "template_harness_model_check"
    assert any("does not establish" in limit for limit in claim.limits)
    provenance = next(item for item in evidence.generated_artifacts if item.get("kind") == "backend_provenance")
    assert provenance["harness_origin"] == "fixture"


def test_cbmc_timeout_evidence_requires_human_review(monkeypatch) -> None:
    monkeypatch.setattr(
        cbmc_evidence,
        "run_cbmc_harness",
        lambda **_kwargs: {
            "status": "unknown",
            "reason": "cbmc execution timed out",
            "native_attempted": True,
            "used_native_binary": True,
            "counterexamples": [],
        },
    )
    evidence = cbmc_evidence.evaluate_cbmc_harness(
        {"intent_id": "cbmc-buffer-bounds"},
        repo="test/repo",
        head_sha="abc12345",
    )
    assert evidence.backend_claims[0].status.value == "unknown"
    assert evidence.decision["merge_recommendation"] == "require_human_review"
    assert evidence.decision["human_review_required"] is True
