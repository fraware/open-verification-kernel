from pathlib import Path

from ovk.core.check import run_check


def test_check_ci_secrets_diff_blocks() -> None:
    diff_text = Path("examples/ci_secrets/workflow_secrets_on_pr.diff").read_text(encoding="utf-8")
    result = run_check(diff_text=diff_text, use_cache=False, repo="test/repo", head_sha="abc123")
    recommendation = result.bundle.decision.get("merge_recommendation")
    assert recommendation == "block"
    assert result.elapsed_ms < 15000
    assert result.jobs


def test_check_doctor_passes_without_verification_dir() -> None:
    from ovk.core.doctor import run_doctor

    report = run_doctor(verification_dir=Path(".verification-test-missing"))
    assert "checks" in report
