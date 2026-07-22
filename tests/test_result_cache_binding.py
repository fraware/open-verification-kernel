from pathlib import Path

from ovk.core import adapter_runtime
from ovk.core.models import BackendClaim, VerificationEvidence, VerificationStatus


def _evidence(*, repo: str, head_sha: str, base_sha: str | None = None) -> VerificationEvidence:
    subject = {"repo": repo, "head_sha": head_sha}
    if base_sha is not None:
        subject["base_sha"] = base_sha
    return VerificationEvidence(
        evidence_id=f"ev-{head_sha}",
        subject=subject,
        intent={"intent_id": "test-intent", "title": "Test intent", "risk": {"severity": "low"}},
        backend_claims=[
            BackendClaim(
                backend="test",
                guarantee_type="deterministic_test",
                status=VerificationStatus.PASS,
                assumptions=["test input is complete"],
                limits=["test-only evaluator"],
                adapter_version="test",
            )
        ],
        decision={"merge_recommendation": "allow", "human_review_required": False},
    )


def test_result_cache_is_bound_to_repository_subject(monkeypatch, tmp_path: Path) -> None:
    calls: list[tuple[str, str]] = []

    def fake_evaluate_lane(lane, data, *, repo, head_sha, base_sha, input_format, policy_path):
        calls.append((repo, head_sha))
        return _evidence(repo=repo, head_sha=head_sha, base_sha=base_sha)

    monkeypatch.setattr(adapter_runtime, "evaluate_lane", fake_evaluate_lane)
    obligations = [{"lane": "infrastructure", "intent_id": "test-intent", "input": {"resources": []}}]

    first = adapter_runtime.execute_obligations(
        obligations,
        {},
        repo="one/repo",
        head_sha="head-one",
        cache_dir=tmp_path,
        parallel=False,
    )
    second = adapter_runtime.execute_obligations(
        obligations,
        {},
        repo="two/repo",
        head_sha="head-two",
        cache_dir=tmp_path,
        parallel=False,
    )
    repeated = adapter_runtime.execute_obligations(
        obligations,
        {},
        repo="two/repo",
        head_sha="head-two",
        cache_dir=tmp_path,
        parallel=False,
    )

    assert first[0].subject == {"repo": "one/repo", "head_sha": "head-one"}
    assert second[0].subject == {"repo": "two/repo", "head_sha": "head-two"}
    assert repeated[0].subject == {"repo": "two/repo", "head_sha": "head-two"}
    assert calls == [("one/repo", "head-one"), ("two/repo", "head-two")]
