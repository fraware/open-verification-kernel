from pathlib import Path

from ovk.core import adapter_runtime
from ovk.core.models import BackendClaim, VerificationEvidence, VerificationStatus


def _evidence(input_format: str) -> VerificationEvidence:
    return VerificationEvidence(
        evidence_id=f"ev-{input_format}",
        subject={"repo": "test/repo", "head_sha": "abc"},
        intent={"intent_id": "test-intent", "title": "Test", "risk": {"severity": "low"}},
        backend_claims=[
            BackendClaim(
                backend="test",
                guarantee_type=input_format,
                status=VerificationStatus.PASS,
                assumptions=["test"],
                limits=["test"],
                adapter_version="test",
            )
        ],
        decision={"merge_recommendation": "allow", "human_review_required": False},
    )


def test_cache_distinguishes_input_normalization_formats(monkeypatch, tmp_path: Path) -> None:
    calls: list[str] = []

    def fake_evaluate_lane(lane, data, *, repo, head_sha, base_sha, input_format, policy_path):
        calls.append(input_format)
        evidence = _evidence(input_format)
        return evidence.model_copy(update={"subject": {"repo": repo, "head_sha": head_sha}})

    monkeypatch.setattr(adapter_runtime, "evaluate_lane", fake_evaluate_lane)
    raw_input = {"resource_changes": []}
    native = [
        {
            "lane": "infrastructure",
            "intent_id": "no-public-sensitive-resource",
            "input": raw_input,
            "input_format": "infra",
        }
    ]
    terraform = [
        {
            "lane": "infrastructure",
            "intent_id": "no-public-sensitive-resource",
            "input": raw_input,
            "input_format": "terraform",
        }
    ]

    adapter_runtime.execute_obligations(
        native,
        {},
        repo="test/repo",
        head_sha="abc",
        cache_dir=tmp_path,
        parallel=False,
    )
    adapter_runtime.execute_obligations(
        terraform,
        {},
        repo="test/repo",
        head_sha="abc",
        cache_dir=tmp_path,
        parallel=False,
    )
    adapter_runtime.execute_obligations(
        terraform,
        {},
        repo="test/repo",
        head_sha="abc",
        cache_dir=tmp_path,
        parallel=False,
    )

    assert calls == ["infra", "terraform"]
