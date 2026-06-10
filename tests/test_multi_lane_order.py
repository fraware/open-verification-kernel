import time
from pathlib import Path

from ovk.core.models import BackendClaim, VerificationEvidence, VerificationStatus
from ovk.core import multi_lane


def _evidence(evidence_id: str) -> VerificationEvidence:
    return VerificationEvidence(
        evidence_id=evidence_id,
        subject={"repo": "example/repo", "head_sha": "abc"},
        intent={"intent_id": evidence_id, "title": evidence_id, "risk": {"severity": "low"}},
        backend_claims=[
            BackendClaim(
                backend="test",
                guarantee_type="deterministic_test",
                status=VerificationStatus.PASS,
                assumptions=["test assumption"],
                limits=["test limit"],
                adapter_version="test",
            )
        ],
        decision={"merge_recommendation": "allow", "human_review_required": False},
    )


def test_run_verification_manifest_preserves_manifest_order(monkeypatch, tmp_path: Path) -> None:
    def fake_evaluate_manifest_entry(entry, **kwargs):
        if entry["lane"] == "first":
            time.sleep(0.02)
        return _evidence(f"ev-{entry['lane']}")

    monkeypatch.setattr(multi_lane, "_evaluate_manifest_entry", fake_evaluate_manifest_entry)
    bundle = multi_lane.run_verification_manifest(
        {"lanes": [{"lane": "first", "input": "a.json"}, {"lane": "second", "input": "b.json"}]},
        root=tmp_path,
        parallel=True,
    )
    assert [item.evidence_id for item in bundle.evidence] == ["ev-first", "ev-second"]
