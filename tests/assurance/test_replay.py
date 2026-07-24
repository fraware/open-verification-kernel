"""Assurance replay: golden match and fail-closed drift."""

from __future__ import annotations

import json

import pytest

from ovk.assurance.errors import ReplayError
from ovk.assurance.pin import resolve_pcs_root
from ovk.assurance.replay import replay_invocation
from ovk.assurance.runner import run_assurance
from tests.assurance.support.digest_adapter import DigestPredicateAdapter

PCS_AVAILABLE = resolve_pcs_root() is not None
requires_pcs = pytest.mark.skipif(
    not PCS_AVAILABLE,
    reason="PCS pin unavailable (set OVK_PCS_CORE_PATH or sibling ../pcs-core)",
)


@requires_pcs
def test_replay_golden_match(tmp_path) -> None:
    expected = "sha256:" + ("ee" * 32)
    adapter = DigestPredicateAdapter(expected_digest=expected, timeout_ms=1500)
    evidence_dir = tmp_path / "evidence"
    outcome = run_assurance(
        adapter,
        input_data={"digest": expected},
        config={"timeout_ms": 1500, "threshold": 1, "expected_digest": expected},
        evidence_dir=evidence_dir,
    )
    invocation_path = evidence_dir / "invocation.json"
    report = replay_invocation(
        invocation_path,
        adapter=adapter,
        evidence_dir=evidence_dir,
        config={"timeout_ms": 1500, "threshold": 1, "expected_digest": expected},
    )
    assert report["replay_status"] == "matched"
    assert report["drift"]["raw_digest_match"] is True
    assert report["drift"]["normalized_digest_match"] is True


@requires_pcs
def test_replay_drift_fails_closed(tmp_path) -> None:
    expected = "sha256:" + ("ff" * 32)
    adapter = DigestPredicateAdapter(expected_digest=expected, timeout_ms=1500, threshold=1)
    evidence_dir = tmp_path / "evidence"
    outcome = run_assurance(
        adapter,
        input_data={"digest": expected},
        config={"timeout_ms": 1500, "threshold": 1, "expected_digest": expected},
        evidence_dir=evidence_dir,
    )
    # Mutate stored raw digest to force drift detection on claim_matched
    invocation = json.loads((evidence_dir / "invocation.json").read_text(encoding="utf-8"))
    # Rerun with different threshold so digests differ, then claim matched.
    drifted_adapter = DigestPredicateAdapter(expected_digest=expected, timeout_ms=1500, threshold=0)
    with pytest.raises(ReplayError):
        replay_invocation(
            invocation,
            adapter=drifted_adapter,
            evidence_dir=evidence_dir,
            config={"timeout_ms": 1500, "threshold": 0, "expected_digest": expected},
            claim_matched=True,
        )

    report = replay_invocation(
        invocation,
        adapter=drifted_adapter,
        evidence_dir=evidence_dir,
        config={"timeout_ms": 1500, "threshold": 0, "expected_digest": expected},
        claim_matched=False,
    )
    assert report["replay_status"] == "drifted"
    assert outcome.decision == "accept"
