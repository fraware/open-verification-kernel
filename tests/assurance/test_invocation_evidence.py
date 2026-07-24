"""Invocation + evidence pack tests."""

from __future__ import annotations

import pytest

from ovk.assurance.errors import AssuranceError
from ovk.assurance.evidence_pack import validate_evidence_dir
from ovk.assurance.guarantee import assert_no_guarantee_upgrade, clamp_guarantee_class
from ovk.assurance.indeterminate import DECISION_ACCEPT
from ovk.assurance.pin import resolve_pcs_root
from ovk.assurance.runner import run_assurance
from tests.assurance.support.digest_adapter import DigestPredicateAdapter

PCS_AVAILABLE = resolve_pcs_root() is not None
requires_pcs = pytest.mark.skipif(
    not PCS_AVAILABLE,
    reason="PCS pin unavailable (set OVK_PCS_CORE_PATH or sibling ../pcs-core)",
)


@requires_pcs
def test_evidence_pack_layout_and_accept(tmp_path) -> None:
    expected = "sha256:" + ("cd" * 32)
    adapter = DigestPredicateAdapter(expected_digest=expected)
    evidence_dir = tmp_path / "evidence"
    outcome = run_assurance(
        adapter,
        input_data={"digest": expected},
        config={"timeout_ms": 1000, "threshold": 1},
        evidence_dir=evidence_dir,
    )
    assert outcome.decision == "accept"
    for name in (
        "invocation.json",
        "verifier_profile.pcs.json",
        "verification_result.pcs.json",
        "compiled_obligation.json",
    ):
        assert (evidence_dir / name).is_file()
    for name in ("raw", "normalized", "provenance"):
        assert (evidence_dir / name).is_dir()
    report = validate_evidence_dir(evidence_dir)
    assert report["valid"] is True


@requires_pcs
def test_missing_checker_is_typed_indeterminate(tmp_path) -> None:
    adapter = DigestPredicateAdapter(
        expected_digest="sha256:" + ("11" * 32),
        missing_checker=True,
    )
    outcome = run_assurance(
        adapter,
        input_data={"digest": "sha256:" + ("11" * 32)},
        evidence_dir=tmp_path / "evidence",
    )
    assert outcome.decision != DECISION_ACCEPT
    assert outcome.indeterminate_reason == "missing_checker"
    assert outcome.decision.startswith("indeterminate_")
    assert outcome.result["decision"] != "accept"
    assert outcome.result["execution_status"] != "completed" or outcome.indeterminate_reason


def test_normalize_cannot_upgrade_guarantee_class() -> None:
    assert_no_guarantee_upgrade("observational", "observational")
    with pytest.raises(AssuranceError):
        assert_no_guarantee_upgrade("observational", "formally_checked")
    assert clamp_guarantee_class("observational", "formally_checked") == "observational"
    assert clamp_guarantee_class("formally_checked", "observational") == "observational"
