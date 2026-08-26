"""Adversarial tests for public project-status maturity claims."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from ovk.core.project_status import build_project_status
from ovk.core.support_contracts import load_support_contract


_PROFILE = "authorization.fastapi.ast_v1"


def _repo_fixture(tmp_path: Path) -> Path:
    shutil.copytree(Path("profiles"), tmp_path / "profiles")
    (tmp_path / "docs" / "benchmarks").mkdir(parents=True)
    (tmp_path / ".verification").mkdir(parents=True)
    return tmp_path


def _strict_shaped_qualification(*, profile_id: str, contract_version: str) -> dict:
    return {
        "profile_id": profile_id,
        "support_contract_version": contract_version,
        "executable_path_complete": True,
        "compiler_binding_present": True,
        "enforcement_test_present": True,
        "materials_trusted": True,
        "measured_coverage_complete": True,
        "execution_attested": True,
        "positive_cases": 3,
        "negative_cases": 3,
        "unsupported_cases": 1,
        "malformed_cases": 1,
        "unknown_cases": 1,
        "timeout_cases": 1,
        "source_range_cases": 1,
        "evidence_invariant_cases": 1,
        "end_to_end_bundle_cases": 1,
        "installed_package_cases": 1,
        "action_cases": 1,
    }


def _write_v1(repo_root: Path, row: dict) -> None:
    payload = {
        "schema_version": "ovk.source_profile_qualification.v1",
        "profiles": {_PROFILE: row},
    }
    (repo_root / ".verification" / "source-profile-qualification.json").write_text(
        json.dumps(payload), encoding="utf-8"
    )


def test_serialized_v1_strict_claim_cannot_promote_public_status(tmp_path: Path) -> None:
    repo_root = _repo_fixture(tmp_path)
    contract = load_support_contract(_PROFILE, repo_root=repo_root)
    qualification = _strict_shaped_qualification(
        profile_id=_PROFILE,
        contract_version=contract.contract_version,
    )
    _write_v1(
        repo_root,
        {
            "profile_id": _PROFILE,
            "maturity": "source_profile_strict_eligible",
            "qualification": {**qualification, "strict_ready": True},
        },
    )

    status = build_project_status(repo_root, candidate_sha="a" * 40)
    row = status["profile_statuses"][_PROFILE]

    # The underlying values are strict-shaped, proving the test exercises the
    # public-status trust boundary rather than merely an incomplete fixture.
    assert row["normative_strict_ready_unbound"] is True
    assert row["strict_ready"] is False
    assert row["maturity"] == "executable_advisory"
    assert row["candidate_bound"] is False
    assert "qualification_v1_not_candidate_bound" in row["status_reasons"]


def test_profile_identity_mismatch_is_rejected_by_status_projection(tmp_path: Path) -> None:
    repo_root = _repo_fixture(tmp_path)
    contract = load_support_contract(_PROFILE, repo_root=repo_root)
    qualification = _strict_shaped_qualification(
        profile_id="authorization.express.ast_v1",
        contract_version=contract.contract_version,
    )
    _write_v1(repo_root, {"qualification": qualification})

    row = build_project_status(repo_root, candidate_sha="b" * 40)["profile_statuses"][_PROFILE]
    assert row["qualification_valid"] is False
    assert row["strict_ready"] is False
    assert "qualification_profile_mismatch" in row["status_reasons"]


def test_support_contract_version_mismatch_is_rejected_by_status_projection(tmp_path: Path) -> None:
    repo_root = _repo_fixture(tmp_path)
    qualification = _strict_shaped_qualification(
        profile_id=_PROFILE,
        contract_version="stale-contract-version",
    )
    _write_v1(repo_root, {"qualification": qualification})

    row = build_project_status(repo_root, candidate_sha="c" * 40)["profile_statuses"][_PROFILE]
    assert row["qualification_valid"] is False
    assert row["strict_ready"] is False
    assert "qualification_support_contract_mismatch" in row["status_reasons"]


def test_missing_qualification_remains_advisory(tmp_path: Path) -> None:
    repo_root = _repo_fixture(tmp_path)
    status = build_project_status(repo_root, candidate_sha="d" * 40)

    assert all(not row["strict_ready"] for row in status["profile_statuses"].values())
    assert all(row["maturity"] == "executable_advisory" for row in status["profile_statuses"].values())
