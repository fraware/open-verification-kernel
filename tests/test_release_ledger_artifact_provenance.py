"""Release-ledger workflow-artifact, distribution, and tag provenance tests."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from ovk.core.release_ledger import (
    REQUIRED_CONSUMER_REPOSITORIES,
    REQUIRED_WORKFLOW_PATHS,
    REQUIRED_WORKFLOWS,
    build_release_ledger,
    validate_release_ledger_structure,
    verify_release_ledger,
)
from scripts.verify_authorized_release_inputs import verify_authorized_release_inputs
from scripts.verify_release_ledger_github import (
    _inspect_consumer_pin_artifacts,
    _inspect_holdout_aggregate,
    _inspect_holdout_predictions,
    _release_artifact_resolver,
)
from scripts.verify_release_tag_github import validate_signed_tag

REPO = Path(__file__).resolve().parents[1]
SHA = "58bee916492f7aa4f550ea6ced9f7271f065656e"
REPOSITORY = "fraware/open-verification-kernel"
PRED_SHA = "1" * 64
MANIFEST_FILE_SHA = "2" * 64
AGG_SHA = "3" * 64
WHEEL_SHA = "4" * 64
SDIST_SHA = "5" * 64
HOLDOUT_TAG = "v0.1.0-synthetic"


def _complete_runs() -> list[dict[str, Any]]:
    return [
        {
            "workflowName": name,
            "databaseId": index + 700,
            "headSha": SHA,
            "status": "completed",
            "conclusion": "success",
            "url": f"https://github.com/{REPOSITORY}/actions/runs/{index + 700}",
            "path": REQUIRED_WORKFLOW_PATHS[name],
            "createdAt": f"2026-08-26T12:{index:02d}:00Z",
        }
        for index, name in enumerate(REQUIRED_WORKFLOWS)
    ]


def _live_run_resolver(repository: str, run_id: int) -> dict[str, Any]:
    assert repository == REPOSITORY
    for run in _complete_runs():
        if run["databaseId"] == run_id:
            return {
                "id": run_id,
                "name": run["workflowName"],
                "head_sha": SHA,
                "status": "completed",
                "conclusion": "success",
                "path": run["path"],
                "html_url": run["url"],
                "repository": {"full_name": REPOSITORY},
            }
    raise KeyError(run_id)


def _consumer(repository: str, source_char: str) -> dict[str, Any]:
    return {
        "schema_version": "ovk.consumer_pin_evidence.v1",
        "consumer_repository": repository,
        "consumer_ref": "main",
        "consumer_source_sha": source_char * 40,
        "ovk_candidate_sha": SHA,
        "pin": f"fraware/open-verification-kernel@{SHA}",
        "workflow_digests": [
            {"path": ".github/workflows/ovk.yml", "sha256": source_char * 64}
        ],
    }


def _workflow_artifact_resolver(
    repository: str, run_id: int, workflow: str
) -> dict[str, Any]:
    assert repository == REPOSITORY
    assert isinstance(run_id, int)
    if workflow == "FormalPR-Holdout predict":
        return {
            "kind": "holdout_predictions.v1",
            "artifact_name": "formalpr-holdout-predictions",
            "predictions_sha256": PRED_SHA,
            "manifest_sha256": MANIFEST_FILE_SHA,
            "candidate_source_sha": SHA,
            "manifest_candidate_source_sha": SHA,
            "manifest_predictions_sha256": PRED_SHA,
            "label_free": True,
            "verified_source_sha_present": False,
        }
    if workflow == "FormalPR-Holdout eval":
        return {
            "kind": "holdout_aggregate.v1",
            "artifact_name": "formalpr-holdout-aggregates",
            "aggregate_sha256": AGG_SHA,
            "candidate_source_sha": SHA,
            "holdout_tag": HOLDOUT_TAG,
            "schema_valid": True,
            "verified_source_sha_present": False,
        }
    if workflow == "Consumer Pin Verification":
        consumers = [
            _consumer(REQUIRED_CONSUMER_REPOSITORIES[0], "6"),
            _consumer(REQUIRED_CONSUMER_REPOSITORIES[1], "7"),
        ]
        return {
            "kind": "consumer_pin_evidence.v1",
            "artifact_names": ["consumer-pin-0", "consumer-pin-1"],
            "consumers": consumers,
            "evidence_file_sha256": {
                REQUIRED_CONSUMER_REPOSITORIES[0]: "8" * 64,
                REQUIRED_CONSUMER_REPOSITORIES[1]: "9" * 64,
            },
        }
    raise AssertionError(f"unexpected workflow artifact lookup: {workflow}")


def _release_artifact_resolver() -> dict[str, Any]:
    return {
        "wheel": {
            "filename": "open_verification_kernel-1.3.0rc1-py3-none-any.whl",
            "sha256": WHEEL_SHA,
        },
        "sdist": {
            "filename": "open_verification_kernel-1.3.0rc1.tar.gz",
            "sha256": SDIST_SHA,
        },
    }


def _draft() -> dict[str, Any]:
    return build_release_ledger(
        REPO,
        candidate_sha=SHA,
        repository=REPOSITORY,
        workflow_evidence={"ok": True, "runs": _complete_runs()},
    )


def _authorize(ledger: dict[str, Any] | None = None):
    return verify_release_ledger(
        ledger or _draft(),
        repo_root=REPO,
        workflow_run_resolver=_live_run_resolver,
        workflow_artifact_resolver=_workflow_artifact_resolver,
        release_artifact_resolver=_release_artifact_resolver,
        expected_repository=REPOSITORY,
        expected_candidate_sha=SHA,
    )


def test_full_provenance_hydrates_evidence_and_authorizes() -> None:
    ok, failures, authorized = _authorize()
    assert ok is True
    assert failures == []
    assert authorized["release_state"]["authorized"] is True
    assert authorized["release_state"]["verified_source_sha"] == SHA
    assert authorized["release_state"]["published"] is False
    assert authorized["holdout"] == {
        "candidate_source_sha": SHA,
        "predictions_sha256": PRED_SHA,
        "aggregate_sha256": AGG_SHA,
        "holdout_tag": HOLDOUT_TAG,
    }
    assert {
        item["consumer_repository"] for item in authorized["consumers"]
    } == set(REQUIRED_CONSUMER_REPOSITORIES)
    assert all(len(item["consumer_source_sha"]) == 40 for item in authorized["consumers"])
    assert authorized["artifacts"]["wheel_sha256"] == WHEEL_SHA
    assert authorized["artifacts"]["sdist_sha256"] == SDIST_SHA
    assert authorized["evidence"]["workflow_provenance"]["candidate_sha"] == SHA
    artifact_provenance = authorized["evidence"]["workflow_artifact_provenance"]
    assert artifact_provenance["holdout"]["predictions_sha256"] == PRED_SHA
    assert set(artifact_provenance["consumers"]["repositories"]) == set(
        REQUIRED_CONSUMER_REPOSITORIES
    )
    assert authorized["evidence"]["release_artifact_provenance"]["wheel"]["sha256"] == WHEEL_SHA


def test_partial_scope_never_mints_release_authority() -> None:
    ok, failures, checked = verify_release_ledger(
        _draft(),
        repo_root=REPO,
        workflow_run_resolver=_live_run_resolver,
        require_artifacts=False,
        require_consumers=False,
        require_holdout=False,
    )
    assert ok is True
    assert failures == []
    assert checked["release_state"]["authorized"] is False
    assert checked["release_state"]["verified_source_sha"] is None
    assert checked["release_state"]["authorization_reason"] == (
        "partial_provenance_verified_not_release_authorized"
    )


def test_holdout_preclaim_mismatch_fails_closed() -> None:
    ledger = _draft()
    ledger["holdout"]["predictions_sha256"] = "a" * 64
    ok, failures, checked = _authorize(ledger)
    assert ok is False
    assert "holdout.predictions_sha256_mismatch_live" in failures
    assert checked["release_state"]["authorized"] is False


def test_distribution_preclaim_mismatch_fails_closed() -> None:
    ledger = _draft()
    ledger["artifacts"]["wheel_sha256"] = "a" * 64
    ok, failures, checked = _authorize(ledger)
    assert ok is False
    assert "artifacts.wheel_sha256_mismatch_live" in failures
    assert checked["release_state"]["verified_source_sha"] is None


def test_default_authorizer_requires_workflow_artifact_resolver() -> None:
    ok, failures, _ = verify_release_ledger(
        _draft(),
        repo_root=REPO,
        workflow_run_resolver=_live_run_resolver,
        release_artifact_resolver=_release_artifact_resolver,
    )
    assert ok is False
    assert failures == ["workflow_artifact_provenance_not_verified"]


def test_default_authorizer_requires_distribution_resolver() -> None:
    ok, failures, _ = verify_release_ledger(
        _draft(),
        repo_root=REPO,
        workflow_run_resolver=_live_run_resolver,
        workflow_artifact_resolver=_workflow_artifact_resolver,
    )
    assert ok is False
    assert failures == ["release_artifacts_not_verified"]


def test_expected_repository_is_external_trust_input() -> None:
    ok, failures, _ = verify_release_ledger(
        _draft(),
        repo_root=REPO,
        workflow_run_resolver=_live_run_resolver,
        workflow_artifact_resolver=_workflow_artifact_resolver,
        release_artifact_resolver=_release_artifact_resolver,
        expected_repository="attacker/open-verification-kernel",
        expected_candidate_sha=SHA,
    )
    assert ok is False
    assert "source.repository mismatch vs expected repository" in failures


def test_expected_candidate_is_external_trust_input() -> None:
    ok, failures, _ = verify_release_ledger(
        _draft(),
        repo_root=REPO,
        workflow_run_resolver=_live_run_resolver,
        workflow_artifact_resolver=_workflow_artifact_resolver,
        release_artifact_resolver=_release_artifact_resolver,
        expected_repository=REPOSITORY,
        expected_candidate_sha="0" * 40,
    )
    assert ok is False
    assert "source.candidate_sha mismatch vs expected candidate" in failures


def test_all_provenance_fields_are_non_self_assertable() -> None:
    ledger = _draft()
    ledger["evidence"]["workflow_artifact_provenance"] = {"forged": True}
    ledger["evidence"]["release_artifact_provenance"] = {"forged": True}
    failures = validate_release_ledger_structure(ledger, repo_root=REPO)
    assert "input ledger must not self-assert workflow_artifact_provenance" in failures
    assert "input ledger must not self-assert release_artifact_provenance" in failures


def test_release_ledger_schema_accepts_draft_and_authorized_output() -> None:
    draft = _draft()
    assert validate_release_ledger_structure(draft, repo_root=REPO) == []
    ok, failures, authorized = _authorize(draft)
    assert ok and not failures
    schema = json.loads((REPO / "schemas" / "release.ledger.schema.json").read_text())
    from ovk.core.schema_validation import validate_against_schema

    assert validate_against_schema(authorized, schema).valid


def _write_json(path: Path, payload: dict[str, Any]) -> str:
    text = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    path.write_text(text, encoding="utf-8")
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def test_holdout_prediction_artifact_parser_binds_manifest(tmp_path: Path) -> None:
    predictions = {
        "schema_version": "ovk.holdout.predictions.v1",
        "candidate_source_sha": SHA,
        "case_set_digest": "b" * 64,
        "policy_version": "ovk.holdout.predict.v1",
        "label_free": True,
        "predictor": "ovk.holdout.labels_free.v1",
        "cases": [
            {
                "case_id": "example.case",
                "prediction": "unknown",
                "predictor": "ovk.holdout.labels_free.v1",
                "rationale_code": "unrecognized_case_family",
            }
        ],
    }
    pred_sha = _write_json(tmp_path / "holdout-predictions.json", predictions)
    manifest = {
        "schema_version": "ovk.holdout.prediction_manifest.v1",
        "candidate_source_sha": SHA,
        "case_set_digest": "b" * 64,
        "policy_version": "ovk.holdout.predict.v1",
        "predictions_sha256": pred_sha,
        "predictions_path": ".verification/holdout-predictions.json",
    }
    manifest_sha = _write_json(tmp_path / "holdout-prediction-manifest.json", manifest)
    observed = _inspect_holdout_predictions(tmp_path)
    assert observed["predictions_sha256"] == pred_sha
    assert observed["manifest_sha256"] == manifest_sha
    assert observed["manifest_predictions_sha256"] == pred_sha
    assert observed["candidate_source_sha"] == SHA
    assert observed["verified_source_sha_present"] is False


def _valid_aggregate_payload() -> dict[str, Any]:
    metrics = {
        "cases": 1,
        "precision": 1.0,
        "recall": 1.0,
        "false_positive_rate": 0.0,
        "missed_detection_rate": 0.0,
        "unknown_rate": 0.0,
        "invalid_input_rate": 0.0,
        "abstention_appropriateness": 1.0,
        "coverage_completeness": 1.0,
        "counterexample_correctness": 1.0,
        "selected_backend_execution_correctness": 1.0,
        "runtime_ms": {"median": 1.0, "p95": 2.0, "max": 3.0},
    }
    return {
        "schema_version": "formalpr_holdout.aggregate_metrics.v1",
        "benchmark": "FormalPR-Holdout",
        "holdout_release_tag": HOLDOUT_TAG,
        "ovk_commit_sha": SHA,
        "generated_at_unix_ms": 1,
        "cases_scored": 1,
        "lanes": {"authorization": metrics},
        "disagreement_summary": {"open": 0, "resolved": 0, "deferred": 0, "total": 0},
        "leakage_guard": {
            "labels_emitted": False,
            "case_ids_emitted": False,
            "fail_closed": True,
            "sanitizer_version": "test",
        },
    }


def test_holdout_aggregate_artifact_parser_validates_schema(tmp_path: Path) -> None:
    aggregate = _valid_aggregate_payload()
    aggregate_sha = _write_json(tmp_path / "holdout-aggregate-metrics.json", aggregate)
    observed = _inspect_holdout_aggregate(tmp_path)
    assert observed["aggregate_sha256"] == aggregate_sha
    assert observed["candidate_source_sha"] == SHA
    assert observed["holdout_tag"] == HOLDOUT_TAG
    assert observed["schema_valid"] is True
    assert observed["verified_source_sha_present"] is False


def test_consumer_artifact_parser_hashes_exact_source_bound_evidence(tmp_path: Path) -> None:
    roots: dict[str, Path] = {}
    expected: dict[str, str] = {}
    for index, (repo_name, char) in enumerate(
        zip(REQUIRED_CONSUMER_REPOSITORIES, ("6", "7"), strict=True)
    ):
        root = tmp_path / f"consumer-pin-{index}"
        root.mkdir()
        path = root / f"consumer-pin-{repo_name.replace('/', '_')}.json"
        payload = _consumer(repo_name, char)
        expected[repo_name] = _write_json(path, payload)
        roots[root.name] = root
    observed = _inspect_consumer_pin_artifacts(roots)
    assert observed["artifact_names"] == ["consumer-pin-0", "consumer-pin-1"]
    assert observed["evidence_file_sha256"] == expected
    assert {
        item["consumer_source_sha"] for item in observed["consumers"]
    } == {"6" * 40, "7" * 40}


def test_local_distribution_resolver_requires_exactly_one_each(tmp_path: Path) -> None:
    wheel = tmp_path / "package.whl"
    sdist = tmp_path / "package.tar.gz"
    wheel.write_bytes(b"wheel")
    sdist.write_bytes(b"sdist")
    observed = _release_artifact_resolver(tmp_path)()
    assert observed["wheel"]["filename"] == wheel.name
    assert observed["wheel"]["sha256"] == hashlib.sha256(b"wheel").hexdigest()
    assert observed["sdist"]["filename"] == sdist.name
    (tmp_path / "second.whl").write_bytes(b"other")
    import pytest

    with pytest.raises(RuntimeError, match="exactly one wheel"):
        _release_artifact_resolver(tmp_path)()


def _authorized_with_real_dist(tmp_path: Path) -> dict[str, Any]:
    wheel = tmp_path / "package.whl"
    sdist = tmp_path / "package.tar.gz"
    wheel.write_bytes(b"wheel")
    sdist.write_bytes(b"sdist")
    ok, failures, authorized = verify_release_ledger(
        _draft(),
        repo_root=REPO,
        workflow_run_resolver=_live_run_resolver,
        workflow_artifact_resolver=_workflow_artifact_resolver,
        release_artifact_resolver=_release_artifact_resolver(tmp_path),
        expected_repository=REPOSITORY,
        expected_candidate_sha=SHA,
    )
    assert ok and not failures
    return authorized


def test_authorized_distribution_rechecker_detects_byte_substitution(tmp_path: Path) -> None:
    authorized = _authorized_with_real_dist(tmp_path)
    assert verify_authorized_release_inputs(
        authorized,
        dist_dir=tmp_path,
        expected_repository=REPOSITORY,
        expected_candidate_sha=SHA,
    ) == []
    wheel = next(tmp_path.glob("*.whl"))
    wheel.write_bytes(b"tampered")
    failures = verify_authorized_release_inputs(
        authorized,
        dist_dir=tmp_path,
        expected_repository=REPOSITORY,
        expected_candidate_sha=SHA,
    )
    assert "wheel digest mismatch" in failures


def test_signed_tag_validator_accepts_verified_annotated_direct_commit() -> None:
    ref = {"object": {"type": "tag", "sha": "a" * 40}}
    tag = {
        "tag": "v1.3.0-rc.1",
        "object": {"type": "commit", "sha": SHA},
        "verification": {"verified": True, "reason": "valid"},
    }
    assert validate_signed_tag(
        ref_payload=ref,
        tag_payload=tag,
        expected_tag="v1.3.0-rc.1",
        expected_candidate_sha=SHA,
    ) == []


def test_signed_tag_validator_rejects_lightweight_unverified_or_wrong_target() -> None:
    lightweight = {"object": {"type": "commit", "sha": SHA}}
    failures = validate_signed_tag(
        ref_payload=lightweight,
        tag_payload={},
        expected_tag="v1.3.0-rc.1",
        expected_candidate_sha=SHA,
    )
    assert any("annotated signed tag" in item for item in failures)

    ref = {"object": {"type": "tag", "sha": "a" * 40}}
    tag = {
        "tag": "v1.3.0-rc.1",
        "object": {"type": "commit", "sha": "0" * 40},
        "verification": {"verified": False},
    }
    failures = validate_signed_tag(
        ref_payload=ref,
        tag_payload=tag,
        expected_tag="v1.3.0-rc.1",
        expected_candidate_sha=SHA,
    )
    assert "annotated tag target does not match candidate SHA" in failures
    assert "annotated tag signature is not verified by GitHub" in failures


def test_consumer_workflow_records_immutable_checkout_source_sha() -> None:
    text = (REPO / ".github/workflows/consumer-pin-verification.yml").read_text(
        encoding="utf-8"
    )
    assert 'CONSUMER_SOURCE_SHA="$(git rev-parse HEAD)"' in text
    assert '"consumer_source_sha": consumer_source_sha' in text
    assert "if-no-files-found: error" in text
