"""WP-17 release-ledger authorization and workflow-provenance tests."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ovk.core.release_ledger import (
    LEDGER_SCHEMA_VERSION,
    REQUIRED_WORKFLOW_PATHS,
    REQUIRED_WORKFLOWS,
    build_release_ledger,
    validate_release_ledger_structure,
    verify_release_ledger,
    write_release_ledger,
)

REPO = Path(__file__).resolve().parents[1]
SHA = "58bee916492f7aa4f550ea6ced9f7271f065656e"
REPOSITORY = "fraware/open-verification-kernel"


def _complete_runs() -> list[dict[str, Any]]:
    return [
        {
            "workflowName": name,
            "databaseId": index + 100,
            "headSha": SHA,
            "status": "completed",
            "conclusion": "success",
            "url": f"https://github.com/{REPOSITORY}/actions/runs/{index + 100}",
            "path": REQUIRED_WORKFLOW_PATHS[name],
            "createdAt": f"2026-08-26T10:{index:02d}:00Z",
        }
        for index, name in enumerate(REQUIRED_WORKFLOWS)
    ]


def _live_runs() -> dict[int, dict[str, Any]]:
    return {
        int(run["databaseId"]): {
            "id": run["databaseId"],
            "name": run["workflowName"],
            "head_sha": run["headSha"],
            "status": "completed",
            "conclusion": "success",
            "path": run["path"],
            "html_url": run["url"],
            "repository": {"full_name": REPOSITORY},
        }
        for run in _complete_runs()
    }


def _resolver(records: dict[int, dict[str, Any]]):
    def resolve(repository: str, run_id: int) -> dict[str, Any]:
        assert repository == REPOSITORY
        return records[run_id]

    return resolve


def _complete_ledger() -> dict[str, Any]:
    return build_release_ledger(
        REPO,
        candidate_sha=SHA,
        repository=REPOSITORY,
        workflow_evidence={"ok": True, "runs": _complete_runs()},
    )


def _run_only_verify(ledger: dict[str, Any], records: dict[int, dict[str, Any]]):
    """Diagnostic workflow-only scope: verification may pass but never authorizes."""
    return verify_release_ledger(
        ledger,
        repo_root=REPO,
        workflow_run_resolver=_resolver(records),
        require_artifacts=False,
        require_consumers=False,
        require_holdout=False,
    )


def test_required_workflow_contract_matches_release_surfaces() -> None:
    assert REQUIRED_WORKFLOWS == (
        "CI",
        "Repro baseline",
        "Native Backends Tier 1",
        "Native Backends Tier 1b",
        "FormalPR-Holdout predict",
        "FormalPR-Holdout eval",
        "Consumer Pin Verification",
    )
    assert "Bench Badge" not in REQUIRED_WORKFLOWS
    assert set(REQUIRED_WORKFLOWS) == set(REQUIRED_WORKFLOW_PATHS)


def test_ledger_builder_starts_unauthorized() -> None:
    ledger = _complete_ledger()
    assert ledger["schema_version"] == LEDGER_SCHEMA_VERSION == "ovk.release_ledger.v2"
    assert ledger["release_state"]["authorized"] is False
    assert ledger["release_state"]["verified_source_sha"] is None
    assert ledger["release_state"]["published"] is False
    assert ledger["evidence"]["workflow_provenance"] is None
    assert ledger["evidence"]["workflow_artifact_provenance"] is None
    assert ledger["evidence"]["release_artifact_provenance"] is None
    assert ledger["toolchain"]["lock_sha256"]
    assert [run["workflow"] for run in ledger["required_runs"]] == list(REQUIRED_WORKFLOWS)


def test_structural_validation_does_not_grant_authority() -> None:
    ledger = _complete_ledger()
    assert validate_release_ledger_structure(ledger, repo_root=REPO) == []
    assert ledger["release_state"]["authorized"] is False
    assert ledger["release_state"]["verified_source_sha"] is None


def test_default_full_verifier_fails_closed_without_artifact_resolvers() -> None:
    ledger = _complete_ledger()
    ok, failures, checked = verify_release_ledger(
        ledger,
        repo_root=REPO,
        workflow_run_resolver=_resolver(_live_runs()),
    )
    assert ok is False
    assert failures == ["workflow_artifact_provenance_not_verified"]
    assert checked["release_state"]["authorized"] is False
    assert checked["release_state"]["verified_source_sha"] is None


def test_offline_verifier_cannot_authorize_forged_complete_ledger() -> None:
    ledger = _complete_ledger()
    ok, failures, checked = verify_release_ledger(ledger, repo_root=REPO)
    assert ok is False
    assert failures == ["workflow_provenance_not_verified"]
    assert checked["release_state"]["authorized"] is False
    assert checked["release_state"]["verified_source_sha"] is None
    assert checked["evidence"]["workflow_provenance"] is None


def test_independently_resolved_workflow_provenance_is_diagnostic_only() -> None:
    ledger = _complete_ledger()
    ok, failures, checked = _run_only_verify(ledger, _live_runs())
    assert failures == []
    assert ok is True
    assert checked["release_state"]["authorized"] is False
    assert checked["release_state"]["verified_source_sha"] is None
    assert checked["release_state"]["published"] is False
    assert checked["release_state"]["tag"] is None
    assert checked["release_state"]["authorization_reason"] == (
        "partial_provenance_verified_not_release_authorized"
    )
    provenance = checked["evidence"]["workflow_provenance"]
    assert provenance["verifier"] == "github-actions-api.v1"
    assert provenance["repository"] == REPOSITORY
    assert provenance["candidate_sha"] == SHA
    assert set(provenance["verified_run_ids"]) == set(REQUIRED_WORKFLOWS)


def test_verifier_fail_closed_on_missing_workflow() -> None:
    runs = _complete_runs()[:-1]
    ledger = build_release_ledger(
        REPO,
        candidate_sha=SHA,
        workflow_evidence={"ok": True, "runs": runs},
    )
    failures = validate_release_ledger_structure(ledger, repo_root=REPO)
    assert any("missing_required_workflow" in item for item in failures)
    ok, _, checked = verify_release_ledger(
        ledger,
        repo_root=REPO,
        workflow_run_resolver=_resolver(_live_runs()),
        require_artifacts=False,
        require_consumers=False,
        require_holdout=False,
    )
    assert ok is False
    assert checked["release_state"]["verified_source_sha"] is None


def test_live_head_sha_mismatch_cannot_pass() -> None:
    ledger = _complete_ledger()
    records = _live_runs()
    first = next(iter(records))
    records[first] = {**records[first], "head_sha": "0" * 40}
    ok, failures, checked = _run_only_verify(ledger, records)
    assert ok is False
    assert any("workflow_provenance_head_sha_mismatch:CI" in item for item in failures)
    assert checked["release_state"]["verified_source_sha"] is None


def test_live_workflow_name_mismatch_cannot_pass() -> None:
    ledger = _complete_ledger()
    records = _live_runs()
    first = next(iter(records))
    records[first] = {**records[first], "name": "CI lookalike"}
    ok, failures, _ = _run_only_verify(ledger, records)
    assert ok is False
    assert "workflow_provenance_name_mismatch:CI" in failures


def test_live_workflow_path_mismatch_cannot_pass() -> None:
    ledger = _complete_ledger()
    records = _live_runs()
    first = next(iter(records))
    records[first] = {**records[first], "path": ".github/workflows/lookalike.yml"}
    ok, failures, _ = _run_only_verify(ledger, records)
    assert ok is False
    assert "workflow_provenance_path_mismatch:CI" in failures


def test_live_repository_mismatch_cannot_pass() -> None:
    ledger = _complete_ledger()
    records = _live_runs()
    first = next(iter(records))
    records[first] = {
        **records[first],
        "repository": {"full_name": "attacker/open-verification-kernel"},
    }
    ok, failures, _ = _run_only_verify(ledger, records)
    assert ok is False
    assert "workflow_provenance_repository_mismatch:CI" in failures


def test_live_unsuccessful_run_cannot_pass() -> None:
    ledger = _complete_ledger()
    records = _live_runs()
    first = next(iter(records))
    records[first] = {**records[first], "conclusion": "failure"}
    ok, failures, _ = _run_only_verify(ledger, records)
    assert ok is False
    assert "workflow_provenance_conclusion_not_success:CI" in failures


def test_resolver_failure_is_fail_closed() -> None:
    ledger = _complete_ledger()

    def failing_resolver(repository: str, run_id: int) -> dict[str, Any]:
        raise RuntimeError("network unavailable")

    ok, failures, checked = verify_release_ledger(
        ledger,
        repo_root=REPO,
        workflow_run_resolver=failing_resolver,
        require_artifacts=False,
        require_consumers=False,
        require_holdout=False,
    )
    assert ok is False
    assert any(item.startswith("workflow_provenance_lookup_failed:") for item in failures)
    assert checked["release_state"]["verified_source_sha"] is None


def test_ledger_cannot_self_assert_authorization_or_any_provenance() -> None:
    ledger = _complete_ledger()
    ledger["release_state"]["authorized"] = True
    ledger["release_state"]["verified_source_sha"] = SHA
    ledger["evidence"]["workflow_provenance"] = {"verifier": "forged"}
    ledger["evidence"]["workflow_artifact_provenance"] = {"verifier": "forged"}
    ledger["evidence"]["release_artifact_provenance"] = {"verifier": "forged"}
    failures = validate_release_ledger_structure(ledger, repo_root=REPO)
    assert "input ledger must have release_state.authorized=false" in failures
    assert "input ledger must not self-assert verified_source_sha" in failures
    assert "input ledger must not self-assert workflow_provenance" in failures
    assert "input ledger must not self-assert workflow_artifact_provenance" in failures
    assert "input ledger must not self-assert release_artifact_provenance" in failures


def test_verifier_rejects_published_claim() -> None:
    ledger = _complete_ledger()
    ledger["release_state"]["published"] = True
    failures = validate_release_ledger_structure(ledger, repo_root=REPO)
    assert "input ledger must have published=false" in failures


def test_builder_prefers_latest_successful_candidate_run() -> None:
    runs = _complete_runs()
    ci = runs[0]
    runs.extend(
        [
            {
                **ci,
                "databaseId": 999,
                "conclusion": "failure",
                "createdAt": "2026-08-26T11:00:00Z",
            },
            {
                **ci,
                "databaseId": 998,
                "conclusion": "success",
                "createdAt": "2026-08-26T10:59:00Z",
            },
        ]
    )
    ledger = build_release_ledger(
        REPO,
        candidate_sha=SHA,
        workflow_evidence={"ok": True, "runs": runs},
    )
    ci_row = next(run for run in ledger["required_runs"] if run["workflow"] == "CI")
    assert ci_row["run_id"] == 998
    assert ci_row["conclusion"] == "success"


def test_write_release_ledger_isolated_to_requested_root(tmp_path: Path) -> None:
    ledger = _complete_ledger()
    ok, _, checked = _run_only_verify(ledger, _live_runs())
    assert ok

    real_path = REPO / ".verification" / "release-ledger.json"
    real_before = real_path.read_bytes() if real_path.is_file() else None

    out = write_release_ledger(tmp_path, checked)
    assert out == tmp_path / ".verification" / "release-ledger.json"
    on_disk = json.loads(out.read_text(encoding="utf-8"))
    assert on_disk["release_state"]["authorized"] is False
    assert on_disk["release_state"]["verified_source_sha"] is None

    real_after = real_path.read_bytes() if real_path.is_file() else None
    assert real_after == real_before, "tests must not mutate the checkout release ledger"
