"""Portable informational PR summary from exact local evidence and source receipt.

These tests do not assert event authenticity, checker soundness, or permission
to merge. They guard a low-friction, least-privilege observation surface.
"""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest
import yaml

from scripts.render_source_bound_job_summary import ObservationError, build_summary, main


ROOT = Path(__file__).resolve().parents[1]
BASE = "a" * 40
HEAD = "b" * 40
MERGE = "c" * 40
TREE = "f" * 40
DIFF_BYTES = b"diff --git a/sample.py b/sample.py\n+authorized = True\n"
DIFF = hashlib.sha256(DIFF_BYTES).hexdigest()


def receipt() -> dict:
    return {
        "schema_version": "ovk.pr_source_input_binding.v1-development",
        "event_name": "pull_request",
        "event_base_sha": BASE,
        "event_pr_head_sha": HEAD,
        "evaluated_checkout_commit_sha": MERGE,
        "evaluated_checkout_tree_sha": TREE,
        "evidence_subject_sha": MERGE,
        "input_comparison": "event_base_to_verified_merge_preview",
        "input_diff_sha256": DIFF,
        "input_structurally_bound_to_checkout": True,
        "independent_event_authentication": False,
        "bound_into_signed_evidence_envelope": False,
        "production_reliance_authorized": False,
    }


def evidence(state: str = "allow") -> dict:
    return {
        "schema_version": "ovk.bundle.v1",
        "bundle_id": "local-case",
        "subject": {"repo": "example/repo", "head_sha": MERGE},
        "evidence": [],
        "decision": {"decision_state": state, "merge_recommendation": state},
    }


def test_shareable_summary_is_precisely_scoped_and_identifiable() -> None:
    data = evidence("block")
    raw = json.dumps(data, sort_keys=True).encode()
    markdown = build_summary(data, receipt(), raw, DIFF_BYTES)
    assert "advisory PR observation" in markdown
    assert "**Recorded scoped decision:** `block`" in markdown
    for id_ in (BASE, HEAD, MERGE, TREE, DIFF):
        assert id_ in markdown
    assert hashlib.sha256(raw).hexdigest() in markdown
    assert "neither the event nor the evidence is independently authenticated" in markdown
    assert "An `allow` is not permission to merge." in markdown
    assert "not signed into the evidence envelope" in markdown
    assert "supported-source completeness" in markdown


@pytest.mark.parametrize(
    ("key", "replacement"),
    [
        ("schema_version", "unknown.schema"),
        ("event_name", "push"),
        ("input_comparison", "caller_supplied_unbound"),
        ("input_structurally_bound_to_checkout", False),
        ("independent_event_authentication", True),
        ("bound_into_signed_evidence_envelope", True),
        ("production_reliance_authorized", True),
        ("evaluated_checkout_commit_sha", "wrong"),
        ("event_pr_head_sha", "missing"),
        ("event_base_sha", "BAD"),
        ("evaluated_checkout_tree_sha", "missing"),
        ("input_diff_sha256", "not-a-digest"),
        ("evidence_subject_sha", BASE),
    ],
)
def test_unbound_unexpected_and_malformed_receipts_fail_closed(key: str, replacement: object) -> None:
    altered = copy.deepcopy(receipt())
    altered[key] = replacement
    with pytest.raises(ObservationError):
        build_summary(evidence(), altered, b"{}", DIFF_BYTES)


def test_subject_mismatch_and_unknown_decision_fail_closed() -> None:
    altered = evidence()
    altered["subject"]["head_sha"] = HEAD
    with pytest.raises(ObservationError, match="evidence subject"):
        build_summary(altered, receipt(), b"{}", DIFF_BYTES)
    with pytest.raises(ObservationError, match="decision state"):
        build_summary(evidence("authoritative_verified"), receipt(), b"{}", DIFF_BYTES)


def test_renderer_appends_without_overwriting_existing_job_summary(tmp_path: Path) -> None:
    observation = tmp_path / "evidence.json"
    binding = tmp_path / "binding.json"
    diff = tmp_path / "actual-pr.diff"
    diff.write_bytes(DIFF_BYTES)
    output = tmp_path / "summary.md"
    observation.write_text(json.dumps(evidence()), encoding="utf-8")
    binding.write_text(json.dumps(receipt()), encoding="utf-8")
    output.write_text("## Existing reviewer summary\n\n", encoding="utf-8")

    assert main([
        "--evidence", str(observation),
        "--source-binding", str(binding),
        "--diff", str(diff),
        "--output", str(output),
    ]) == 0
    contents = output.read_text(encoding="utf-8")
    assert contents.startswith("## Existing reviewer summary\n\n")
    assert "advisory PR observation" in contents
    assert MERGE in contents
    assert observation.read_bytes() and binding.read_bytes()


def test_no_summary_written_from_unbound_input(tmp_path: Path) -> None:
    observation = tmp_path / "evidence.json"
    binding = tmp_path / "binding.json"
    diff = tmp_path / "actual-pr.diff"
    diff.write_bytes(DIFF_BYTES)
    output = tmp_path / "summary.md"
    observation.write_text(json.dumps(evidence("allow")), encoding="utf-8")
    unbound = receipt()
    unbound["input_structurally_bound_to_checkout"] = False
    binding.write_text(json.dumps(unbound), encoding="utf-8")

    assert main([
        "--evidence", str(observation),
        "--source-binding", str(binding),
        "--diff", str(diff),
        "--output", str(output),
    ]) == 2
    assert not output.exists()


def test_job_summary_only_runs_for_default_source_bound_advisory_pr() -> None:
    action = yaml.safe_load((ROOT / "action.yml").read_text(encoding="utf-8"))
    steps = action["runs"]["steps"]
    step = next(s for s in steps if s.get("name") == "Share scoped advisory observation in job summary")
    condition = step["if"]
    for guard in (
        "github.event_name == 'pull_request'",
        "inputs.mode == 'advisory'",
        "inputs.verification-manifest == ''",
        "inputs.changed-files == ''",
        "inputs.use-check == 'true'",
    ):
        assert guard in condition
    assert 'render_source_bound_job_summary.py' in step["run"]
    assert "--diff .ovk-pr.diff" in step["run"]
    assert '"$GITHUB_STEP_SUMMARY"' in step["run"]
    assert "GITHUB_TOKEN" not in step.get("env", {})
    assert "GITHUB_TOKEN" not in step["run"]
    assert "check-runs" not in step["run"]


def test_modified_diff_bytes_cannot_be_described_by_old_receipt() -> None:
    with pytest.raises(ObservationError, match="diff bytes"):
        build_summary(evidence(), receipt(), b"{}", DIFF_BYTES + b"unexpected")


def test_missing_source_diff_never_creates_report(tmp_path: Path) -> None:
    observation = tmp_path / "evidence.json"
    binding = tmp_path / "binding.json"
    destination = tmp_path / "summary.md"
    observation.write_text(json.dumps(evidence()), encoding="utf-8")
    binding.write_text(json.dumps(receipt()), encoding="utf-8")
    assert main([
        "--evidence", str(observation),
        "--source-binding", str(binding),
        "--diff", str(tmp_path / "absent.diff"),
        "--output", str(destination),
    ]) == 2
    assert not destination.exists()


def test_portable_report_matches_append_only_job_summary(tmp_path: Path) -> None:
    evidence_path = tmp_path / "ovk-evidence.json"
    receipt_path = tmp_path / "ovk-source-binding.json"
    diff_path = tmp_path / ".ovk-pr.diff"
    job_summary = tmp_path / "GITHUB_STEP_SUMMARY"
    portable = tmp_path / "ovk-advisory-pr-summary.md"
    evidence_path.write_text(json.dumps(evidence("allow")), encoding="utf-8")
    receipt_path.write_text(json.dumps(receipt()), encoding="utf-8")
    diff_path.write_bytes(DIFF_BYTES)
    job_summary.write_text("## First tool\n\n", encoding="utf-8")
    rc = main([
        "--evidence", str(evidence_path), "--source-binding", str(receipt_path),
        "--diff", str(diff_path), "--output", str(job_summary),
        "--portable-output", str(portable),
    ])
    assert rc == 0
    expected = build_summary(evidence(), receipt(), evidence_path.read_bytes(), DIFF_BYTES)
    assert portable.read_text(encoding="utf-8") == expected + "\n"
    assert job_summary.read_text(encoding="utf-8") == "## First tool\n\n" + expected + "\n"
    assert "An `allow` is not permission to merge" in portable.read_text(encoding="utf-8")
    assert "independently authenticated" in portable.read_text(encoding="utf-8")
    assert "ovk-advisory-pr-summary" not in evidence_path.read_text(encoding="utf-8")


def test_bad_source_does_not_retain_preexisting_shareable_report(tmp_path: Path) -> None:
    evidence_path = tmp_path / "ovk-evidence.json"
    receipt_path = tmp_path / "ovk-source-binding.json"
    diff_path = tmp_path / ".ovk-pr.diff"
    job_summary = tmp_path / "GITHUB_STEP_SUMMARY"
    portable = tmp_path / "ovk-advisory-pr-summary.md"
    evidence_path.write_text(json.dumps(evidence()), encoding="utf-8")
    receipt_path.write_text(json.dumps(receipt()), encoding="utf-8")
    diff_path.write_bytes(DIFF_BYTES + b"tampered")
    portable.write_text("UNSAFE STALE ALLOW", encoding="utf-8")
    assert main([
        "--evidence", str(evidence_path), "--source-binding", str(receipt_path),
        "--diff", str(diff_path), "--output", str(job_summary),
        "--portable-output", str(portable),
    ]) == 2
    assert not portable.exists()
    assert not job_summary.exists()


@pytest.mark.parametrize("alias", ["evidence", "receipt", "diff", "summary"])
def test_portable_report_cannot_overwrite_verification_input(
    tmp_path: Path, alias: str,
) -> None:
    paths = {
        "evidence": tmp_path / "evidence.json",
        "receipt": tmp_path / "receipt.json",
        "diff": tmp_path / "change.diff",
        "summary": tmp_path / "job-summary.md",
    }
    paths["evidence"].write_text(json.dumps(evidence()), encoding="utf-8")
    paths["receipt"].write_text(json.dumps(receipt()), encoding="utf-8")
    paths["diff"].write_bytes(DIFF_BYTES)
    before = paths[alias].read_bytes() if paths[alias].exists() else None
    assert main([
        "--evidence", str(paths["evidence"]),
        "--source-binding", str(paths["receipt"]),
        "--diff", str(paths["diff"]),
        "--output", str(paths["summary"]),
        "--portable-output", str(paths[alias]),
    ]) == 2
    after = paths[alias].read_bytes() if paths[alias].exists() else None
    assert before == after


def test_action_uploads_scoped_report_without_uploading_raw_diff(tmp_path: Path) -> None:
    action = yaml.safe_load((ROOT / "action.yml").read_text(encoding="utf-8"))
    steps = action["runs"]["steps"]
    summary = next(s for s in steps if s.get("name") == "Share scoped advisory observation in job summary")
    assert "--portable-output ovk-advisory-pr-summary.md" in summary["run"]
    assert "inputs.changed-files == ''" in summary["if"]
    assert "inputs.verification-manifest == ''" in summary["if"]
    upload = next(s for s in steps if s.get("name") == "Upload OVK artifacts")
    assert "ovk-advisory-pr-summary.md" in upload["with"]["path"]
    cleanup = next(s for s in steps if s.get("name") == "Invalidate stale generated Action outputs")
    assert "ovk-advisory-pr-summary.md" in cleanup["run"]
