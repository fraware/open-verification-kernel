"""A real merge-preview must remain the evidence subject after PR event ingestion.

Local source checks are structural, not signature verification or generalized
source-to-model fidelity. This test creates real Git commits and a merge.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from ovk.cli import app
from ovk.core.context import build_repository_context
from ovk.core.source_binding_identity import (
    SourceSubjectMismatch, require_bound_merge_preview_subject,
)
from scripts.prepare_verified_change_input import prepare


pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="Git required")


def git(*args: str) -> str:
    result = subprocess.run(
        ["git", *args], capture_output=True, text=True, check=True,
    )
    return result.stdout.strip()


@pytest.fixture
def merge_pr(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict:
    monkeypatch.chdir(tmp_path)
    git("init", "-b", "main")
    git("config", "user.email", "test@example.invalid")
    git("config", "user.name", "Source Identity Test")
    git("config", "core.autocrlf", "false")
    (tmp_path / "original.txt").write_text("original\n", encoding="utf-8")
    git("add", ".")
    git("commit", "-m", "base")
    base = git("rev-parse", "HEAD")
    git("checkout", "-b", "contribution")
    (tmp_path / "example.py").write_text("sink()\n", encoding="utf-8")
    git("add", ".")
    git("commit", "-m", "head")
    pr_head = git("rev-parse", "HEAD")
    git("checkout", "main")
    git("merge", "--no-ff", "contribution", "-m", "merge preview")
    merged = git("rev-parse", "HEAD")
    assert merged != pr_head
    event_path = tmp_path / "pr-event.json"
    event_path.write_text(json.dumps({
        "repository": {"full_name": "pilot/repo"},
        "pull_request": {
            "number": 17,
            "head": {"sha": pr_head},
            "base": {"sha": base},
        },
        "sender": {"login": "contributor", "type": "User"},
    }), encoding="utf-8")
    path, diff, receipt = prepare(
        event_name="pull_request", github_sha=merged, base_sha=base, pr_head_sha=pr_head,
    )
    assert path == ".ovk-pr.diff"
    diff_path = tmp_path / path
    diff_path.write_bytes(diff)
    receipt_path = tmp_path / "ovk-source-binding.json"
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
    return {
        "base": base, "head": pr_head, "merge": merged,
        "event": event_path, "diff": diff_path,
        "receipt": receipt_path,
    }


def validate(case: dict) -> None:
    require_bound_merge_preview_subject(
        receipt_path=case["receipt"],
        diff_path=case["diff"],
        event_path=case["event"],
        repo="pilot/repo",
        head_sha=case["merge"],
        base_sha=case["base"],
    )


def test_real_pr_subject_receipt_and_context_agree(merge_pr: dict) -> None:
    validate(merge_pr)
    ordinary = build_repository_context(
        changed_files=["example.py"], github_event_path=merge_pr["event"],
        repo="pilot/repo", head_sha=merge_pr["merge"],
    )
    assert ordinary.head_sha == merge_pr["head"]
    bound = build_repository_context(
        changed_files=["example.py"], github_event_path=merge_pr["event"],
        repo="pilot/repo", head_sha=merge_pr["merge"],
        preserve_explicit_subject=True,
    )
    assert bound.head_sha == merge_pr["merge"]
    assert bound.base_sha == merge_pr["base"]
    assert bound.branch_metadata["event_pr_head_sha"] == merge_pr["head"]
    assert bound.branch_metadata["source_subject_origin"] == "locally_bound_merge_preview"


@pytest.mark.parametrize("mutation", ["receipt_head", "diff", "pr_event", "checkout", "requested_head", "base"])
def test_mismatched_source_materials_fail_closed(merge_pr: dict, mutation: str) -> None:
    case = dict(merge_pr)
    if mutation == "receipt_head":
        receipt = json.loads(case["receipt"].read_text())
        receipt["evidence_subject_sha"] = case["head"]
        case["receipt"].write_text(json.dumps(receipt))
    elif mutation == "diff":
        case["diff"].write_bytes(case["diff"].read_bytes() + b"tamper")
    elif mutation == "pr_event":
        event = json.loads(case["event"].read_text())
        event["pull_request"]["head"]["sha"] = case["base"]
        case["event"].write_text(json.dumps(event))
    elif mutation == "checkout":
        git("checkout", "contribution")
    elif mutation == "requested_head":
        case["merge"] = case["head"]
    elif mutation == "base":
        case["base"] = case["head"]
    with pytest.raises(SourceSubjectMismatch):
        validate(case)


def test_cli_emits_observed_merge_subject_and_keeps_event_pr_head(merge_pr: dict, tmp_path: Path) -> None:
    output = tmp_path / "outputs"
    outcome = CliRunner().invoke(
        app, [
            "check", "--diff", str(merge_pr["diff"]),
            "--github-event", str(merge_pr["event"]),
            "--source-binding", str(merge_pr["receipt"]),
            "--repo", "pilot/repo",
            "--head-sha", merge_pr["merge"],
            "--base-sha", merge_pr["base"],
            "--output-dir", str(output),
            "--advisory", "--no-cache",
        ],
    )
    assert outcome.exit_code == 0, outcome.output
    bundle = json.loads((output / "ovk-evidence.json").read_text())
    assert bundle["subject"]["head_sha"] == merge_pr["merge"]
    assert bundle["subject"]["base_sha"] == merge_pr["base"]
    assert bundle["subject"]["repo"] == "pilot/repo"


def test_cli_rejects_fake_subject_before_publishing_evidence(merge_pr: dict, tmp_path: Path) -> None:
    output = tmp_path / "out-rejected"
    outcome = CliRunner().invoke(
        app, [
            "check", "--diff", str(merge_pr["diff"]),
            "--github-event", str(merge_pr["event"]),
            "--source-binding", str(merge_pr["receipt"]),
            "--repo", "pilot/repo",
            "--head-sha", merge_pr["head"],
            "--output-dir", str(output),
            "--advisory",
        ],
    )
    assert outcome.exit_code != 0
    assert "refusing unbound evidence subject" in outcome.output
    assert not (output / "ovk-evidence.json").exists()
