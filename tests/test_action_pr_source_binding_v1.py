"""Adversarial Git-object tests for source/diff binding in the Action.

These are real Git commits and a two-parent merge-preview, not mocked SHA
strings. No network or GitHub credentials are involved.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from scripts import prepare_verified_change_input as binding

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="Git required")


def git(*args: str) -> str:
    proc = subprocess.run(
        ["git", *args], check=True, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True,
    )
    return proc.stdout.strip()


@pytest.fixture
def example_repo(tmp_path, monkeypatch):
    repo = tmp_path / "consumer"
    repo.mkdir()
    monkeypatch.chdir(repo)
    git("init", "-b", "main")
    git("config", "user.email", "test@example.invalid")
    git("config", "user.name", "OVK Test")
    git("config", "core.autocrlf", "false")
    (repo / "base.txt").write_text("base\n", encoding="utf-8")
    git("add", ".")
    git("commit", "-m", "base")
    base = git("rev-parse", "HEAD")
    git("checkout", "-b", "contributor")
    (repo / "pr.txt").write_text("head\n", encoding="utf-8")
    git("add", ".")
    git("commit", "-m", "head")
    pr_head = git("rev-parse", "HEAD")
    git("checkout", "main")
    git("merge", "--no-ff", "contributor", "-m", "merge-preview")
    merge = git("rev-parse", "HEAD")
    assert merge != pr_head
    assert binding.parents() == [base, pr_head]
    return {"repo": repo, "base": base, "pr_head": pr_head, "merge": merge}


def make_args(record):
    return {
        "event_name": "pull_request",
        "base_sha": record["base"],
        "pr_head_sha": record["pr_head"],
        "github_sha": record["merge"],
    }


def test_real_merge_preview_checks_the_tree_it_labels(example_repo):
    path, diff, receipt = binding.prepare(**make_args(example_repo))
    expected = subprocess.run(
        ["git", "diff", "--no-ext-diff", "--binary",
         example_repo["base"], example_repo["merge"]],
        check=True, stdout=subprocess.PIPE,
    ).stdout
    assert path == ".ovk-pr.diff"
    assert diff == expected
    assert b"pr.txt" in diff
    assert receipt["event_pr_head_sha"] != receipt["evaluated_checkout_commit_sha"]
    assert receipt["evidence_subject_sha"] == example_repo["merge"]
    assert receipt["event_base_sha"] == example_repo["base"]
    assert receipt["input_comparison"] == "event_base_to_verified_merge_preview"
    assert receipt["input_diff_sha256"] == hashlib.sha256(diff).hexdigest()
    assert receipt["input_structurally_bound_to_checkout"] is True
    assert receipt["bound_into_signed_evidence_envelope"] is False
    assert receipt["production_reliance_authorized"] is False


@pytest.mark.parametrize("mutation", ["head", "base", "checkout"])
def test_identity_confusion_rejected(example_repo, mutation):
    options = make_args(example_repo)
    if mutation == "head":
        options["pr_head_sha"] = example_repo["base"]
    elif mutation == "base":
        options["base_sha"] = example_repo["pr_head"]
    else:
        options["github_sha"] = example_repo["pr_head"]
    with pytest.raises(binding.BindingError):
        binding.prepare(**options)


def test_non_merge_pr_checkout_rejected(example_repo):
    git("checkout", "contributor")
    options = make_args(example_repo)
    options["github_sha"] = example_repo["pr_head"]
    with pytest.raises(binding.BindingError, match="merge parents"):
        binding.prepare(**options)


@pytest.mark.parametrize("payload", [b"caller-selected input\n", b"caller-selected input\r\n"])
def test_external_input_is_advisory_and_explicitly_unbound(example_repo, payload):
    # Bytes must be stable across OSes: Windows text-mode writes translate LF to CRLF.
    custom = example_repo["repo"] / "manual.diff"
    custom.write_bytes(payload)
    path, diff, receipt = binding.prepare(
        **make_args(example_repo), changed_files=str(custom),
    )
    assert path == str(custom)
    assert diff == payload
    assert receipt["input_diff_sha256"] == hashlib.sha256(payload).hexdigest()
    assert receipt["input_comparison"] == "caller_supplied_unbound"
    assert receipt["input_structurally_bound_to_checkout"] is False
    with pytest.raises(binding.BindingError, match="cannot authorize strict"):
        binding.prepare(**make_args(example_repo), changed_files=str(custom), mode="strict")


def test_caller_input_does_not_hide_mismatched_checkout(example_repo):
    custom = example_repo["repo"] / "manual.diff"
    custom.write_text("caller-selected input", encoding="utf-8")
    options = make_args(example_repo)
    options["github_sha"] = example_repo["base"]
    with pytest.raises(binding.BindingError):
        binding.prepare(**options, changed_files=str(custom))


def test_privileged_event_refused(example_repo):
    with pytest.raises(binding.BindingError, match="pull_request_target"):
        binding.prepare(
            event_name="pull_request_target", github_sha=example_repo["merge"],
        )


def test_bad_sha_and_non_pr_pr_metadata_fail_closed(example_repo):
    with pytest.raises(binding.BindingError):
        binding.prepare(event_name="pull_request", github_sha="HEAD")
    with pytest.raises(binding.BindingError, match="non-PR"):
        binding.prepare(
            event_name="push", github_sha=example_repo["merge"],
            pr_head_sha=example_repo["pr_head"],
        )


def test_cli_generates_separate_observational_receipt(example_repo):
    assert binding.main([
        "--event-name", "pull_request",
        "--github-sha", example_repo["merge"],
        "--base-sha", example_repo["base"],
        "--pr-head-sha", example_repo["pr_head"],
    ]) == 0
    path = Path(".ovk-effective-input-path").read_text(encoding="utf-8").strip()
    receipt = json.loads(Path("ovk-source-binding.json").read_text(encoding="utf-8"))
    assert path == ".ovk-pr.diff"
    # Bash command substitution strips LF, not CR. This must be exact on Windows.
    assert Path(".ovk-effective-input-path").read_bytes() == b".ovk-pr.diff\n"
    assert receipt["input_diff_sha256"] == hashlib.sha256(
        Path(path).read_bytes()
    ).hexdigest()
    assert receipt["bound_into_signed_evidence_envelope"] is False


def test_source_binding_failure_emits_no_misleading_new_receipt(example_repo):
    assert binding.main([
        "--event-name", "pull_request",
        "--github-sha", example_repo["base"],
        "--base-sha", example_repo["base"],
        "--pr-head-sha", example_repo["pr_head"],
    ]) == 2
    assert not Path("ovk-source-binding.json").exists()


def test_rejected_source_binding_discards_previous_generated_outputs(example_repo):
    # A failed PR identity check must not leave old handoff/receipt files that
    # the always-running artifact upload step could mistake for current output.
    Path(".ovk-effective-input-path").write_bytes(b"stale.diff\\n")
    Path("ovk-source-binding.json").write_bytes(b'{"forged": true}\\n')
    assert binding.main([
        "--event-name", "pull_request",
        "--github-sha", example_repo["base"],
        "--base-sha", example_repo["base"],
        "--pr-head-sha", example_repo["pr_head"],
    ]) == 2
    assert not Path(".ovk-effective-input-path").exists()
    assert not Path("ovk-source-binding.json").exists()


def test_caller_input_cannot_alias_generated_receipt(example_repo):
    content = b"caller supplied input"
    Path("ovk-source-binding.json").write_bytes(content)
    assert binding.main([
        "--event-name", "pull_request",
        "--github-sha", example_repo["merge"],
        "--base-sha", example_repo["base"],
        "--pr-head-sha", example_repo["pr_head"],
        "--changed-files", "ovk-source-binding.json",
    ]) == 2
    # Reserved generated artifacts must be removed even when used as inputs.
    assert not Path("ovk-source-binding.json").exists()


def test_non_pr_push_uses_actual_checkout_parent(example_repo):
    _, diff, receipt = binding.prepare(
        event_name="push", github_sha=example_repo["merge"],
    )
    assert receipt["input_comparison"] == "checked_out_first_parent_to_head"
    assert receipt["input_structurally_bound_to_checkout"] is True
    assert b"pr.txt" in diff
