"""Manifest input has no authenticated PR-diff binding.

The composite Action must not turn explicit manifest output into a GitHub
PR-wide Check or comment, nor inherit generated artifacts from an earlier
Action invocation in the same workspace. Local advisory verification remains.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]


def _steps() -> list[dict]:
    action = yaml.safe_load((ROOT / "action.yml").read_text(encoding="utf-8"))
    return action["runs"]["steps"]


def test_stale_output_cleanup_precedes_package_install() -> None:
    steps = _steps()
    names = [step.get("name") for step in steps]
    assert names.index("Invalidate stale generated Action outputs") < names.index("Install OVK package")
    cleanup = next(step for step in steps if step.get("name") == "Invalidate stale generated Action outputs")
    assert "set -euo pipefail" in cleanup["run"]
    for artifact in (
        "ovk-source-binding.json", "ovk-evidence.json", "ovk-pr-comment.md",
        "ovk-artifact-manifest.json", "ovk-attestation-envelope.json",
        ".ovk-check-emitted",
    ):
        assert artifact in cleanup["run"]


def test_unbound_manifest_has_no_publication_path() -> None:
    steps = _steps()
    by_name = {step.get("name"): step for step in steps}
    assert "Emit OVK GitHub check (verify path)" not in by_name

    default_check = by_name["Emit OVK GitHub check (check path)"]
    assert "inputs.verification-manifest == ''" in default_check["if"]
    assert "inputs.changed-files == ''" in default_check["if"]

    comment = by_name["Post OVK pull-request comment"]
    assert "inputs.verification-manifest == ''" in comment["if"]
    assert "inputs.changed-files == ''" in comment["if"]
    assert "||" not in comment["if"]

    warning = by_name["Disclose unbound manifest inputs"]
    assert "inputs.verification-manifest != ''" in warning["if"]
    assert "source-to-PR binding" in warning["run"]
    assert "strict enforcement are disabled" in warning["run"]


def test_all_caller_selected_inputs_degrade_action_level_decision() -> None:
    step = next(s for s in _steps() if s.get("name") == "Set action outputs")
    assert step["env"]["OVK_CHANGED_FILES"] == "${{ inputs.changed-files }}"
    assert step["env"]["OVK_VERIFICATION_MANIFEST"] == "${{ inputs.verification-manifest }}"
    assert 'or os.environ.get("OVK_CHANGED_FILES")' in step["run"]
    assert 'decision_state = "unknown"' in step["run"]
    assert 'recommendation = "require_human_review"' in step["run"]


def test_manifest_step_is_advisory_only_and_removes_stale_source_receipt() -> None:
    step = next(s for s in _steps() if s.get("name") == "Run OVK multi-lane verification")
    assert "inputs.verification-manifest != ''" in step["if"]
    script = step["run"]
    assert "set -euo pipefail" in script
    assert 'if [ "$OVK_MODE" != "advisory" ]; then' in script
    assert "exit 2" in script
    for path in (
        "ovk-source-binding.json",
        ".ovk-effective-input-path",
        ".ovk-pr.diff",
        ".ovk-check-emitted",
        "ovk-evidence.json",
        "ovk-pr-comment.md",
        "ovk-attestation-envelope.json",
    ):
        assert path in script
    assert "args+=(--advisory)" in script


@pytest.mark.skipif(sys.platform == "win32", reason="Bash step executes on Linux/macOS in this runtime test")
def test_strict_manifest_rejects_before_checker_or_artifact_reuse(tmp_path: Path) -> None:
    if shutil.which("bash") is None:
        pytest.skip("bash unavailable")
    script = next(
        s["run"] for s in _steps()
        if s.get("name") == "Run OVK multi-lane verification"
    )
    for name in (
        "ovk-source-binding.json", ".ovk-effective-input-path",
        ".ovk-pr.diff", "ovk-evidence.json", ".ovk-check-emitted",
    ):
        (tmp_path / name).write_text("STALE", encoding="utf-8")

    env = dict(os.environ)
    env.update({
        "OVK_MODE": "strict",
        "OVK_VERIFICATION_MANIFEST": "fixtures/fake.json",
        "OVK_BUNDLE_OUTPUT_DIR": "ovk-release-bundle",
        "OVK_REPO": "owner/repo",
        "OVK_HEAD_SHA": "a" * 40,
    })
    result = subprocess.run(
        ["bash", "-eo", "pipefail", "-c", script],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 2, result.stderr
    assert "strict Action enforcement is refused" in result.stdout
    for name in (
        "ovk-source-binding.json", ".ovk-effective-input-path",
        ".ovk-pr.diff", "ovk-evidence.json", ".ovk-check-emitted",
    ):
        assert not (tmp_path / name).exists()


@pytest.mark.skipif(sys.platform == "win32", reason="Bash runtime exercised on Linux/macOS")
def test_manifest_rejects_existing_nonempty_output_bundle(tmp_path: Path) -> None:
    if shutil.which("bash") is None:
        pytest.skip("bash unavailable")
    step = next(step for step in _steps() if step.get("name") == "Run OVK multi-lane verification")
    folder = tmp_path / "ovk-release-bundle"
    folder.mkdir()
    (folder / "old-ovk-evidence.json").write_text("STALE", encoding="utf-8")
    env = dict(os.environ)
    env.update({
        "OVK_MODE": "advisory",
        "OVK_VERIFICATION_MANIFEST": "sample.json",
        "OVK_BUNDLE_OUTPUT_DIR": str(folder),
        "OVK_REPO": "owner/repo",
        "OVK_HEAD_SHA": "b" * 40,
    })
    proc = subprocess.run(
        ["bash", "-eo", "pipefail", "-c", step["run"]],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 2, proc.stderr
    assert "already contains files" in proc.stdout
    assert (folder / "old-ovk-evidence.json").read_text(encoding="utf-8") == "STALE"


@pytest.mark.skipif(sys.platform == "win32", reason="Bash execution tested on Linux/macOS")
def test_manifest_pass_cannot_be_exported_as_pr_allow(tmp_path: Path) -> None:
    if shutil.which("bash") is None:
        pytest.skip("bash unavailable")
    outputs = next(step for step in _steps() if step.get("name") == "Set action outputs")
    folder = tmp_path / "ovk-bundle"
    folder.mkdir()
    (folder / "ovk-evidence.json").write_text(
        '{"decision": {"decision_state": "allow", "merge_recommendation": "allow"}}',
        encoding="utf-8",
    )
    target = tmp_path / "action-output.txt"
    env = dict(os.environ)
    env.update({
        "OVK_VERIFICATION_MANIFEST": "selected.json",
        "OVK_BUNDLE_OUTPUT_DIR": str(folder),
        "OVK_EVIDENCE_OUTPUT": "ovk-evidence.json",
        "GITHUB_OUTPUT": str(target),
    })
    proc = subprocess.run(
        ["bash", "-eo", "pipefail", "-c", outputs["run"]],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    outcome = dict(line.split("=", 1) for line in target.read_text(encoding="utf-8").splitlines())
    assert outcome == {
        "decision_state": "unknown",
        "recommendation": "require_human_review",
        "exit_code": "2",
        "check_emitted": "false",
    }
    # The raw, explicitly scoped advisory observation remains available.
    assert '"allow"' in (folder / "ovk-evidence.json").read_text(encoding="utf-8")


@pytest.mark.skipif(sys.platform == "win32", reason="Bash runtime exercised on Linux/macOS")
@pytest.mark.parametrize(
    ("changed_files", "expected_state", "expected_exit"),
    [("caller-selected.diff", "unknown", "2"), ("", "allow", "0")],
)
def test_caller_selected_diff_cannot_export_allow_but_default_bound_path_can(
    tmp_path: Path, changed_files: str, expected_state: str, expected_exit: str,
) -> None:
    if shutil.which("bash") is None:
        pytest.skip("bash unavailable")
    step = next(s for s in _steps() if s.get("name") == "Set action outputs")
    (tmp_path / "ovk-evidence.json").write_text(
        '{"decision": {"decision_state": "allow", "merge_recommendation": "allow"}}',
        encoding="utf-8",
    )
    target = tmp_path / "action-outputs.txt"
    env = dict(os.environ)
    env.update({
        "OVK_VERIFICATION_MANIFEST": "",
        "OVK_CHANGED_FILES": changed_files,
        "OVK_BUNDLE_OUTPUT_DIR": "ovk-release-bundle",
        "OVK_EVIDENCE_OUTPUT": "ovk-evidence.json",
        "GITHUB_OUTPUT": str(target),
    })
    proc = subprocess.run(
        ["bash", "-eo", "pipefail", "-c", step["run"]],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    outcome = dict(line.split("=", 1) for line in target.read_text(encoding="utf-8").splitlines())
    assert outcome["decision_state"] == expected_state
    assert outcome["exit_code"] == expected_exit
    assert outcome["recommendation"] == (
        "allow" if not changed_files else "require_human_review"
    )
    assert outcome["check_emitted"] == "false"
