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
