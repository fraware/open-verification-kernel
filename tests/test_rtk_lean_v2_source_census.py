"""Source-only census checks. Git revisions are real; native Lean is not run."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from experiments.rtk.lean_v2_source_census import (
    _source_theorems,
    source_only_transition_census,
)


def _git(root: Path, *args: str) -> str:
    run = subprocess.run(
        ["git", "-C", str(root), *args],
        text=True,
        capture_output=True,
        check=True,
    )
    return run.stdout.strip()


def _history(tmp_path: Path, *, source_text: str) -> tuple[Path, str, str]:
    root = tmp_path / "upstream"
    root.mkdir()
    _git(root, "init")
    _git(root, "config", "user.email", "test@example.org")
    _git(root, "config", "user.name", "Source Census Test")
    (root / "Proof.lean").write_text(source_text)
    _git(root, "add", "Proof.lean")
    _git(root, "commit", "-m", "original proof")
    source_sha = _git(root, "rev-parse", "HEAD")
    # The exact target file is changed, yet the census may only examine
    # the source blob. A native target check belongs to a separate phase.
    (root / "Proof.lean").write_text(
        source_text + "\n/-! Target-only prose. -/\n"
    )
    _git(root, "add", "Proof.lean")
    _git(root, "commit", "-m", "target prose")
    target_sha = _git(root, "rev-parse", "HEAD")
    return root, source_sha, target_sha


def test_source_census_emits_preliminary_source_only_record(tmp_path):
    root, old, new = _history(
        tmp_path,
        source_text="theorem id_nat (n : Nat) : n = n := by\n  rfl\n\n",
    )
    record = source_only_transition_census(
        repo_path=root, repository="external/examples",
        source_sha=old, target_sha=new,
    )
    assert record["target_file_bytes_read_by_adapter"] is False
    assert record["oracle_checks_executed"] is False
    assert record["source_native_checks_executed"] is False
    assert record["sut_predictions_executed"] is False
    assert record["case_qualification_complete"] is False
    assert len(record["candidates"]) == 1
    assert record["candidates"][0]["theorem_name"] == "id_nat"
    assert record["candidates"][0]["status"] == "PRELIMINARY_SOURCE_SHAPE_ONLY"


def test_source_census_fails_closed_for_hole(tmp_path):
    root, old, new = _history(
        tmp_path, source_text="theorem fabricated : True := by\n  sorry\n\n"
    )
    record = source_only_transition_census(
        repo_path=root, repository="external/examples",
        source_sha=old, target_sha=new,
    )
    assert record["candidates"] == []
    assert record["exclusions"][0]["reason"] == (
        "no_unambiguous_supported_source_theorem"
    )


def test_non_parent_commits_cannot_form_transition(tmp_path):
    root, old, new = _history(
        tmp_path,
        source_text="theorem id_nat (n : Nat) : n = n := by\n  rfl\n\n",
    )
    with pytest.raises(ValueError, match="first parent"):
        source_only_transition_census(
            repo_path=root,
            repository="external/examples",
            source_sha=new,
            target_sha=old,
        )


def test_unsupported_source_proof_forms_are_excluded():
    assert _source_theorems(
        "import Mathlib\ntheorem z : True := by\n  trivial\n\n"
    ) == []
    assert _source_theorems(
        "theorem z : True := by\n  sorry\n\n"
    ) == []


def test_repeated_theorem_names_fail_closed():
    text = (
        "theorem same : True := by\n  trivial\n\n"
        "theorem same : True := by\n  trivial\n\n"
    )
    assert _source_theorems(text) == []
