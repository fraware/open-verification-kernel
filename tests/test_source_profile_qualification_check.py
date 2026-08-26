"""Regression tests for read-only source-profile qualification verification."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

from ovk.core.source_profile_qualification import write_source_profile_qualification


def _repo_fixture(tmp_path: Path) -> Path:
    shutil.copytree(Path("profiles"), tmp_path / "profiles")
    return tmp_path


def _run_check(repo_root: Path, output: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            "scripts/build_source_profile_qualification.py",
            "--repo-root",
            str(repo_root),
            "--output",
            str(output),
            "--check",
        ],
        text=True,
        capture_output=True,
        check=False,
    )


def test_check_accepts_fresh_artifact_without_mutation(tmp_path: Path) -> None:
    repo_root = _repo_fixture(tmp_path)
    output = repo_root / ".verification" / "source-profile-qualification.json"
    write_source_profile_qualification(repo_root, output)
    before = output.read_bytes()

    result = _run_check(repo_root, output)

    assert result.returncode == 0, result.stderr
    assert output.read_bytes() == before


def test_check_rejects_stale_artifact_without_repairing_it(tmp_path: Path) -> None:
    repo_root = _repo_fixture(tmp_path)
    output = repo_root / ".verification" / "source-profile-qualification.json"
    write_source_profile_qualification(repo_root, output)
    payload = json.loads(output.read_text(encoding="utf-8"))
    payload["profiles"]["authorization.fastapi.ast_v1"]["maturity"] = "forged-strict"
    output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    stale_bytes = output.read_bytes()

    result = _run_check(repo_root, output)

    assert result.returncode == 1
    assert "stale" in result.stderr.lower()
    assert output.read_bytes() == stale_bytes, "--check must not repair the artifact it verifies"


def test_check_rejects_missing_artifact_without_creating_it(tmp_path: Path) -> None:
    repo_root = _repo_fixture(tmp_path)
    output = repo_root / ".verification" / "source-profile-qualification.json"

    result = _run_check(repo_root, output)

    assert result.returncode == 1
    assert "missing" in result.stderr.lower()
    assert not output.exists()
