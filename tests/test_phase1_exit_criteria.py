import json
import subprocess
import sys
import time
from pathlib import Path

from ovk.core.check import run_check


ROOT = Path(__file__).resolve().parents[1]


def test_check_ci_secrets_diff_blocks_under_five_seconds() -> None:
    diff_text = Path("examples/ci_secrets/workflow_secrets_on_pr.diff").read_text(encoding="utf-8")
    started = time.perf_counter()
    result = run_check(diff_text=diff_text, use_cache=False, repo="test/repo", head_sha="abc123")
    elapsed_s = time.perf_counter() - started
    assert result.bundle.decision.get("merge_recommendation") == "block"
    assert elapsed_s < 5.0


def test_check_cli_writes_outputs_to_output_dir(tmp_path: Path) -> None:
    output_dir = tmp_path / "bundle"
    command = [
        sys.executable,
        "-m",
        "ovk.cli",
        "check",
        "--diff",
        str(ROOT / "examples/ci_secrets/workflow_secrets_on_pr.diff"),
        "--advisory",
        "--output-dir",
        str(output_dir),
        "--format",
        "json",
    ]
    completed = subprocess.run(command, cwd=ROOT, check=False, capture_output=True, text=True)
    assert completed.returncode == 0, completed.stderr
    evidence = json.loads((output_dir / "ovk-evidence.json").read_text(encoding="utf-8"))
    assert evidence["decision"]["merge_recommendation"] == "block"


def test_compilation_failure_requires_human_review() -> None:
    result = run_check(changed_files=["README.md"], use_cache=False)
    assert result.bundle.decision.get("merge_recommendation") == "require_human_review"
    assert result.jobs == []
