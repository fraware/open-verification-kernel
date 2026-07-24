from pathlib import Path

from ovk.core.execution_budget import LocalSubprocessWorker


def test_worker_does_not_inherit_unlisted_parent_environment(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("UNRECOGNIZED_PRIVATE_CREDENTIAL", "must-not-leak")
    worker = LocalSubprocessWorker(bound_roots=(tmp_path,))
    result = worker.run(
        [
            "python",
            "-c",
            "import os; print(os.environ.get('UNRECOGNIZED_PRIVATE_CREDENTIAL', ''))",
        ],
        cwd=tmp_path,
        timeout_seconds=5,
    )
    assert result.exit_code == 0
    assert "must-not-leak" not in result.stdout


def test_worker_accepts_explicit_non_secret_environment(tmp_path: Path) -> None:
    worker = LocalSubprocessWorker(bound_roots=(tmp_path,))
    result = worker.run(
        ["python", "-c", "import os; print(os.environ.get('OVK_WORKER_SAFE', ''))"],
        cwd=tmp_path,
        env={"OVK_WORKER_SAFE": "ok"},
        timeout_seconds=5,
    )
    assert result.exit_code == 0
    assert result.stdout.strip() == "ok"


def test_worker_rejects_non_positive_timeout_without_execution(tmp_path: Path) -> None:
    marker = tmp_path / "should-not-exist"
    worker = LocalSubprocessWorker(bound_roots=(tmp_path,))
    result = worker.run(
        ["python", "-c", f"from pathlib import Path; Path({str(marker)!r}).write_text('ran')"],
        cwd=tmp_path,
        timeout_seconds=0,
    )
    assert result.timed_out is True
    assert result.exit_code is None
    assert marker.exists() is False
