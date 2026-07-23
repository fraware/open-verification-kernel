import json
from pathlib import Path
from unittest.mock import MagicMock, patch
from urllib.error import URLError

from scripts.emit_github_check import _post_check_run, main


def _write_evidence(path: Path, recommendation: str = "block") -> None:
    payload = {
        "schema_version": "ovk.bundle.v1",
        "bundle_id": "emit-check-test",
        "subject": {"repo": "owner/repo", "head_sha": "abc123"},
        "evidence": [],
        "open_obligations": [],
        "decision": {
            "merge_recommendation": recommendation,
            "reason": "unit-test fixture",
        },
    }
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_emit_github_check_dry_run_prints_payload(capsys, tmp_path: Path) -> None:
    evidence = tmp_path / "ovk-evidence.json"
    _write_evidence(evidence)
    with patch("sys.argv", ["emit_github_check.py", "--evidence", str(evidence), "--dry-run"]):
        assert main() == 0
    output = capsys.readouterr().out
    payload = json.loads(output)
    assert payload["name"] == "Open Verification Kernel"
    assert payload["conclusion"] == "failure"


def test_emit_github_check_missing_evidence_exits_zero(tmp_path: Path) -> None:
    missing = tmp_path / "missing.json"
    with patch("sys.argv", ["emit_github_check.py", "--evidence", str(missing)]):
        assert main() == 0


def test_emit_github_check_posts_check_run(tmp_path: Path, monkeypatch) -> None:
    evidence = tmp_path / "ovk-evidence.json"
    markdown = tmp_path / "ovk-pr-comment.md"
    _write_evidence(evidence, recommendation="allow")
    markdown.write_text("summary", encoding="utf-8")
    monkeypatch.setenv("GITHUB_TOKEN", "test-token")

    response = MagicMock()
    response.status = 201
    response.__enter__ = MagicMock(return_value=response)
    response.__exit__ = MagicMock(return_value=False)

    with patch("sys.argv", [
        "emit_github_check.py",
        "--evidence",
        str(evidence),
        "--markdown",
        str(markdown),
        "--repo",
        "owner/repo",
        "--head-sha",
        "abc123",
    ]):
        with patch("urllib.request.urlopen", return_value=response) as urlopen:
            assert main() == 0
            request = urlopen.call_args.args[0]
            assert request.full_url.endswith("/repos/owner/repo/check-runs")
            assert request.get_header("Authorization") == "Bearer test-token"
            body = json.loads(request.data.decode("utf-8"))
            assert body["conclusion"] == "success"


def test_emit_github_check_api_failure_returns_one(tmp_path: Path, monkeypatch) -> None:
    evidence = tmp_path / "ovk-evidence.json"
    _write_evidence(evidence)
    monkeypatch.setenv("GITHUB_TOKEN", "test-token")

    with patch("sys.argv", [
        "emit_github_check.py",
        "--evidence",
        str(evidence),
        "--repo",
        "owner/repo",
        "--head-sha",
        "abc123",
    ]):
        with patch("scripts.emit_github_check._post_check_run", return_value=False):
            assert main() == 1


def test_post_check_run_returns_false_on_http_error() -> None:
    with patch("urllib.request.urlopen", side_effect=URLError("network down")):
        assert _post_check_run("https://api.github.com", "owner/repo", "token", {"name": "x"}) is False
