import json
from pathlib import Path
from unittest.mock import MagicMock, patch
from urllib.error import URLError

from scripts.emit_github_check import _post_check_run, emit_or_update_check_run, main


def _write_evidence(path: Path, recommendation: str = "block", head_sha: str = "abc123") -> None:
    payload = {
        "schema_version": "ovk.bundle.v1",
        "bundle_id": "emit-check-test",
        "subject": {"repo": "owner/repo", "head_sha": head_sha},
        "evidence": [],
        "open_obligations": [],
        "decision": {
            "merge_recommendation": recommendation,
            "decision_state": "block" if recommendation == "block" else "allow",
            "reason": "unit-test fixture",
        },
    }
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_emit_github_check_dry_run_prints_payload(capsys, tmp_path: Path) -> None:
    evidence = tmp_path / "ovk-evidence.json"
    _write_evidence(evidence)
    with patch(
        "sys.argv",
        ["emit_github_check.py", "--evidence", str(evidence), "--head-sha", "abc123", "--dry-run"],
    ):
        assert main() == 0
    output = capsys.readouterr().out
    payload = json.loads(output)
    assert payload["name"] == "Open Verification Kernel"
    assert payload["conclusion"] == "failure"
    assert payload["external_id"] == "ovk:owner/repo:abc123"


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

    responses: list[MagicMock] = []

    def make_response(status: int, body: dict | list) -> MagicMock:
        response = MagicMock()
        response.status = status
        response.read = MagicMock(return_value=json.dumps(body).encode("utf-8"))
        response.__enter__ = MagicMock(return_value=response)
        response.__exit__ = MagicMock(return_value=False)
        responses.append(response)
        return response

    # First call: list check-runs (empty). Second: create check-run.
    queue = [
        make_response(200, {"check_runs": []}),
        make_response(201, {"id": 1}),
    ]

    with patch(
        "sys.argv",
        [
            "emit_github_check.py",
            "--evidence",
            str(evidence),
            "--markdown",
            str(markdown),
            "--repo",
            "owner/repo",
            "--head-sha",
            "abc123",
        ],
    ):
        with patch("urllib.request.urlopen", side_effect=queue) as urlopen:
            assert main() == 0
            assert urlopen.call_count == 2
            create_request = urlopen.call_args_list[1].args[0]
            assert create_request.full_url.endswith("/repos/owner/repo/check-runs")
            assert create_request.get_header("Authorization") == "Bearer test-token"
            body = json.loads(create_request.data.decode("utf-8"))
            assert body["conclusion"] == "success"
            assert body["external_id"] == "ovk:owner/repo:abc123"


def test_emit_github_check_api_failure_returns_one(tmp_path: Path, monkeypatch) -> None:
    evidence = tmp_path / "ovk-evidence.json"
    _write_evidence(evidence)
    monkeypatch.setenv("GITHUB_TOKEN", "test-token")

    with patch(
        "sys.argv",
        [
            "emit_github_check.py",
            "--evidence",
            str(evidence),
            "--repo",
            "owner/repo",
            "--head-sha",
            "abc123",
        ],
    ):
        with patch("scripts.emit_github_check.emit_or_update_check_run", return_value=False):
            assert main() == 1


def test_emit_github_check_stale_sha_returns_one(tmp_path: Path, monkeypatch) -> None:
    evidence = tmp_path / "ovk-evidence.json"
    _write_evidence(evidence, head_sha="evidence-sha")
    monkeypatch.setenv("GITHUB_TOKEN", "test-token")
    with patch(
        "sys.argv",
        [
            "emit_github_check.py",
            "--evidence",
            str(evidence),
            "--repo",
            "owner/repo",
            "--head-sha",
            "other-sha",
        ],
    ):
        assert main() == 1


def test_post_check_run_returns_false_on_http_error() -> None:
    with patch("urllib.request.urlopen", side_effect=URLError("network down")):
        assert _post_check_run("https://api.github.com", "owner/repo", "token", {"name": "x"}) is False


def test_emit_or_update_patches_existing() -> None:
    payload = {
        "name": "Open Verification Kernel",
        "head_sha": "abc123",
        "external_id": "ovk:owner/repo:abc123",
        "status": "completed",
        "conclusion": "success",
        "output": {"title": "t", "summary": "s"},
    }

    def fake_request(url: str, *, token: str, method: str = "GET", payload: dict | None = None):
        _ = token, payload
        if method == "GET":
            return 200, {"check_runs": [{"id": 55, "external_id": "ovk:owner/repo:abc123"}]}
        assert method == "PATCH"
        assert url.endswith("/check-runs/55")
        return 200, {"id": 55}

    with patch("scripts.emit_github_check._request", side_effect=fake_request):
        assert emit_or_update_check_run("https://api.github.com", "owner/repo", "token", payload)
