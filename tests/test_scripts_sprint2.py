import json
from pathlib import Path

from scripts.normalize_required_checks import main as normalize_main
from scripts.post_pr_comment import main as post_comment_main


def test_normalize_required_checks_script(tmp_path: Path, monkeypatch) -> None:
    input_path = tmp_path / "branch_protection.json"
    output_path = tmp_path / "required_checks.json"
    input_path.write_text(
        json.dumps(
            {
                "after_branch_protection": {
                    "required_status_checks": {
                        "contexts": ["unit-tests", "ovk-verify"]
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "sys.argv",
        ["normalize_required_checks.py", str(input_path), "--output", str(output_path)],
    )
    assert normalize_main() == 0
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["after_required_checks"] == ["unit-tests", "ovk-verify"]


def test_post_pr_comment_no_event_exits_successfully(tmp_path: Path, monkeypatch) -> None:
    markdown = tmp_path / "comment.md"
    markdown.write_text("OVK report", encoding="utf-8")
    missing_event = tmp_path / "missing-event.json"
    monkeypatch.delenv("GITHUB_EVENT_PATH", raising=False)
    monkeypatch.setattr(
        "sys.argv",
        ["post_pr_comment.py", "--markdown", str(markdown), "--event", str(missing_event)],
    )
    assert post_comment_main() == 0
