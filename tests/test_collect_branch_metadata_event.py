import json
from pathlib import Path

from scripts.collect_branch_metadata import main as collect_main


def test_collect_branch_metadata_reads_repository_from_event(tmp_path: Path, monkeypatch) -> None:
    event = tmp_path / "event.json"
    output = tmp_path / "checks.json"
    event.write_text(
        json.dumps(
            {
                "repository": {"full_name": "org/repo"},
                "pull_request": {"base": {"ref": "main"}, "head": {"sha": "abc"}, "number": 1},
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.setattr(
        "sys.argv",
        ["collect_branch_metadata.py", "--event", str(event), "--output", str(output)],
    )
    assert collect_main() == 0
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload == {}
