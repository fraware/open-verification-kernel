import json
from pathlib import Path

from scripts.collect_branch_metadata import main as collect_main


def test_collect_branch_metadata_without_env_writes_empty_payload(tmp_path: Path, monkeypatch) -> None:
    output = tmp_path / "checks.json"
    monkeypatch.delenv("GITHUB_REPOSITORY", raising=False)
    monkeypatch.delenv("GITHUB_BASE_REF", raising=False)
    monkeypatch.delenv("GITHUB_REF_NAME", raising=False)
    monkeypatch.setattr("sys.argv", ["collect_branch_metadata.py", "--output", str(output)])
    assert collect_main() == 0
    assert json.loads(output.read_text(encoding="utf-8")) == {}
