from pathlib import Path

from ovk.core.json_io import read_json_file, write_json_file


def test_write_json_file_uses_trailing_newline(tmp_path: Path) -> None:
    path = tmp_path / "payload.json"
    write_json_file(path, {"a": 1})
    assert path.read_text(encoding="utf-8").endswith("\n")


def test_read_json_file_round_trips(tmp_path: Path) -> None:
    path = tmp_path / "payload.json"
    write_json_file(path, {"a": [1, 2, 3]})
    assert read_json_file(path) == {"a": [1, 2, 3]}
