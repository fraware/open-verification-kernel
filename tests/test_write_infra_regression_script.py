import json
from pathlib import Path

from scripts.write_infra_regression import main as write_infra_regression_main


def test_write_infra_regression_script_writes_artifact(tmp_path: Path, monkeypatch) -> None:
    bundle = tmp_path / "bundle.json"
    output = tmp_path / "test_infra.py"
    bundle.write_text(
        json.dumps(
            {
                "evidence": [
                    {
                        "generated_artifacts": [
                            {
                                "kind": "regression_unit_test",
                                "content": "def test_generated():\n    assert True\n",
                            }
                        ]
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr("sys.argv", ["write_infra_regression.py", str(bundle), "--output", str(output)])
    assert write_infra_regression_main() == 0
    assert "test_generated" in output.read_text(encoding="utf-8")


def test_write_infra_regression_script_writes_fallback(tmp_path: Path, monkeypatch) -> None:
    bundle = tmp_path / "bundle.json"
    output = tmp_path / "test_infra.py"
    bundle.write_text(json.dumps({"evidence": []}), encoding="utf-8")
    monkeypatch.setattr("sys.argv", ["write_infra_regression.py", str(bundle), "--output", str(output)])
    assert write_infra_regression_main() == 0
    assert "No infrastructure regression artifact" in output.read_text(encoding="utf-8")
