import json
from pathlib import Path

from scripts.write_authorization_regression import main as write_regression_main


def test_write_authorization_regression_script(tmp_path: Path, monkeypatch) -> None:
    evidence_bundle = tmp_path / "bundle.json"
    output = tmp_path / "test_auth.py"
    evidence_bundle.write_text(
        json.dumps(
            {
                "evidence": [
                    {
                        "counterexamples": [
                            {
                                "route": "/admin/export",
                                "user_role": "user",
                            }
                        ]
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "sys.argv",
        ["write_authorization_regression.py", str(evidence_bundle), "--output", str(output)],
    )
    assert write_regression_main() == 0
    assert "authorization regression" in output.read_text(encoding="utf-8")
