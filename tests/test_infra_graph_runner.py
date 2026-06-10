import json
from pathlib import Path

from scripts.run_infra_exposure import main as infra_main


def test_infra_runner_graph_format_blocks(tmp_path: Path, monkeypatch) -> None:
    graph = tmp_path / "graph.json"
    graph.write_text(
        json.dumps(
            {
                "nodes": [
                    {"id": "edge", "kind": "external", "external": True},
                    {"id": "store", "kind": "storage", "sensitivity": "restricted"},
                ],
                "edges": [{"from": "edge", "to": "store"}],
            }
        ),
        encoding="utf-8",
    )
    evidence = tmp_path / "evidence.json"
    monkeypatch.setattr(
        "sys.argv",
        [
            "run_infra_exposure.py",
            str(graph),
            "--input-format",
            "graph",
            "--evidence-output",
            str(evidence),
            "--advisory",
        ],
    )
    assert infra_main() == 0
    payload = json.loads(evidence.read_text(encoding="utf-8"))
    assert payload["decision"]["merge_recommendation"] == "block"
