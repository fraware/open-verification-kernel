from pathlib import Path

from ovk.core.backend_fixture import evaluate_backend_fixture
from ovk.core.json_io import read_json_file


def test_backend_fixture_cedar_pass_allows() -> None:
    data = read_json_file(Path("examples/backends/cedar_pass.json"))
    evidence = evaluate_backend_fixture(data, repo="test/repo", head_sha="test-head")
    assert evidence.decision["merge_recommendation"] == "allow"


def test_backend_fixture_via_multi_lane_backend_format() -> None:
    from ovk.core.multi_lane import evaluate_lane

    data = read_json_file(Path("examples/backends/kani_pass.json"))
    evidence = evaluate_lane("backend", data, input_format="backend", repo="test/repo", head_sha="test-head")
    assert evidence.decision["merge_recommendation"] == "allow"
