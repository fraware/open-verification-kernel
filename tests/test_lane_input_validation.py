import pytest

from ovk.core.json_io import read_json_file
from ovk.core.multi_lane import evaluate_lane
from ovk.paths import resource_path


def test_ci_secrets_lane_rejects_invalid_input() -> None:
    with pytest.raises(ValueError, match="ci_secrets input failed schema validation"):
        evaluate_lane("ci_secrets", {"author_type": "ai_agent"}, repo="test/repo", head_sha="abc")


def test_deployment_lane_rejects_invalid_input() -> None:
    with pytest.raises(ValueError, match="deployment input failed schema validation"):
        evaluate_lane("deployment", {"states": ["draft"]}, repo="test/repo", head_sha="abc")


def test_ci_secrets_lane_accepts_valid_fixture() -> None:
    data = read_json_file(resource_path("examples", "ci_secrets", "input_secrets_safe.json"))
    evidence = evaluate_lane("ci_secrets", data, repo="test/repo", head_sha="abc")
    assert evidence.intent["intent_id"]


def test_deployment_lane_accepts_valid_fixture() -> None:
    data = read_json_file(resource_path("examples", "deployment_state", "input_valid_approval_path.json"))
    evidence = evaluate_lane("deployment", data, repo="test/repo", head_sha="abc")
    assert evidence.intent["intent_id"]


def test_self_protection_lane_rejects_invalid_input() -> None:
    with pytest.raises(ValueError, match="self_protection input failed schema validation"):
        evaluate_lane("self_protection", {"changed_files": "not-an-array"}, repo="test/repo", head_sha="abc")


def test_self_protection_lane_accepts_canonical_fixture() -> None:
    data = read_json_file(resource_path("examples", "no_agent_self_approval", "input_gate_preserved.json"))
    evidence = evaluate_lane("self_protection", data, repo="test/repo", head_sha="abc")
    assert evidence.intent["intent_id"]
