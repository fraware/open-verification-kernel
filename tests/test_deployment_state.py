from pathlib import Path

from ovk.adapters.deployment.evidence import evaluate_approval_state_machine
from ovk.core.bundle import make_bundle
from ovk.core.json_io import read_json_file


def test_deployment_state_blocks_skipped_approval() -> None:
    data = read_json_file(Path("examples/deployment_state/input_skipped_approval.json"))
    bundle = make_bundle([evaluate_approval_state_machine(data, repo="test/repo", head_sha="abc")])
    assert bundle.decision["merge_recommendation"] == "block"


def test_deployment_state_allows_valid_path() -> None:
    data = read_json_file(Path("examples/deployment_state/input_valid_approval_path.json"))
    bundle = make_bundle([evaluate_approval_state_machine(data, repo="test/repo", head_sha="abc")])
    assert bundle.decision["merge_recommendation"] == "allow"
