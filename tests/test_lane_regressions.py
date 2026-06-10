from pathlib import Path

from ovk.adapters.ci_secrets.evidence import evaluate_ci_secrets_exposure
from ovk.adapters.deployment.evidence import evaluate_approval_state_machine
from ovk.core.json_io import read_json_file


def test_ci_secrets_regression_artifact_generated() -> None:
    data = read_json_file(Path("examples/ci_secrets/input_secrets_exposed.json"))
    evidence = evaluate_ci_secrets_exposure(data, repo="test/repo", head_sha="abc")
    assert evidence.generated_artifacts
    assert evidence.generated_artifacts[0]["kind"] == "regression_unit_test"
    assert "test_ci_secrets_regression_0" in evidence.generated_artifacts[0]["content"]


def test_deployment_regression_artifact_generated() -> None:
    data = read_json_file(Path("examples/deployment_state/input_skipped_approval.json"))
    evidence = evaluate_approval_state_machine(data, repo="test/repo", head_sha="abc")
    assert evidence.generated_artifacts
    assert evidence.generated_artifacts[0]["kind"] == "regression_unit_test"
    assert "test_deployment_state_regression_0" in evidence.generated_artifacts[0]["content"]
