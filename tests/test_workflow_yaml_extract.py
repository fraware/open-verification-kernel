from pathlib import Path

from ovk.adapters.ci_secrets.evidence import evaluate_ci_secrets_exposure
from ovk.adapters.workflow.yaml_extract import workflow_path_to_ci_secrets_input
from ovk.core.bundle import make_bundle


def test_workflow_yaml_extract_blocks_secrets_on_pull_request() -> None:
    data = workflow_path_to_ci_secrets_input(Path("examples/ci_secrets/workflow_secrets_on_pr.yml"))
    assert "pull_request" in data["workflows"][0]["triggers"]
    bundle = make_bundle([evaluate_ci_secrets_exposure(data, repo="test/repo", head_sha="abc")])
    assert bundle.decision["merge_recommendation"] == "block"


def test_workflow_yaml_extract_allows_workflow_dispatch() -> None:
    data = workflow_path_to_ci_secrets_input(Path("examples/ci_secrets/workflow_safe_dispatch.yml"))
    bundle = make_bundle([evaluate_ci_secrets_exposure(data, repo="test/repo", head_sha="abc")])
    assert bundle.decision["merge_recommendation"] == "allow"
