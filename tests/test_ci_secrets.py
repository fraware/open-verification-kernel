from ovk.adapters.ci_secrets.evidence import evaluate_ci_secrets_exposure
from ovk.core.bundle import make_bundle
from ovk.core.json_io import read_json_file
from pathlib import Path


def test_ci_secrets_blocks_exposed_fixture() -> None:
    data = read_json_file(Path("examples/ci_secrets/input_secrets_exposed.json"))
    bundle = make_bundle([evaluate_ci_secrets_exposure(data, repo="test/repo", head_sha="abc")])
    assert bundle.decision["merge_recommendation"] == "block"


def test_ci_secrets_allows_safe_fixture() -> None:
    data = read_json_file(Path("examples/ci_secrets/input_secrets_safe.json"))
    bundle = make_bundle([evaluate_ci_secrets_exposure(data, repo="test/repo", head_sha="abc")])
    assert bundle.decision["merge_recommendation"] == "allow"
