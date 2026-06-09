import json
from pathlib import Path

from ovk.adapters.infra.exposure import find_exposure_counterexamples
from ovk.adapters.infra.validation import validate_infra_input


def load_fixture(name: str) -> dict:
    return json.loads(Path(f"examples/infrastructure_exposure/{name}").read_text(encoding="utf-8"))


def test_public_sensitive_resource_is_counterexample() -> None:
    counterexamples = find_exposure_counterexamples(load_fixture("input_public_sensitive_resource.json"))
    assert len(counterexamples) == 1
    assert counterexamples[0]["failure_mode"] == "sensitive_resource_publicly_exposed"
    assert counterexamples[0]["resource_id"] == "bucket-customer-exports"


def test_private_sensitive_resource_has_no_counterexample() -> None:
    counterexamples = find_exposure_counterexamples(load_fixture("input_private_sensitive_resource.json"))
    assert counterexamples == []


def test_missing_resources_is_validation_error() -> None:
    issues = validate_infra_input({"task": "missing resources"})
    assert len(issues) == 1
    assert issues[0].path == "resources"


def test_invalid_infra_resource_fields_are_validation_errors() -> None:
    issues = validate_infra_input(
        {
            "resources": [
                {
                    "resource_id": "",
                    "resource_type": "",
                    "sensitivity": "secret",
                    "public_exposure": "yes",
                    "exposure_paths": "internet",
                }
            ]
        }
    )
    issue_paths = {issue.path for issue in issues}
    assert "resources[0].resource_id" in issue_paths
    assert "resources[0].resource_type" in issue_paths
    assert "resources[0].sensitivity" in issue_paths
    assert "resources[0].public_exposure" in issue_paths
    assert "resources[0].exposure_paths" in issue_paths
