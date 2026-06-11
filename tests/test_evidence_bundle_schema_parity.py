from pathlib import Path

from ovk.adapters.infra.evidence import evaluate_infra_exposure
from ovk.core.bundle import make_bundle
from ovk.core.json_io import read_json_file
from ovk.core.output_validation import validate_against_schema, validate_evidence_bundle
from ovk.paths import schema_path


def test_evidence_bundle_matches_pydantic_and_json_schema() -> None:
    data = read_json_file(Path("examples/infrastructure_exposure/input_private_sensitive_resource.json"))
    bundle = make_bundle([evaluate_infra_exposure(data, repo="test/repo", head_sha="abc")])
    payload = bundle.model_dump(mode="json")

    pydantic_report = validate_evidence_bundle(payload)
    assert pydantic_report.valid is True

    schema = read_json_file(schema_path("verification.bundle.schema.json"))
    json_report = validate_against_schema(payload, schema)
    assert json_report.valid is True, [issue.message for issue in json_report.issues]
