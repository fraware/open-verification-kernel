import json
from pathlib import Path

from jsonschema import Draft202012Validator


def load_json(path: str) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def schema_errors(data: dict) -> list:
    schema = load_json("schemas/infrastructure.input.schema.json")
    return list(Draft202012Validator(schema).iter_errors(data))


def test_infra_schema_accepts_public_sensitive_fixture() -> None:
    assert schema_errors(load_json("examples/infrastructure_exposure/input_public_sensitive_resource.json")) == []


def test_infra_schema_accepts_private_sensitive_fixture() -> None:
    assert schema_errors(load_json("examples/infrastructure_exposure/input_private_sensitive_resource.json")) == []


def test_infra_schema_rejects_missing_resources() -> None:
    assert schema_errors({"task": "missing resources"})


def test_infra_schema_rejects_empty_resources() -> None:
    assert schema_errors({"resources": []})


def test_infra_schema_rejects_invalid_resource_shape() -> None:
    assert schema_errors(
        {
            "resources": [
                {
                    "resource_id": "",
                    "resource_type": "",
                    "sensitivity": "secret",
                    "public_exposure": "yes",
                }
            ]
        }
    )
