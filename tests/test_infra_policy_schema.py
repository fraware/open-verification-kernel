import json
from pathlib import Path

from jsonschema import Draft202012Validator


def errors(data: dict) -> list:
    schema = json.loads(Path("schemas/infrastructure.policy.schema.json").read_text(encoding="utf-8"))
    return list(Draft202012Validator(schema).iter_errors(data))


def test_policy_schema_accepts_valid_levels() -> None:
    assert errors({"blocked_public_sensitivities": ["internal", "confidential"]}) == []


def test_policy_schema_accepts_default_shape() -> None:
    assert errors({}) == []


def test_policy_schema_rejects_unknown_level() -> None:
    assert errors({"blocked_public_sensitivities": ["other"]})


def test_policy_schema_rejects_scalar_value() -> None:
    assert errors({"blocked_public_sensitivities": "confidential"})
