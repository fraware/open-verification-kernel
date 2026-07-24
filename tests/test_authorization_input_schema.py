import json
from pathlib import Path

from jsonschema import Draft202012Validator


def load_json(path: str) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def validator() -> Draft202012Validator:
    return Draft202012Validator(load_json("schemas/authorization.input.schema.json"))


def test_authorization_schema_accepts_valid_bypass_fixture() -> None:
    errors = list(validator().iter_errors(load_json("examples/auth_regression/input_admin_bypass.json")))
    assert errors == []


def test_authorization_schema_accepts_valid_protected_fixture() -> None:
    errors = list(validator().iter_errors(load_json("examples/auth_regression/input_admin_protected.json")))
    assert errors == []


def test_authorization_schema_rejects_missing_routes_fixture() -> None:
    errors = list(validator().iter_errors(load_json("examples/auth_regression/input_malformed_missing_routes.json")))
    assert errors


def test_authorization_schema_rejects_bad_witness_fixture() -> None:
    errors = list(validator().iter_errors(load_json("examples/auth_regression/input_malformed_bad_witness.json")))
    assert errors
