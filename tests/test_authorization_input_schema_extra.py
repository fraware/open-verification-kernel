import json
from pathlib import Path

from jsonschema import Draft202012Validator


def schema_errors(data: dict) -> list:
    schema = json.loads(Path("schemas/authorization.input.schema.json").read_text(encoding="utf-8"))
    return list(Draft202012Validator(schema).iter_errors(data))


def test_authorization_schema_rejects_empty_routes() -> None:
    assert schema_errors({"routes": []})


def test_authorization_schema_rejects_missing_route_path() -> None:
    assert schema_errors(
        {
            "routes": [
                {
                    "admin_only_before": True,
                    "admin_only_after": True,
                    "reachable_after": [],
                }
            ]
        }
    )


def test_authorization_schema_rejects_missing_reachable_after() -> None:
    assert schema_errors(
        {
            "routes": [
                {
                    "path": "/admin/export",
                    "admin_only_before": True,
                    "admin_only_after": True,
                }
            ]
        }
    )


def test_authorization_schema_rejects_non_object_witness() -> None:
    assert schema_errors(
        {
            "routes": [
                {
                    "path": "/admin/export",
                    "admin_only_before": True,
                    "admin_only_after": True,
                    "reachable_after": ["bad-witness"],
                }
            ]
        }
    )
