import json
from pathlib import Path

from jsonschema import Draft202012Validator


def test_valid_intent_fixture_validates() -> None:
    schema = json.loads(Path("schemas/verification.intent.schema.json").read_text(encoding="utf-8"))
    fixture = json.loads(Path("tests/fixtures/valid_intent_self_protection.json").read_text(encoding="utf-8"))
    errors = list(Draft202012Validator(schema).iter_errors(fixture))
    assert errors == []


def test_failing_evidence_fixture_validates() -> None:
    schema = json.loads(Path("schemas/verification.evidence.schema.json").read_text(encoding="utf-8"))
    fixture = json.loads(Path("examples/no_agent_self_approval/failing_evidence.json").read_text(encoding="utf-8"))
    errors = list(Draft202012Validator(schema).iter_errors(fixture))
    assert errors == []
