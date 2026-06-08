import json
from pathlib import Path

from ovk.adapters.opa import evaluate_self_protection
from ovk.core.bundle import content_digest, make_bundle
from ovk.core.schema_validation import validate_file


def test_content_digest_is_stable_for_dict_order() -> None:
    left = {"b": 2, "a": 1}
    right = {"a": 1, "b": 2}
    assert content_digest(left) == content_digest(right)


def test_bundle_id_is_stable_for_same_evidence() -> None:
    data = json.loads(Path("examples/no_agent_self_approval/input_gate_removed.json").read_text())
    evidence = evaluate_self_protection(data, repo="example/repo", head_sha="abc")
    first = make_bundle([evidence])
    second = make_bundle([evidence])
    assert first.bundle_id == second.bundle_id


def test_schema_validation_helper_accepts_valid_intent() -> None:
    report = validate_file(
        Path("tests/fixtures/valid_intent_self_protection.json"),
        Path("schemas/verification.intent.schema.json"),
    )
    assert report.valid
    assert report.issues == []
