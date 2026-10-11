"""Reference predictor: CanonicalDecisionInput.v1 → sealed verdict space.

Semantics: see SEMANTICS.md. Not the unrecovered historical Go checker.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable, Mapping, MutableMapping

from jsonschema import Draft202012Validator

try:
    from .canonicalize import compute_canonical_digest, digests_match
except ImportError:  # pragma: no cover - direct file load in conformance tests
    from canonicalize import compute_canonical_digest, digests_match

VERDICT_SPACE = (
    "VALID",
    "INVALID",
    "REVALIDATION_REQUIRED",
    "UNRESOLVED",
)

IMPLEMENTATION_ID = "rtk.reference_implementation.v0"
PREDICTION_SCHEMA_VERSION = "rtk.sealed_prediction.v0"

_SCHEMA_DIR = Path(__file__).resolve().parent.parent / "schemas"
_PREDICTION_SCHEMA_PATH = Path(__file__).resolve().parent / "schemas" / "prediction.v0.schema.json"

_cdi_validator: Draft202012Validator | None = None
_prediction_validator: Draft202012Validator | None = None


def _load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise TypeError(f"expected object in {path}")
    return data


def _cdi_schema_validator() -> Draft202012Validator:
    global _cdi_validator
    if _cdi_validator is None:
        schema = _load_json(_SCHEMA_DIR / "CanonicalDecisionInput.v1.schema.json")
        _cdi_validator = Draft202012Validator(schema)
    return _cdi_validator


def _prediction_schema_validator() -> Draft202012Validator:
    global _prediction_validator
    if _prediction_validator is None:
        schema = _load_json(_PREDICTION_SCHEMA_PATH)
        _prediction_validator = Draft202012Validator(schema)
    return _prediction_validator


def _operational_failure(
    *,
    decision_input_id: str | None,
    failure_category: str,
    detail: str,
) -> dict[str, Any]:
    record = {
        "schema_version": PREDICTION_SCHEMA_VERSION,
        "implementation_id": IMPLEMENTATION_ID,
        "implementation_kind": "REFERENCE_NOT_HISTORICAL_GO",
        "decision_input_id": decision_input_id,
        "execution_status": "OPERATIONAL_FAILURE",
        "verdict": None,
        "failure_category": failure_category,
        "detail": detail,
        "impacted_paths": [],
        "predicted_repair_catalog_id": None,
        "rationale_codes": [failure_category],
    }
    _prediction_schema_validator().validate(record)
    return record


def _ok_prediction(
    *,
    decision_input_id: str,
    verdict: str,
    rationale_codes: list[str],
    impacted_paths: list[str],
    predicted_repair_catalog_id: str | None,
    detail: str,
) -> dict[str, Any]:
    if verdict not in VERDICT_SPACE:
        raise ValueError(f"verdict outside frozen space: {verdict}")
    record = {
        "schema_version": PREDICTION_SCHEMA_VERSION,
        "implementation_id": IMPLEMENTATION_ID,
        "implementation_kind": "REFERENCE_NOT_HISTORICAL_GO",
        "decision_input_id": decision_input_id,
        "execution_status": "OK",
        "verdict": verdict,
        "failure_category": None,
        "detail": detail,
        "impacted_paths": impacted_paths,
        "predicted_repair_catalog_id": predicted_repair_catalog_id,
        "rationale_codes": rationale_codes,
    }
    _prediction_schema_validator().validate(record)
    return record


def _repair_catalog_id(decision_input: Mapping[str, Any]) -> str | None:
    ref = decision_input.get("repair_catalog_ref")
    if not isinstance(ref, dict):
        return None
    catalog_id = ref.get("catalog_id")
    return catalog_id if isinstance(catalog_id, str) and catalog_id else None


def predict(decision_input: Mapping[str, Any]) -> dict[str, Any]:
    """Predict a sealed-verdict-shaped record from one CanonicalDecisionInput.v1."""

    if not isinstance(decision_input, Mapping):
        return _operational_failure(
            decision_input_id=None,
            failure_category="INPUT_TYPE_ERROR",
            detail="decision_input must be a JSON object",
        )

    decision_input_id = decision_input.get("decision_input_id")
    if not isinstance(decision_input_id, str):
        decision_input_id = None

    errors = sorted(_cdi_schema_validator().iter_errors(decision_input), key=lambda e: e.path)
    if errors:
        first = errors[0]
        path = "/".join(str(p) for p in first.path) or "<root>"
        return _operational_failure(
            decision_input_id=decision_input_id,
            failure_category="SCHEMA_VALIDATION_FAILURE",
            detail=f"{path}: {first.message}",
        )

    assert isinstance(decision_input_id, str)

    if not digests_match(decision_input):
        expected = compute_canonical_digest(decision_input)
        stored = decision_input.get("canonical_digest")
        return _operational_failure(
            decision_input_id=decision_input_id,
            failure_category="CANONICAL_DIGEST_MISMATCH",
            detail=f"stored={stored} recomputed={expected}",
        )

    evidence = decision_input["evidence_snapshot"]
    completeness = evidence["completeness"]
    footprint = decision_input["context_footprint"]
    elements = list(footprint.get("elements") or [])
    changed_paths = list(decision_input["transition"].get("changed_paths") or [])
    repair_id = _repair_catalog_id(decision_input)

    if completeness == "UNKNOWN":
        return _ok_prediction(
            decision_input_id=decision_input_id,
            verdict="UNRESOLVED",
            rationale_codes=["EVIDENCE_COMPLETENESS_UNKNOWN"],
            impacted_paths=[],
            predicted_repair_catalog_id=None,
            detail="Evidence completeness UNKNOWN; insufficient material for a defensible verdict.",
        )

    if completeness == "INCOMPLETE":
        return _ok_prediction(
            decision_input_id=decision_input_id,
            verdict="REVALIDATION_REQUIRED",
            rationale_codes=["EVIDENCE_SNAPSHOT_INCOMPLETE"],
            impacted_paths=[],
            predicted_repair_catalog_id=repair_id,
            detail="Incomplete evidence snapshot; applicability cannot be carried from existing evidence alone.",
        )

    artifact_refs = evidence.get("artifact_refs") or []
    artifact_paths = {str(ref["path"]) for ref in artifact_refs if isinstance(ref, dict) and "path" in ref}
    element_set = {str(path) for path in elements}
    missing_from_artifacts = sorted(element_set - artifact_paths)
    if missing_from_artifacts:
        return _ok_prediction(
            decision_input_id=decision_input_id,
            verdict="INVALID",
            rationale_codes=["FOOTPRINT_NOT_COVERED_BY_ARTIFACT_REFS"],
            impacted_paths=missing_from_artifacts,
            predicted_repair_catalog_id=None,
            detail="COMPLETE snapshot footprint elements are not covered by artifact_refs paths.",
        )

    changed_set = {str(path) for path in changed_paths}
    impacted = sorted(changed_set & element_set)
    if not impacted:
        return _ok_prediction(
            decision_input_id=decision_input_id,
            verdict="VALID",
            rationale_codes=["NO_FOOTPRINT_PATH_CHANGED"],
            impacted_paths=[],
            predicted_repair_catalog_id=None,
            detail="No claim-relevant footprint path changed across the transition.",
        )

    return _ok_prediction(
        decision_input_id=decision_input_id,
        verdict="REVALIDATION_REQUIRED",
        rationale_codes=["FOOTPRINT_PATH_CHANGED"],
        impacted_paths=impacted,
        predicted_repair_catalog_id=repair_id,
        detail="Claim-relevant footprint paths changed; revalidation required from existing evidence alone.",
    )


def predict_many(decision_inputs: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Map predict() over an iterable of decision inputs."""

    return [predict(item) for item in decision_inputs]


def attach_canonical_digest(decision_input: MutableMapping[str, Any]) -> dict[str, Any]:
    """Helper for synthetic fixtures: set canonical_digest from frozen rules."""

    prepared = dict(decision_input)
    prepared["canonical_digest"] = compute_canonical_digest(prepared)
    return prepared
