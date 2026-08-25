"""Canonical JSON digest vectors for ovk.canonical_json.v1."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ovk.core.bundle import CANONICAL_JSON_VERSION, content_digest
from ovk.core.evidence_verifier import VERIFIER_TCB_MODULES, VERIFIER_VERSION


def test_canonicalization_vectors() -> None:
    payload = json.loads(Path("tests/vectors/content_digest_v1.json").read_text(encoding="utf-8"))
    assert payload["canonicalization"] == CANONICAL_JSON_VERSION
    for vector in payload["vectors"]:
        left = content_digest(vector["left"])
        right = content_digest(vector["right"])
        if vector["equal"]:
            assert left == right, vector["name"]
        else:
            assert left != right, vector["name"]


def test_nonfinite_numbers_are_rejected() -> None:
    with pytest.raises(ValueError, match="non-finite"):
        content_digest({"value": float("nan")})
    with pytest.raises(ValueError, match="non-finite"):
        content_digest({"value": float("inf")})


def test_verifier_tcb_is_named_and_excludes_producer_orchestration() -> None:
    assert VERIFIER_VERSION == "ovk.verifier.v1"
    assert "ovk.core.evidence_verifier" in VERIFIER_TCB_MODULES
    joined = " ".join(VERIFIER_TCB_MODULES)
    assert "sprint1_runner" not in joined
    assert "lane_compiler" not in joined
    assert "kernel" not in joined
