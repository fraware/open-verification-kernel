"""Tests for the seven-item adapter conformance matrix (OVK-PR4 / OVK-05)."""

from __future__ import annotations

from pathlib import Path

import pytest

from ovk.core.adapter_conformance import (
    ADVERTISED_ADAPTER_IDS,
    FORMAL_BACKEND_IDS,
    LANE_ADAPTER_IDS,
    apply_release_status_honesty,
    behavioral_conformance_failures,
    effective_release_status,
    evaluate_conformance_fixture,
    is_fully_conformant,
    structural_conformance_failures,
    validate_all_adapter_conformance,
)
from ovk.core.capabilities import CapabilityRegistry
from ovk.core.evidence_integrity import seal_evidence, verify_evidence_digest
from ovk.core.json_io import read_json_file
from scripts.validate_adapter_conformance import main as validate_main


ROOT = Path(__file__).resolve().parents[1]


def test_advertised_adapter_count() -> None:
    assert len(ADVERTISED_ADAPTER_IDS) == 15
    assert len(FORMAL_BACKEND_IDS) == 10
    assert len(LANE_ADAPTER_IDS) == 5


@pytest.mark.parametrize("adapter_id", ADVERTISED_ADAPTER_IDS)
def test_structural_conformance_complete(adapter_id: str) -> None:
    assert structural_conformance_failures(adapter_id, root=ROOT) == []


@pytest.mark.parametrize("adapter_id", ADVERTISED_ADAPTER_IDS)
def test_behavioral_conformance_with_integrity(adapter_id: str) -> None:
    failures = behavioral_conformance_failures(adapter_id, root=ROOT, seal=True)
    assert failures == [], failures


def test_validate_all_adapter_conformance() -> None:
    assert validate_all_adapter_conformance(root=ROOT, seal=True) == []


def test_validate_script_exits_zero(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("sys.argv", ["validate_adapter_conformance.py"])
    assert validate_main() == 0


def test_stable_auto_downgrade_when_not_conformant(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "ovk.core.adapter_conformance.is_fully_conformant",
        lambda *_args, **_kwargs: False,
    )
    manifest = {
        "checker_id": "opa",
        "release_status": "stable",
        "native_execution": True,
    }
    assert effective_release_status(manifest, root=ROOT, conformant=False) == "preview"
    adjusted = apply_release_status_honesty(manifest, root=ROOT, conformant=False)
    assert adjusted["release_status"] == "preview"
    assert adjusted.get("_release_status_auto_downgraded") is True


def test_no_capability_claims_stable_without_gate() -> None:
    registry = CapabilityRegistry.from_directory(ROOT / "adapters", validate=True)
    for manifest in registry.all():
        if manifest.get("release_status") == "stable":
            assert is_fully_conformant(str(manifest["checker_id"]), root=ROOT)


def test_opa_pass_fixture_seals() -> None:
    data = read_json_file(ROOT / "examples" / "backends" / "opa_pass.json")
    evidence = evaluate_conformance_fixture("opa", data)
    sealed = seal_evidence(evidence)
    assert verify_evidence_digest(sealed)


def test_kani_timeout_fixture_is_unknown() -> None:
    data = read_json_file(ROOT / "examples" / "backends" / "kani_timeout.json")
    evidence = evaluate_conformance_fixture("kani", data)
    assert evidence.backend_claims[0].status.value == "unknown"


def test_capability_pointer_present_for_formal_backends() -> None:
    for checker in FORMAL_BACKEND_IDS:
        dirname = "tla" if checker == "tla+" else checker
        payload = read_json_file(ROOT / "adapters" / dirname / "capability.json")
        assert payload.get("conformance", {}).get("suite") == "conformance/manifest.json"
