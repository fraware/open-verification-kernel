"""Typed mutation tests."""

from __future__ import annotations

import pytest

from ovk.assurance.errors import MutationError
from ovk.assurance.mutation import mutate_profile
from ovk.assurance.pcs_export import snapshot_to_verifier_profile
from ovk.assurance.pin import resolve_pcs_root
from tests.assurance.support.digest_adapter import DigestPredicateAdapter

PCS_AVAILABLE = resolve_pcs_root() is not None
requires_pcs = pytest.mark.skipif(
    not PCS_AVAILABLE,
    reason="PCS pin unavailable (set OVK_PCS_CORE_PATH or sibling ../pcs-core)",
)


@requires_pcs
def test_mutation_changes_digest_and_refuses_production_overwrite(tmp_path) -> None:
    adapter = DigestPredicateAdapter(expected_digest="sha256:" + ("aa" * 32))
    snapshot = adapter.snapshot_config({"timeout_ms": 1000, "threshold": 1})
    profile = snapshot_to_verifier_profile(snapshot)
    production = tmp_path / "production" / "profile.json"
    production.parent.mkdir(parents=True)
    production.write_text("{}", encoding="utf-8")

    mutated, manifest = mutate_profile(
        profile,
        mutation_class="alter_timeout",
        parameters={"timeout_ms": 9000},
        out_path=tmp_path / "mutated.json",
        production_profile_path=production,
        supported_dimensions=adapter.supported_mutation_dimensions(),
    )
    assert mutated["integrity"]["artifact_digest"] != profile["integrity"]["artifact_digest"]
    assert manifest["production_prohibition"] is True
    assert manifest["mutation_class"] == "alter_timeout"

    with pytest.raises(MutationError, match="production"):
        mutate_profile(
            profile,
            mutation_class="alter_timeout",
            parameters={"timeout_ms": 8000},
            out_path=production,
            production_profile_path=production,
            supported_dimensions=adapter.supported_mutation_dimensions(),
        )


@requires_pcs
def test_unsupported_mutation_fails() -> None:
    adapter = DigestPredicateAdapter(expected_digest="sha256:" + ("bb" * 32))
    profile = snapshot_to_verifier_profile(adapter.snapshot_config({"timeout_ms": 1000}))
    with pytest.raises(MutationError, match="not in adapter supported"):
        mutate_profile(
            profile,
            mutation_class="change_prompt",
            parameters={"prompt": "x"},
            supported_dimensions=adapter.supported_mutation_dimensions(),
        )
    with pytest.raises(MutationError, match="unsupported mutation class"):
        mutate_profile(
            profile,
            mutation_class="not_a_real_mutation",
            parameters={},
        )
