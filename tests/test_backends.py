from pathlib import Path

import json

from ovk.adapters.cedar.evidence import evaluate_cedar_policy
from ovk.adapters.tla.evidence import evaluate_tla_state_machine
from ovk.core.capabilities import CapabilityRegistry


def test_cedar_backend_pass_and_fail() -> None:
    passed = evaluate_cedar_policy(
        json.loads(Path("examples/backends/cedar_pass.json").read_text(encoding="utf-8")), repo="r", head_sha="sha"
    )
    failed = evaluate_cedar_policy(
        json.loads(Path("examples/backends/cedar_fail.json").read_text(encoding="utf-8")), repo="r", head_sha="sha"
    )
    assert passed.backend_claims[0].status.value == "pass"
    assert failed.backend_claims[0].status.value == "fail"


def test_tla_backend_detects_skipped_state() -> None:
    evidence = evaluate_tla_state_machine(
        json.loads(Path("examples/backends/tla_fail.json").read_text(encoding="utf-8")),
        repo="r",
        head_sha="sha",
    )
    assert evidence.backend_claims[0].status.value == "fail"


def test_capability_registry_lists_new_backends() -> None:
    registry = CapabilityRegistry.from_directory(Path("adapters"))
    tools = {manifest.get("tool", {}).get("name") for manifest in registry.all()}
    for backend in ["cedar", "tla+", "kani", "dafny", "verus", "lean", "cbmc", "alloy"]:
        assert backend in tools
