import json
from pathlib import Path

import pytest

from ovk.adapters.cedar.adapter import ADAPTER
from tests.native_ci import skip_unless_native_backend


@pytest.mark.skipif(skip_unless_native_backend("cedar"), reason="Cedar integration runs in tier-1 workflow")
def test_cedar_adapter_pass_fixture_reports_probe_without_native_policy_claim() -> None:
    data = json.loads(Path("examples/backends/cedar_pass.json").read_text(encoding="utf-8"))
    evidence = ADAPTER.evaluate_evidence(data, repo="test/repo", head_sha="abc12345")
    assert evidence.backend_claims[0].status.value == "pass"
    assert evidence.backend_claims[0].guarantee_type == "deterministic_fallback"
    provenance = next(item for item in evidence.generated_artifacts if item.get("kind") == "backend_provenance")
    assert provenance["binary_present"] is True
    assert provenance["used_native_binary"] is False
    obligation = ADAPTER.compile(intent={"intent_id": data["intent_id"]}, change={"input": data, "changed_files": []})
    raw = ADAPTER.run(obligation)
    assert raw.used_native_binary is False


@pytest.mark.skipif(skip_unless_native_backend("cedar"), reason="Cedar integration runs in tier-1 workflow")
def test_cedar_adapter_fail_fixture_remains_deterministic_when_cli_installed() -> None:
    data = json.loads(Path("examples/backends/cedar_fail.json").read_text(encoding="utf-8"))
    evidence = ADAPTER.evaluate_evidence(data, repo="test/repo", head_sha="abc12345")
    assert evidence.backend_claims[0].status.value == "fail"
    assert evidence.decision.get("merge_recommendation") == "block"
    obligation = ADAPTER.compile(intent={"intent_id": data["intent_id"]}, change={"input": data, "changed_files": []})
    raw = ADAPTER.run(obligation)
    assert raw.used_native_binary is False
