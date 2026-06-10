import json
from pathlib import Path

from ovk.adapters.opa.infra_exposure import evaluate_infra_exposure_opa, write_infra_exposure_rego


def test_opa_infra_domain_pack_blocks_public_sensitive_resource() -> None:
    payload = json.loads(Path("examples/infrastructure_exposure/input_public_sensitive_resource.json").read_text(encoding="utf-8"))
    evidence = evaluate_infra_exposure_opa(payload, repo="r", head_sha="sha")
    assert evidence.backend_claims[0].status.value == "fail"
    assert evidence.counterexamples[0]["failure_mode"] == "sensitive_resource_publicly_exposed"


def test_opa_infra_domain_pack_allows_private_resource() -> None:
    payload = json.loads(Path("examples/infrastructure_exposure/input_private_sensitive_resource.json").read_text(encoding="utf-8"))
    evidence = evaluate_infra_exposure_opa(payload, repo="r", head_sha="sha")
    assert evidence.backend_claims[0].status.value == "pass"


def test_infra_rego_policy_is_materializable(tmp_path: Path) -> None:
    path = tmp_path / "infra_exposure.rego"
    write_infra_exposure_rego(path)
    assert "ovk.infra_exposure" in path.read_text(encoding="utf-8")
