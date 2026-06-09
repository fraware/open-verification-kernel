import pytest

from ovk.adapters.infra.evidence import evaluate_infra_exposure
from ovk.adapters.infra.normalize import normalize_infra_input


def test_normalize_native_infra_returns_input() -> None:
    data = {
        "resources": [
            {
                "resource_id": "bucket",
                "resource_type": "object_storage_bucket",
                "sensitivity": "confidential",
                "public_exposure": False,
                "exposure_paths": [],
            }
        ]
    }
    assert normalize_infra_input(data, "infra") == data


def test_normalize_terraform_input_can_block() -> None:
    plan = {
        "resource_changes": [
            {
                "type": "aws_s3_bucket",
                "name": "exports",
                "change": {"after": {"tags": {"sensitivity": "restricted"}, "acl": "public-read"}},
            }
        ]
    }
    evidence = evaluate_infra_exposure(normalize_infra_input(plan, "terraform"), repo="example/repo", head_sha="abc")
    assert evidence.decision["merge_recommendation"] == "block"


def test_normalize_kubernetes_input_can_block() -> None:
    data = {
        "kind": "Service",
        "metadata": {"name": "api", "annotations": {"ovk.io/sensitivity": "restricted"}},
        "spec": {"type": "NodePort"},
    }
    evidence = evaluate_infra_exposure(normalize_infra_input(data, "kubernetes"), repo="example/repo", head_sha="abc")
    assert evidence.decision["merge_recommendation"] == "block"


def test_normalize_rejects_unknown_format() -> None:
    with pytest.raises(ValueError):
        normalize_infra_input({"resources": []}, "unknown")
