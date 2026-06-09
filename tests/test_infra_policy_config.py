import json
from pathlib import Path

import pytest

from ovk.adapters.infra.model import InfraResource
from ovk.adapters.infra.policy_config import load_policy, policy_from_data


def test_policy_from_data_uses_default_when_missing() -> None:
    policy = policy_from_data({})
    resource = InfraResource(
        resource_id="resource-a",
        resource_type="storage",
        sensitivity="confidential",
        public_exposure=True,
    )
    assert policy.blocks_public_exposure(resource)


def test_policy_from_data_can_add_internal() -> None:
    policy = policy_from_data({"blocked_public_sensitivities": ["internal", "confidential"]})
    resource = InfraResource(
        resource_id="resource-b",
        resource_type="service",
        sensitivity="internal",
        public_exposure=True,
    )
    assert policy.blocks_public_exposure(resource)


def test_policy_from_data_rejects_invalid_sensitivity() -> None:
    with pytest.raises(ValueError):
        policy_from_data({"blocked_public_sensitivities": ["secret"]})


def test_load_policy_reads_json_file(tmp_path: Path) -> None:
    path = tmp_path / "policy.json"
    path.write_text(json.dumps({"blocked_public_sensitivities": ["restricted"]}), encoding="utf-8")
    policy = load_policy(path)
    resource = InfraResource(
        resource_id="resource-c",
        resource_type="storage",
        sensitivity="restricted",
        public_exposure=True,
    )
    assert policy.blocks_public_exposure(resource)
