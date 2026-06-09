from ovk.adapters.infra.model import InfraResource
from ovk.adapters.infra.policy import DEFAULT_INFRA_EXPOSURE_POLICY, InfraExposurePolicy


def test_default_policy_blocks_confidential_public_resource() -> None:
    resource = InfraResource(
        resource_id="resource-a",
        resource_type="storage",
        sensitivity="confidential",
        public_exposure=True,
    )
    assert DEFAULT_INFRA_EXPOSURE_POLICY.blocks_public_exposure(resource)


def test_default_policy_allows_internal_public_resource() -> None:
    resource = InfraResource(
        resource_id="resource-b",
        resource_type="service",
        sensitivity="internal",
        public_exposure=True,
    )
    assert not DEFAULT_INFRA_EXPOSURE_POLICY.blocks_public_exposure(resource)


def test_custom_policy_can_block_internal_public_resource() -> None:
    policy = InfraExposurePolicy(blocked_public_sensitivities=frozenset({"internal", "confidential"}))
    resource = InfraResource(
        resource_id="resource-c",
        resource_type="service",
        sensitivity="internal",
        public_exposure=True,
    )
    assert policy.blocks_public_exposure(resource)
