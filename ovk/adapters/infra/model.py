"""Infrastructure exposure model."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal


Sensitivity = Literal["public", "internal", "confidential", "restricted"]


@dataclass(frozen=True)
class InfraResource:
    """A resource in the infrastructure exposure abstraction."""

    resource_id: str
    resource_type: str
    sensitivity: Sensitivity
    public_exposure: bool
    exposure_paths: list[str] = field(default_factory=list)


def load_resources(data: dict[str, Any]) -> list[InfraResource]:
    """Load infrastructure resources from a JSON-like object."""
    resources: list[InfraResource] = []
    for item in data.get("resources", []):
        resources.append(
            InfraResource(
                resource_id=str(item.get("resource_id", "")),
                resource_type=str(item.get("resource_type", "")),
                sensitivity=str(item.get("sensitivity", "public")),  # type: ignore[arg-type]
                public_exposure=bool(item.get("public_exposure", False)),
                exposure_paths=[str(path) for path in item.get("exposure_paths", [])],
            )
        )
    return resources


def is_sensitive(resource: InfraResource) -> bool:
    """Return whether a resource should not be publicly exposed."""
    return resource.sensitivity in {"confidential", "restricted"}
