"""Infrastructure intermediate representation."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

Eligibility = Literal["strict", "review"]
ResourceKind = Literal[
    "generic",
    "terraform",
    "kubernetes",
    "service",
    "ingress",
    "gateway",
    "network_policy",
    "rbac",
    "service_account",
    "secret_ref",
    "pod_security",
]


class ExposureEdge(BaseModel):
    """Directed edge in the exposure graph."""

    source: str
    target: str
    kind: str
    evidence: str | None = None


class ExposurePath(BaseModel):
    """Concrete public exposure path (node id sequence)."""

    nodes: list[str] = Field(default_factory=list)
    edges: list[ExposureEdge] = Field(default_factory=list)

    @property
    def is_concrete(self) -> bool:
        return len(self.nodes) >= 2 and all(self.nodes)


class InfraResourceIR(BaseModel):
    """One infrastructure resource in the IR."""

    resource_id: str
    resource_type: str
    kind: ResourceKind = "generic"
    sensitivity: str = "internal"
    public_exposure: bool = False
    exposure_paths: list[str] = Field(default_factory=list)
    attributes: dict[str, Any] = Field(default_factory=dict)
    support: Literal["supported", "partial", "unsupported"] = "supported"
    notes: list[str] = Field(default_factory=list)


class InfrastructureIR(BaseModel):
    """Canonical infrastructure IR."""

    schema_version: Literal["ovk.infrastructure.ir.v1"] = "ovk.infrastructure.ir.v1"
    source_kind: Literal["terraform_plan", "kubernetes", "graph", "mixed"] = "graph"
    resources: list[InfraResourceIR] = Field(default_factory=list)
    edges: list[ExposureEdge] = Field(default_factory=list)
    public_paths: list[ExposurePath] = Field(default_factory=list)
    unsupported_constructs: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    eligibility: Eligibility = "review"
    eligibility_reasons: list[str] = Field(default_factory=list)

    def to_lane_input(self) -> dict[str, Any]:
        return {
            "resources": [
                {
                    "resource_id": item.resource_id,
                    "resource_type": item.resource_type,
                    "sensitivity": item.sensitivity,
                    "public_exposure": item.public_exposure,
                    "exposure_paths": list(item.exposure_paths),
                }
                for item in sorted(self.resources, key=lambda row: row.resource_id)
            ],
            "edges": [edge.model_dump(mode="json") for edge in self.edges],
            "public_paths": [path.model_dump(mode="json") for path in self.public_paths],
            "eligibility": self.eligibility,
            "unsupported_constructs": list(self.unsupported_constructs),
            "warnings": list(self.warnings),
        }
