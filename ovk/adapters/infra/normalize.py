"""Unified infrastructure input normalization."""

from __future__ import annotations

from typing import Any, Literal

from ovk.adapters.infra.graph import graph_to_infra_input
from ovk.adapters.infra.k8s import k8s_resources_to_infra_input
from ovk.adapters.infra.tf_plan import terraform_plan_to_infra_input


InfraInputFormat = Literal["infra", "terraform", "kubernetes", "graph"]


SUPPORTED_INFRA_INPUT_FORMATS: tuple[InfraInputFormat, ...] = ("infra", "terraform", "kubernetes", "graph")


def normalize_infra_input(data: dict[str, Any], input_format: str = "infra") -> dict[str, Any]:
    """Normalize supported infrastructure inputs into the OVK infra abstraction.

    Supported formats:
    - `infra`: already normalized OVK infrastructure input;
    - `terraform`: Terraform-plan-style JSON subset;
    - `kubernetes`: Kubernetes Service-style JSON subset;
    - `graph`: graph-style nodes and edges abstraction.
    """
    normalized_format = input_format.strip().lower()
    if normalized_format == "infra":
        return data
    if normalized_format == "terraform":
        return terraform_plan_to_infra_input(data)
    if normalized_format == "kubernetes":
        return k8s_resources_to_infra_input(data)
    if normalized_format == "graph":
        return graph_to_infra_input(data)
    raise ValueError(f"unsupported infrastructure input format: {input_format}")
