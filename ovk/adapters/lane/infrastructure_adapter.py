"""Infrastructure lane wrapper around the existing exposure evaluator."""

from __future__ import annotations

from typing import Any

from ovk.adapters.infra.evidence import evaluate_infra_exposure
from ovk.adapters.lane._base import LaneEvaluatorAdapter
from ovk.core.models import VerificationEvidence


def _evaluate_infra(
    data: dict[str, Any],
    *,
    repo: str = "unknown/repo",
    head_sha: str = "unknown",
    base_sha: str | None = None,
) -> VerificationEvidence:
    return evaluate_infra_exposure(data, repo=repo, head_sha=head_sha, base_sha=base_sha)


class InfrastructureLaneAdapter(LaneEvaluatorAdapter):
    backend_id = "lane-infrastructure"
    adapter_id = "ovk-adapter-lane-infrastructure"
    adapter_version = "0.1.0"
    lane = "infrastructure"
    guarantee_type = "policy_evaluation"
    backend_class = "static_analyzer"
    supported_domains = ["infrastructure"]
    supported_property_kinds = ["forbidden_configuration", "safety", "data_boundary"]
    input_languages = ["json"]
    uses_native_execution = False
    has_deterministic_fallback = True
    fallback_semantically_weaker = False
    requires_network = False
    reads_repository_files = False
    writes_generated_files = True
    processes_untrusted_input_safely = True
    supported_os = ["linux", "darwin", "windows"]
    supported_arch = ["x86_64", "aarch64"]
    assumptions = [
        "Infrastructure abstractions are normalized before evaluation.",
        "Sensitivity labels in the input are authoritative for this check.",
    ]
    limits = [
        "Does not execute Terraform or kubectl; evaluates supplied graphs/plans only.",
        "Provider-specific reachability may be incomplete without plan materials.",
    ]

    def __init__(self) -> None:
        super().__init__(evaluator=_evaluate_infra)


ADAPTER = InfrastructureLaneAdapter()
