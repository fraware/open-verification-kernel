"""Self-protection lane wrapper around the existing OPA/deterministic evaluator."""

from __future__ import annotations

from ovk.adapters.lane._base import LaneEvaluatorAdapter
from ovk.adapters.opa import evaluate_self_protection


class SelfProtectionLaneAdapter(LaneEvaluatorAdapter):
    backend_id = "lane-self-protection"
    adapter_id = "ovk-adapter-lane-self-protection"
    adapter_version = "0.1.0"
    lane = "self_protection"
    guarantee_type = "policy_evaluation"
    backend_class = "policy_engine"
    supported_domains = ["self_protection", "ci_cd", "agent_authority"]
    supported_property_kinds = ["safety", "invariant", "forbidden_configuration"]
    input_languages = ["json"]
    uses_native_execution = False
    has_deterministic_fallback = True
    fallback_semantically_weaker = False
    requires_network = False
    reads_repository_files = False
    writes_generated_files = False
    processes_untrusted_input_safely = True
    supported_os = ["linux", "darwin", "windows"]
    supported_arch = ["x86_64", "aarch64"]
    assumptions = [
        "Trusted branch-protection metadata is supplied by the caller.",
        "Changed-file lists faithfully represent the pull request.",
    ]
    limits = [
        "Does not execute OPA unless a dedicated opa-native adapter is selected.",
        "Missing required metadata yields unknown, not pass.",
    ]

    def __init__(self) -> None:
        super().__init__(evaluator=evaluate_self_protection)


ADAPTER = SelfProtectionLaneAdapter()
