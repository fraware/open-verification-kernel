"""Authorization lane wrapper around the validated authorization path."""

from __future__ import annotations

from ovk.adapters.lane._base import LaneEvaluatorAdapter
from ovk.adapters.z3.validated_path import evaluate_validated_authorization_path


class AuthorizationLaneAdapter(LaneEvaluatorAdapter):
    backend_id = "lane-authorization"
    adapter_id = "ovk-adapter-lane-authorization"
    adapter_version = "0.1.0"
    lane = "authorization"
    guarantee_type = "smt_refutation_search"
    backend_class = "smt_solver"
    supported_domains = ["authorization"]
    supported_property_kinds = ["access_control", "safety", "invariant"]
    input_languages = ["json"]
    uses_native_execution = True
    has_deterministic_fallback = True
    fallback_semantically_weaker = True
    requires_network = False
    reads_repository_files = False
    writes_generated_files = True
    processes_untrusted_input_safely = True
    supported_os = ["linux", "darwin", "windows"]
    supported_arch = ["x86_64", "aarch64"]
    assumptions = [
        "Route and role abstractions faithfully represent the change under review.",
        "Witness polarity encodes the intended authorization property.",
    ]
    limits = [
        "Native Z3 availability is optional; deterministic fallback is weaker.",
        "Does not reconstruct frameworks beyond the supplied route abstraction.",
    ]

    def __init__(self) -> None:
        super().__init__(evaluator=evaluate_validated_authorization_path)


ADAPTER = AuthorizationLaneAdapter()
