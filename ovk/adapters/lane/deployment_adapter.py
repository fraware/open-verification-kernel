"""Deployment lane wrapper around the approval state-machine evaluator."""

from __future__ import annotations

from ovk.adapters.deployment.evidence import evaluate_approval_state_machine
from ovk.adapters.lane._base import LaneEvaluatorAdapter


class DeploymentLaneAdapter(LaneEvaluatorAdapter):
    backend_id = "lane-deployment"
    adapter_id = "ovk-adapter-lane-deployment"
    adapter_version = "0.1.0"
    lane = "deployment"
    guarantee_type = "state_machine_safety"
    backend_class = "model_checker"
    supported_domains = ["deployment"]
    supported_property_kinds = ["safety", "invariant", "forbidden_configuration"]
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
        "Deployment state transitions in the input are complete for the change.",
        "Required approval edges are encoded in the supplied state machine.",
    ]
    limits = [
        "Does not query live deployment providers in this wrapper.",
        "Missing transition metadata yields unknown or fail per evaluator rules.",
    ]

    def __init__(self) -> None:
        super().__init__(evaluator=evaluate_approval_state_machine)


ADAPTER = DeploymentLaneAdapter()
