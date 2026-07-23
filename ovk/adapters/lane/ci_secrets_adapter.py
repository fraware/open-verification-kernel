"""CI secrets lane wrapper around the existing exposure evaluator."""

from __future__ import annotations

from ovk.adapters.ci_secrets.evidence import evaluate_ci_secrets_exposure
from ovk.adapters.lane._base import LaneEvaluatorAdapter


class CiSecretsLaneAdapter(LaneEvaluatorAdapter):
    backend_id = "lane-ci-secrets"
    adapter_id = "ovk-adapter-lane-ci-secrets"
    adapter_version = "0.1.0"
    lane = "ci_secrets"
    guarantee_type = "workflow_secrets_boundary_check"
    backend_class = "static_analyzer"
    supported_domains = ["ci_cd", "ci_secrets"]
    supported_property_kinds = ["data_boundary", "forbidden_configuration", "safety"]
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
        "Workflow abstractions enumerate jobs, triggers, and secret references.",
        "Untrusted contexts are labeled in the input.",
    ]
    limits = [
        "Does not parse arbitrary YAML beyond the supplied abstraction.",
        "Reusable workflow expansion is limited to materials present in the input.",
    ]

    def __init__(self) -> None:
        super().__init__(evaluator=evaluate_ci_secrets_exposure)


ADAPTER = CiSecretsLaneAdapter()
