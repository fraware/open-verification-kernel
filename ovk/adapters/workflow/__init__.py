"""GitHub Actions workflow extraction."""

from ovk.adapters.workflow.yaml_extract import (
    workflow_path_to_ci_secrets_input,
    workflow_yaml_to_ci_secrets_input,
    workflow_yaml_to_self_protection_hints,
)

__all__ = [
    "workflow_yaml_to_ci_secrets_input",
    "workflow_path_to_ci_secrets_input",
    "workflow_yaml_to_self_protection_hints",
]
