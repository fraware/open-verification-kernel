"""Extract verification inputs from workflow changes in unified diffs."""

from __future__ import annotations

from pathlib import PurePosixPath

import yaml

from ovk.adapters.workflow.yaml_extract import workflow_yaml_to_ci_secrets_input
from ovk.core.diff_parser import extract_post_images, is_unified_diff


WORKFLOW_PREFIX = ".github/workflows/"


def _is_workflow_path(path: str) -> bool:
    normalized = path.replace("\\", "/")
    if not normalized.startswith(WORKFLOW_PREFIX):
        return False
    suffix = PurePosixPath(normalized).suffix.lower()
    return suffix in {".yml", ".yaml"}


def workflow_inputs_from_diff(
    diff_text: str,
    *,
    trust_context: str = "untrusted_fork_pr",
) -> list[dict]:
    """Convert changed workflow files in a unified diff to CI secrets lane inputs.

    Partial unified diffs often reconstruct incomplete YAML documents. Those
    images are skipped rather than aborting the whole check path.
    """
    if not is_unified_diff(diff_text):
        return []

    inputs: list[dict] = []
    for path, content in extract_post_images(diff_text).items():
        if not _is_workflow_path(path) or not content.strip():
            continue
        workflow_id = PurePosixPath(path).stem
        try:
            inputs.append(
                workflow_yaml_to_ci_secrets_input(
                    content,
                    workflow_id=workflow_id,
                    trust_context=trust_context,
                )
            )
        except (yaml.YAMLError, ValueError):
            continue
    return inputs
