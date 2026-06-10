"""Extract Cedar/IAM lane inputs from IaC diffs."""

from __future__ import annotations

import re

from ovk.core.diff_parser import extract_post_images, is_unified_diff

IAM_MARKERS = ("iam", "policy", "role", "aws_iam")


def _is_iam_path(path: str) -> bool:
    normalized = path.replace("\\", "/").lower()
    return any(marker in normalized for marker in IAM_MARKERS)


def _policies_from_tf(content: str) -> list[dict]:
    policies: list[dict] = []
    if "aws_iam" not in content and "policy" not in content.lower():
        return policies

    principal = "*"
    action = "unknown"
    effect = "allow"
    principal_match = re.search(r'Principal\s*=\s*"?(\*|[^"\s]+)"?', content, re.IGNORECASE)
    action_match = re.search(r'Action\s*=\s*"?([^"\n]+)"?', content, re.IGNORECASE)
    effect_match = re.search(r'Effect\s*=\s*"?([^"\n]+)"?', content, re.IGNORECASE)
    if principal_match:
        principal = principal_match.group(1)
    if action_match:
        action = action_match.group(1)
    if effect_match:
        effect = effect_match.group(1)

    policies.append({"principal": principal, "action": action, "effect": effect})
    return policies


def cedar_inputs_from_diff(diff_text: str) -> list[dict]:
    """Convert IAM policy changes in a unified diff to Cedar backend inputs."""
    if not is_unified_diff(diff_text):
        return []

    inputs: list[dict] = []
    for path, content in extract_post_images(diff_text).items():
        if not _is_iam_path(path) or not content.strip():
            continue
        policies = _policies_from_tf(content)
        if not policies:
            continue
        inputs.append(
            {
                "intent_id": "cedar-policy-check",
                "policies": policies,
                "source_path": path,
            }
        )
    return inputs
