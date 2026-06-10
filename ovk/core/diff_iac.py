"""Extract infrastructure inputs from IaC files in unified diffs."""

from __future__ import annotations

from pathlib import PurePosixPath
import re

from ovk.core.diff_parser import extract_post_images, is_unified_diff


IAC_SUFFIXES = {".tf", ".tf.json"}
IAC_PREFIXES = ("k8s/", "kubernetes/", "deploy/", "infra/")


def _is_iac_path(path: str) -> bool:
    normalized = path.replace("\\", "/").lower()
    suffix = PurePosixPath(normalized).suffix
    if suffix in IAC_SUFFIXES:
        return True
    return any(marker in normalized for marker in ("/k8s/", "/kubernetes/", "/deploy/", "deployment")) or normalized.startswith(("k8s/", "kubernetes/"))


def _iam_policy_is_overly_permissive(resource_type: str, lines: list[str]) -> bool:
    """Detect wildcard principals or admin actions in IAM policy resources."""
    if "iam_policy" not in resource_type.lower():
        return False
    joined = "\n".join(lines).lower()
    if "iam_policy" not in resource_type.lower():
        return False
    if 'principal' in joined and "*" in joined and ("admin" in joined or "action" in joined):
        return True
    return 'action' in joined and 'resource' in joined and "*" in joined


def _parse_tf_hunk(content: str) -> dict | None:
    """Best-effort parse of Terraform-like resource blocks from diff post-image."""
    resources: list[dict] = []
    current: dict | None = None
    current_lines: list[str] = []
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("resource "):
            if current:
                if _iam_policy_is_overly_permissive(str(current.get("resource_type", "")), current_lines):
                    current["publicly_accessible"] = True
                    current["sensitivity"] = "confidential"
                resources.append(current)
            parts = stripped.split('"')
            resource_type = parts[1] if len(parts) > 1 else "unknown"
            resource_name = parts[3] if len(parts) > 3 else "unknown"
            current = {
                "resource_type": resource_type,
                "resource_name": resource_name,
                "publicly_accessible": False,
                "sensitivity": "confidential" if "iam_policy" in resource_type.lower() else "internal",
            }
            current_lines = [stripped]
        elif current is not None:
            current_lines.append(stripped)
            if "publicly_accessible" in stripped and "true" in stripped.lower():
                current["publicly_accessible"] = True
            if "sensitivity" in stripped.lower() and "confidential" in stripped.lower():
                current["sensitivity"] = "confidential"
            if re.search(r'acl\s*=\s*["\']public', stripped, re.IGNORECASE):
                current["publicly_accessible"] = True
            if "principal" in stripped.lower() and "*" in stripped:
                current["publicly_accessible"] = True
                current["sensitivity"] = "confidential"
            if "action" in stripped.lower() and "admin" in stripped.lower():
                current["sensitivity"] = "confidential"
    if current:
        if _iam_policy_is_overly_permissive(str(current.get("resource_type", "")), current_lines):
            current["publicly_accessible"] = True
            current["sensitivity"] = "confidential"
        resources.append(current)
    if not resources:
        orphan_public = False
        for line in content.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            if "publicly_accessible" in stripped and "true" in stripped.lower():
                orphan_public = True
            if re.search(r'acl\s*=\s*["\']public', stripped, re.IGNORECASE):
                orphan_public = True
        if orphan_public:
            resources.append(
                {
                    "resource_type": "partial_hunk",
                    "resource_name": "inferred_exposure",
                    "publicly_accessible": True,
                    "sensitivity": "internal",
                }
            )
    if not resources:
        return None
    normalized_resources: list[dict] = []
    for resource in resources:
        resource_type = str(resource.get("resource_type", "unknown"))
        resource_id = str(resource.get("resource_name", "unknown"))
        public_exposure = bool(resource.get("publicly_accessible"))
        sensitivity = str(resource.get("sensitivity", "internal"))
        if public_exposure and sensitivity == "internal":
            sensitivity = "confidential"
        normalized_type = "object_storage_bucket" if "s3_bucket" in resource_type else resource_type
        normalized_resources.append(
            {
                "resource_id": resource_id,
                "resource_type": normalized_type,
                "sensitivity": sensitivity,
                "public_exposure": public_exposure,
                "exposure_paths": ["public_bucket_policy"] if public_exposure else [],
            }
        )
    return {"resources": normalized_resources}


def _parse_k8s_hunk(content: str) -> dict | None:
    """Parse Kubernetes Service-like YAML from diff post-image."""
    if "kind:" not in content and "apiVersion:" not in content:
        return None
    service_type = "ClusterIP"
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.lower().startswith("type:"):
            service_type = stripped.split(":", 1)[1].strip()
            break
    public = service_type in {"LoadBalancer", "NodePort"}
    name = "unknown"
    for line in content.splitlines():
        if line.strip().startswith("name:"):
            name = line.split(":", 1)[1].strip()
            break
    return {
        "resources": [
            {
                "resource_id": name,
                "resource_type": "kubernetes_service",
                "sensitivity": "confidential" if public else "internal",
                "public_exposure": public,
                "exposure_paths": [f"service:{service_type}"] if public else [],
            }
        ]
    }


def infra_inputs_from_diff(diff_text: str) -> list[dict]:
    """Convert IaC file changes in a unified diff to infrastructure lane inputs."""
    if not is_unified_diff(diff_text):
        return []

    inputs: list[dict] = []
    for path, content in extract_post_images(diff_text).items():
        if not _is_iac_path(path) or not content.strip():
            continue
        normalized = path.replace("\\", "/").lower()
        if normalized.endswith((".tf", ".tf.json")):
            parsed = _parse_tf_hunk(content)
            input_format = "infra"
        else:
            parsed = _parse_k8s_hunk(content)
            input_format = "infra" if parsed is not None else "kubernetes"
        if parsed is None:
            continue
        inputs.append({"input_format": input_format, "data": parsed})
    return inputs
