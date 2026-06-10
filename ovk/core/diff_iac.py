"""Extract infrastructure inputs from IaC files in unified diffs."""

from __future__ import annotations

from pathlib import PurePosixPath

from ovk.core.diff_parser import extract_post_images, is_unified_diff


IAC_SUFFIXES = {".tf", ".tf.json"}
IAC_PREFIXES = ("k8s/", "kubernetes/", "deploy/", "infra/")


def _is_iac_path(path: str) -> bool:
    normalized = path.replace("\\", "/").lower()
    suffix = PurePosixPath(normalized).suffix
    if suffix in IAC_SUFFIXES:
        return True
    return any(marker in normalized for marker in ("/k8s/", "/kubernetes/", "/deploy/", "deployment"))


def _parse_tf_hunk(content: str) -> dict | None:
    """Best-effort parse of Terraform-like resource blocks from diff post-image."""
    resources: list[dict] = []
    current: dict | None = None
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("resource "):
            if current:
                resources.append(current)
            parts = stripped.split('"')
            resource_type = parts[1] if len(parts) > 1 else "unknown"
            resource_name = parts[3] if len(parts) > 3 else "unknown"
            current = {
                "resource_type": resource_type,
                "resource_name": resource_name,
                "publicly_accessible": False,
                "sensitivity": "internal",
            }
        elif current is not None:
            if "publicly_accessible" in stripped and "true" in stripped.lower():
                current["publicly_accessible"] = True
            if "sensitivity" in stripped.lower() and "confidential" in stripped.lower():
                current["sensitivity"] = "confidential"
            if "acl" in stripped.lower() and "public" in stripped.lower():
                current["publicly_accessible"] = True
    if current:
        resources.append(current)
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
    public = "type: LoadBalancer" in content or "type: NodePort" in content
    name = "unknown"
    for line in content.splitlines():
        if line.strip().startswith("name:"):
            name = line.split(":", 1)[1].strip()
            break
    return {
        "resources": [
            {
                "resource_type": "kubernetes_service",
                "resource_name": name,
                "publicly_accessible": public,
                "sensitivity": "internal",
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
            input_format = "kubernetes"
        if parsed is None:
            continue
        inputs.append({"input_format": input_format, "data": parsed})
    return inputs
