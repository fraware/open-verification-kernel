"""Release artifact layout helpers."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


LAYOUT_SCHEMA_VERSION = "ovk.release_layout.v1"


@dataclass(frozen=True)
class ReleaseArtifact:
    """One expected release artifact."""

    path: str
    kind: str
    required: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {"path": self.path, "kind": self.kind, "required": self.required}


DEFAULT_RELEASE_ARTIFACTS = [
    ReleaseArtifact("ovk-evidence.json", "evidence"),
    ReleaseArtifact("ovk-pr-comment.md", "markdown"),
    ReleaseArtifact("ovk-attestation.json", "attestation"),
    ReleaseArtifact("ovk-artifact-manifest.json", "artifact_manifest"),
    ReleaseArtifact("ovk-attestation-envelope.json", "attestation_envelope"),
]


def default_release_layout() -> dict[str, Any]:
    """Return the default OVK release artifact layout."""
    return {
        "schema_version": LAYOUT_SCHEMA_VERSION,
        "artifacts": [artifact.to_dict() for artifact in DEFAULT_RELEASE_ARTIFACTS],
    }


def missing_required_artifacts(root: Path, layout: dict[str, Any] | None = None) -> list[str]:
    """Return missing required artifact paths under a root directory."""
    active_layout = layout or default_release_layout()
    missing: list[str] = []
    for artifact in active_layout.get("artifacts", []):
        if not isinstance(artifact, dict):
            continue
        if artifact.get("required", True) and not (root / str(artifact.get("path", ""))).exists():
            missing.append(str(artifact.get("path", "")))
    return missing
