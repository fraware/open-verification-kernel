"""Deterministic artifact manifest helpers."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any


MANIFEST_SCHEMA_VERSION = "ovk.artifact_manifest.v1"


@dataclass(frozen=True)
class ArtifactEntry:
    """One file entry in an OVK artifact manifest."""

    path: str
    sha256: str
    size_bytes: int
    kind: str = "artifact"

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "kind": self.kind,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
        }


def sha256_file(path: Path) -> str:
    """Return the SHA-256 digest for a file."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def artifact_entry(path: Path, *, kind: str = "artifact", root: Path | None = None) -> ArtifactEntry:
    """Create a manifest entry for a file."""
    resolved_root = root.resolve() if root is not None else None
    resolved_path = path.resolve()
    display_path = str(resolved_path.relative_to(resolved_root)) if resolved_root else str(path)
    return ArtifactEntry(
        path=display_path,
        kind=kind,
        sha256=sha256_file(resolved_path),
        size_bytes=resolved_path.stat().st_size,
    )


def build_artifact_manifest(entries: list[ArtifactEntry]) -> dict[str, Any]:
    """Build a deterministic OVK artifact manifest."""
    sorted_entries = sorted(entries, key=lambda item: (item.kind, item.path))
    return {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "artifacts": [entry.to_dict() for entry in sorted_entries],
    }
