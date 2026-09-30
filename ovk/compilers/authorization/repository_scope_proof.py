"""Machine-derived closed-world repository scope proofs.

Unlike a caller-supplied ClosedWorldScopeProof trust input, these proofs are
content-addressed from authenticated repository materials: revision, roots,
file manifest digests, analyzed paths, and import-resolution status.

A derived proof is invalidated when Python files are added/changed, source
roots change, or import-resolution semantics change.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from ovk.compilers.authorization.bypass_authority import ClosedWorldScopeProof
from ovk.core.bundle import content_digest


_IMPLEMENTATION_VERSION = "0.1.0"


@dataclass(frozen=True)
class DerivedClosedWorldScopeProof:
    """Content-addressed scope proof derived from repository materials."""

    repo: str
    revision: str
    source_roots: tuple[str, ...]
    accounted_paths: tuple[str, ...]
    file_manifest_digest: str
    analyzed_paths: tuple[str, ...]
    field_searched: str | None
    unsupported_dynamics: tuple[str, ...]
    import_resolution_status: str
    implementation_version: str = _IMPLEMENTATION_VERSION

    def as_closed_world_scope_proof(self) -> ClosedWorldScopeProof:
        return ClosedWorldScopeProof(
            accounted_paths=self.accounted_paths,
            source_roots=self.source_roots,
        )

    def digest(self) -> str:
        return content_digest(
            {
                "repo": self.repo,
                "revision": self.revision,
                "source_roots": list(self.source_roots),
                "accounted_paths": list(self.accounted_paths),
                "file_manifest_digest": self.file_manifest_digest,
                "analyzed_paths": list(self.analyzed_paths),
                "field_searched": self.field_searched,
                "unsupported_dynamics": list(self.unsupported_dynamics),
                "import_resolution_status": self.import_resolution_status,
                "implementation_version": self.implementation_version,
            }
        )


def _normalize(path: str) -> str:
    return path.replace("\\", "/")


def file_manifest_digest(files: Mapping[str, str]) -> str:
    """Content-address the path -> source digest map."""

    return content_digest(
        {
            _normalize(path): content_digest(source)
            for path, source in sorted(
                (_normalize(path), source) for path, source in files.items()
            )
        }
    )


def derive_closed_world_scope_proof(
    *,
    repo: str,
    revision: str,
    files: Mapping[str, str],
    source_roots: Sequence[str],
    analyzed_paths: Sequence[str] | None = None,
    field_searched: str | None = None,
    unsupported_dynamics: Sequence[str] = (),
    import_resolution_status: str = "unit_local_static_imports_v1",
) -> DerivedClosedWorldScopeProof:
    """Derive a content-addressed scope proof from repository materials.

    ``files`` must be the complete Python set claimed for the search scope.
    ``analyzed_paths`` defaults to all file paths and must be a subset.
    """

    normalized = {
        _normalize(path): source for path, source in files.items()
    }
    accounted = tuple(sorted(normalized))
    roots = tuple(
        sorted(
            {
                root.strip().replace("\\", "/")
                for root in source_roots
                if root.strip()
            }
        )
    )
    if not roots:
        raise ValueError("source_roots must be non-empty")
    analyzed = (
        tuple(sorted({_normalize(path) for path in analyzed_paths}))
        if analyzed_paths is not None
        else accounted
    )
    if any(path not in normalized for path in analyzed):
        raise ValueError("analyzed_paths must be a subset of files")
    return DerivedClosedWorldScopeProof(
        repo=repo,
        revision=revision,
        source_roots=roots,
        accounted_paths=accounted,
        file_manifest_digest=file_manifest_digest(normalized),
        analyzed_paths=analyzed,
        field_searched=field_searched,
        unsupported_dynamics=tuple(sorted(set(unsupported_dynamics))),
        import_resolution_status=import_resolution_status,
        implementation_version=_IMPLEMENTATION_VERSION,
    )


def scope_proof_invalidated_by_file_change(
    proof: DerivedClosedWorldScopeProof,
    *,
    files: Mapping[str, str],
) -> bool:
    """True when the current file set no longer matches the proof manifest."""

    return file_manifest_digest(files) != proof.file_manifest_digest


def scope_proof_invalidated_by_roots(
    proof: DerivedClosedWorldScopeProof,
    *,
    source_roots: Sequence[str],
) -> bool:
    """True when source-root configuration diverges from the proof."""

    roots = tuple(
        sorted(
            {
                root.strip().replace("\\", "/")
                for root in source_roots
                if root.strip()
            }
        )
    )
    return roots != proof.source_roots
