"""Machine-derived closed-world repository scope proofs.

Unlike a caller-supplied ClosedWorldScopeProof trust input, these proofs are
content-addressed from authenticated repository materials: revision, roots,
file manifest digests, analyzed paths, and import-resolution status.

A derived proof is invalidated when Python files are added/changed, source
roots change, or import-resolution semantics change.

Product compile must derive proofs from the complete authenticated Python
manifest for a revision — never from PE ``source_paths``-filtered materials
alone. Durable evidence must retain ``DerivedClosedWorldScopeProof.digest()``,
not only the stripped ``ClosedWorldScopeProof`` path/root pair.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from ovk.compilers.authorization.bypass_authority import ClosedWorldScopeProof
from ovk.core.bundle import content_digest


_IMPLEMENTATION_VERSION = "0.4.0"
_CONVENTIONAL_PYTHON_SOURCE_ROOTS = ("backend", "src")


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
    python_import_roots: tuple[str, ...] = ()
    implementation_version: str = _IMPLEMENTATION_VERSION

    def as_closed_world_scope_proof(self) -> ClosedWorldScopeProof:
        return ClosedWorldScopeProof(
            accounted_paths=self.accounted_paths,
            source_roots=self.source_roots,
            python_import_roots=self.python_import_roots,
        )

    def digest(self) -> str:
        return content_digest(
            {
                "repo": self.repo,
                "revision": self.revision,
                "source_roots": list(self.source_roots),
                "python_import_roots": list(self.python_import_roots),
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


def derive_python_source_roots(paths: Sequence[str]) -> tuple[str, ...]:
    """Infer path-accounting roots from repository-relative paths.

    Conventional package roots such as ``backend/`` and ``src/`` remain useful
    for path scoping displays. Import identity (#161) uses trusted
    ``python_import_roots`` (or exact repo-root / relative grounding), not
    these path-accounting roots.
    Paths outside those conventions keep repository-root ``"."``. Empty input
    is refused.
    """

    normalized = {_normalize(path) for path in paths if path and path.strip()}
    if not normalized:
        raise ValueError("source_roots require at least one Python path")

    conventional: set[str] = set()
    for root in _CONVENTIONAL_PYTHON_SOURCE_ROOTS:
        prefix = root + "/"
        if any(path == root or path.startswith(prefix) for path in normalized):
            conventional.add(root)

    if not conventional:
        return (".",)

    outside = [
        path
        for path in normalized
        if not any(
            path == root or path.startswith(root + "/") for root in conventional
        )
    ]
    roots = set(conventional)
    if outside:
        roots.add(".")
    return tuple(sorted(roots))


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
    python_import_roots: Sequence[str] = (),
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
    from ovk.compilers.authorization.python_import_space import (
        normalize_import_roots,
    )

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
        python_import_roots=normalize_import_roots(python_import_roots),
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
