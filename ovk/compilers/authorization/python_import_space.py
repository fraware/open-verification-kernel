"""Bounded Python import-space theorem (#161).

Callee resolution and closed-world import accounting share this primitive so
they cannot diverge on module identity.

Proof sources for binding an absolute import ``a.b.c`` to a repository path:
1. Exact repo-root module path: ``a/b/c.py`` or ``a/b/c/__init__.py``
2. Trusted configured ``python_import_roots``: ``{root}/a/b/c.py`` (same for
   ``__init__.py``)
3. Packaging metadata OVK explicitly understands and binds to a revision
   (currently none — hook returns empty)
4. Relative imports first reduce to an absolute module name via the importer
   path, then use (1)–(3)

Unproved path-suffix matching (``*/a/b/c.py`` anywhere in the manifest) is
intentionally absent: without a root proof, ``from helpers import f`` with
only ``app/helpers.py`` is unresolved.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

# Product compile status string for revision-bound import-root semantics.
BOUNDED_IMPORT_RESOLUTION_STATUS = "authenticated_revision_python_manifest_v3"


def normalize_path(path: str) -> str:
    return path.replace("\\", "/")


def normalize_import_root(root: str) -> str:
    """Normalize a trusted import root; ``.`` / empty means repository root."""

    cleaned = root.replace("\\", "/").strip().strip("/")
    if cleaned in ("", "."):
        return ""
    if ".." in cleaned.split("/"):
        raise ValueError(f"import root must not contain '..': {root!r}")
    return cleaned


def normalize_import_roots(roots: Sequence[str] | None) -> tuple[str, ...]:
    """Deduplicate and sort trusted import roots (repo-root ``.`` omitted)."""

    if not roots:
        return ()
    normalized: set[str] = set()
    for root in roots:
        item = normalize_import_root(str(root))
        if item:
            normalized.add(item)
    return tuple(sorted(normalized))


def import_roots_from_understood_packaging(
    *,
    files: Mapping[str, str],
    revision: str | None = None,
) -> tuple[str, ...]:
    """Import roots proved by packaging metadata OVK understands for a revision.

    No packaging layout is currently bound into the theorem. Returns empty so
    callers must supply trusted ``python_import_roots`` or rely on exact
    repo-root / relative import grounding.
    """

    del files, revision
    return ()


def module_candidates_in_manifest(
    module: str,
    available_paths: set[str] | frozenset[str],
    *,
    import_roots: Sequence[str] = (),
) -> tuple[str, ...]:
    """Locate repository paths that could bind an absolute import.

    Shared by :mod:`python_callee_resolution` and bypass closed-world import
    accounting. Multiple candidates mean ambiguity; zero means external unless
    the caller separately proves a local miss (relative or local package hint).
    """

    if not module or not module.strip():
        return ()
    stem = module.replace(".", "/")
    wanted = (f"{stem}.py", f"{stem}/__init__.py")
    available = {normalize_path(path) for path in available_paths}
    found: set[str] = set()

    for suffix in wanted:
        if suffix in available:
            found.add(suffix)

    for root in normalize_import_roots(import_roots):
        for suffix in wanted:
            candidate = f"{root}/{suffix}"
            if candidate in available:
                found.add(candidate)

    return tuple(sorted(found))


def top_level_appears_local(top: str, available_paths: set[str] | frozenset[str]) -> bool:
    """True when ``top`` already names a path segment under the manifest.

    Used so ``from app.missing import ...`` cannot be classified external when
    ``app/...`` paths are present (Unknown > false PASS). This is a local-miss
    heuristic only — it does not establish import identity.
    """

    if not top or "." in top:
        return False
    for path in available_paths:
        norm = normalize_path(path)
        if norm == f"{top}.py" or norm.startswith(f"{top}/"):
            return True
        if f"/{top}/" in f"/{norm}/" or norm.endswith(f"/{top}.py"):
            return True
    return False
