"""Shared AST index for Python authorization source profiles.

A compiler pass should parse each head source file once and share the resulting
AST across contract inference, compatibility projections, and route/effect
extraction.

This module is intentionally syntax-only. It does not assign semantic meaning or
cache across repository revisions.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field

from ovk.compilers.authorization.material_loader import AuthMaterials
from ovk.core.bundle import content_digest


@dataclass(frozen=True)
class ParsedPythonMaterials:
    """Parsed head-revision Python materials keyed by repository-relative path."""

    trees: dict[str, ast.Module] = field(default_factory=dict)
    syntax_errors: dict[str, str] = field(default_factory=dict)
    source_digests: dict[str, str] = field(default_factory=dict)
    parse_count: int = 0
    reused_count: int = 0


def parsed_index_matches_materials(
    parsed: ParsedPythonMaterials,
    materials: AuthMaterials,
) -> bool:
    """Return whether the index is bound to this exact head source set."""

    current = {
        path: content_digest(source)
        for path, source in sorted(materials.head_files.items())
    }
    return current == parsed.source_digests


def parse_head_python_materials(
    materials: AuthMaterials,
    *,
    reuse_from: ParsedPythonMaterials | None = None,
) -> ParsedPythonMaterials:
    """Parse each head material exactly once.

    Syntax failures are retained as explicit path -> message entries so semantic
    extractors can lower coverage without reparsing the same file.
    """

    trees: dict[str, ast.Module] = {}
    errors: dict[str, str] = {}
    digests: dict[str, str] = {}
    parse_count = 0
    reused_count = 0

    for path, source in sorted(materials.head_files.items()):
        digest = content_digest(source)
        digests[path] = digest

        if (
            reuse_from is not None
            and reuse_from.source_digests.get(path) == digest
        ):
            if path in reuse_from.trees:
                trees[path] = reuse_from.trees[path]
                reused_count += 1
                continue
            if path in reuse_from.syntax_errors:
                errors[path] = reuse_from.syntax_errors[path]
                reused_count += 1
                continue

        parse_count += 1
        try:
            trees[path] = ast.parse(source, filename=path)
        except SyntaxError as exc:
            errors[path] = exc.msg

    return ParsedPythonMaterials(
        trees=trees,
        syntax_errors=errors,
        source_digests=digests,
        parse_count=parse_count,
        reused_count=reused_count,
    )
