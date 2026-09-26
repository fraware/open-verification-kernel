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


@dataclass(frozen=True)
class ParsedPythonMaterials:
    """Parsed head-revision Python materials keyed by repository-relative path."""

    trees: dict[str, ast.Module] = field(default_factory=dict)
    syntax_errors: dict[str, str] = field(default_factory=dict)
    parse_count: int = 0


def parse_head_python_materials(materials: AuthMaterials) -> ParsedPythonMaterials:
    """Parse each head material exactly once.

    Syntax failures are retained as explicit path -> message entries so semantic
    extractors can lower coverage without reparsing the same file.
    """

    trees: dict[str, ast.Module] = {}
    errors: dict[str, str] = {}
    parse_count = 0

    for path, source in sorted(materials.head_files.items()):
        parse_count += 1
        try:
            trees[path] = ast.parse(source, filename=path)
        except SyntaxError as exc:
            errors[path] = exc.msg

    return ParsedPythonMaterials(
        trees=trees,
        syntax_errors=errors,
        parse_count=parse_count,
    )
