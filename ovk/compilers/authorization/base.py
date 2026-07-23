"""Shared helpers for source-grounded authorization compilers."""

from __future__ import annotations

import re
from typing import Protocol

from ovk.compilers.authorization.ir import AuthorizationIR
from ovk.compilers.authorization.material_loader import AuthMaterials

ADMIN_ROLE_TOKENS = (
    "admin",
    "is_admin",
    "require_admin",
    "role_admin",
    "roles=['admin']",
    'roles=["admin"]',
    "role == 'admin'",
    'role == "admin"',
    "AdminRequired",
    "requireAdmin",
    "ensureAdmin",
    "checkAdmin",
)


class AuthorizationCompiler(Protocol):
    """Protocol for framework authorization compilers."""

    framework: str

    def compile(self, materials: AuthMaterials) -> AuthorizationIR: ...


def looks_admin_protected(text: str) -> bool:
    lowered = text.lower()
    return any(token.lower() in lowered for token in ADMIN_ROLE_TOKENS)


def normalize_path(*parts: str) -> str:
    pieces: list[str] = []
    for part in parts:
        cleaned = part.strip()
        if not cleaned or cleaned == "/":
            continue
        pieces.append(cleaned.strip("/"))
    return "/" + "/".join(pieces) if pieces else "/"


def extract_string_literal(source: str, pattern: str) -> list[str]:
    return [match.group(1) for match in re.finditer(pattern, source)]


def line_span(source: str, match_start: int, match_end: int, path: str):
    from ovk.compilers.authorization.ir import SourceSpan

    start_line = source.count("\n", 0, match_start) + 1
    end_line = source.count("\n", 0, match_end) + 1
    return SourceSpan(path=path, start_line=start_line, end_line=end_line)
