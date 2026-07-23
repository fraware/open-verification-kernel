"""Function selection for CBMC harness generation."""

from __future__ import annotations

import re
from pathlib import Path

from ovk.compilers.cbmc.project import CbmcFunctionTarget

_FUNC = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\([^;]*\)\s*\{")


def select_functions_from_source(
    path: Path,
    *,
    name_substr: str | None = None,
    limit: int = 50,
) -> list[CbmcFunctionTarget]:
    text = path.read_text(encoding="utf-8")
    found: list[CbmcFunctionTarget] = []
    for match in _FUNC.finditer(text):
        name = match.group(1)
        if name in {"if", "for", "while", "switch"}:
            continue
        if name_substr and name_substr not in name:
            continue
        found.append(
            CbmcFunctionTarget(
                name=name,
                file=path.as_posix(),
                selected_reason=f"source scan match:{name_substr or '*'}",
            )
        )
        if len(found) >= limit:
            break
    return found
