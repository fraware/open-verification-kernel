"""Compile-commands.json database loading for CBMC."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def load_compile_database(path: Path) -> list[dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError("compile_commands.json must be a list")
    return [item for item in data if isinstance(item, dict)]


def files_in_database(entries: list[dict[str, Any]]) -> list[str]:
    files: list[str] = []
    for item in entries:
        file_path = item.get("file")
        if isinstance(file_path, str):
            files.append(file_path)
    return sorted(set(files))
