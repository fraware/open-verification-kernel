"""Resolve OVK resource paths for editable installs and PyPI wheels."""

from __future__ import annotations

import sys
from functools import lru_cache
from pathlib import Path


@lru_cache(maxsize=1)
def ovk_data_root() -> Path:
    """Return the directory containing schemas, templates, and adapter manifests."""
    module_dir = Path(__file__).resolve().parent
    repo_root = module_dir.parent
    if (repo_root / "schemas").is_dir():
        return repo_root
    packaged = module_dir / "package_data"
    if packaged.is_dir():
        return packaged
    return repo_root


def resource_path(*parts: str) -> Path:
    """Return a path under the OVK data root (examples, benchmarks, scripts, etc.)."""
    return ovk_data_root().joinpath(*parts)


def ensure_repo_on_path() -> Path:
    """Ensure the OVK data root is importable for ``benchmarks`` and ``scripts`` packages."""
    root = ovk_data_root()
    path = str(root)
    if path not in sys.path:
        sys.path.insert(0, path)
    return root


def schema_path(name: str) -> Path:
    """Return the path to a JSON schema file by basename."""
    return ovk_data_root() / "schemas" / name
