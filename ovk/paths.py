"""Resolve OVK resource paths for editable installs and PyPI wheels."""

from __future__ import annotations

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


def schema_path(name: str) -> Path:
    """Return the path to a JSON schema file by basename."""
    return ovk_data_root() / "schemas" / name
