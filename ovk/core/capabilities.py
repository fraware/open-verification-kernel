"""Capability manifest loading and validation."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class CapabilityRegistry:
    """Filesystem-backed registry for backend capability manifests."""

    def __init__(self, manifests: list[dict[str, Any]] | None = None) -> None:
        self._manifests = manifests or []

    @classmethod
    def from_directory(cls, path: Path) -> "CapabilityRegistry":
        manifests: list[dict[str, Any]] = []
        if not path.exists():
            return cls(manifests)
        for manifest_path in sorted(path.rglob("capability.json")):
            manifests.append(json.loads(manifest_path.read_text(encoding="utf-8")))
        return cls(manifests)

    def all(self) -> list[dict[str, Any]]:
        return list(self._manifests)

    def by_tool(self, tool_name: str) -> dict[str, Any] | None:
        for manifest in self._manifests:
            if manifest.get("tool", {}).get("name") == tool_name:
                return manifest
        return None

    def supporting_domain(self, domain: str) -> list[dict[str, Any]]:
        return [m for m in self._manifests if domain in m.get("supported_domains", [])]

    def supporting_property_kind(self, property_kind: str) -> list[dict[str, Any]]:
        return [m for m in self._manifests if property_kind in m.get("supported_property_kinds", [])]
