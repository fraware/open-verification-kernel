"""Sensitivity classification helpers for infrastructure IR."""

from __future__ import annotations

from typing import Any

VALID_SENSITIVITY = frozenset({"public", "internal", "confidential", "restricted"})
SENSITIVE = frozenset({"confidential", "restricted"})


def normalize_sensitivity(value: Any, default: str = "internal") -> str:
    if isinstance(value, str) and value in VALID_SENSITIVITY:
        return value
    return default


def is_sensitive(sensitivity: str) -> bool:
    return sensitivity in SENSITIVE


def sensitivity_from_tags(tags: dict[str, Any] | None, attributes: dict[str, Any] | None = None) -> str:
    tags = tags or {}
    attributes = attributes or {}
    for key in ("sensitivity", "data_sensitivity", "classification", "data_classification", "ovk.io/sensitivity"):
        for source in (attributes, tags):
            value = source.get(key)
            if isinstance(value, str) and value in VALID_SENSITIVITY:
                return value
    return "internal"
