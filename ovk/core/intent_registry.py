"""Verification intent template loading."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class IntentRegistry:
    """Load intent templates from the repository template directory."""

    def __init__(self, intents: dict[str, dict[str, Any]]) -> None:
        self._intents = intents

    @classmethod
    def from_directory(cls, path: Path) -> "IntentRegistry":
        intents: dict[str, dict[str, Any]] = {}
        if not path.exists():
            return cls(intents)
        for intent_path in sorted(path.rglob("*.intent.json")):
            data = json.loads(intent_path.read_text(encoding="utf-8"))
            intent_id = str(data.get("intent_id"))
            if intent_id:
                intents[intent_id] = data
        return cls(intents)

    def get(self, intent_id: str) -> dict[str, Any] | None:
        return self._intents.get(intent_id)

    def all(self) -> list[dict[str, Any]]:
        return list(self._intents.values())

    def ids(self) -> list[str]:
        return sorted(self._intents.keys())
