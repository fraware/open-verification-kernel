"""Template library helpers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


TEMPLATES_DIR = Path("templates")


def list_templates(template_dir: Path = TEMPLATES_DIR) -> list[dict[str, str]]:
    """List available verification intent templates."""
    items: list[dict[str, str]] = []
    for path in sorted(template_dir.rglob("*.intent.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        items.append(
            {
                "path": str(path),
                "intent_id": str(data.get("intent_id", path.stem)),
                "domain": str(data.get("domain", "unknown")),
            }
        )
    return items


def show_template(path: Path) -> dict[str, Any]:
    """Load one template JSON document."""
    return json.loads(path.read_text(encoding="utf-8"))


def apply_template(path: Path, destination: Path) -> Path:
    """Copy a template into `.verification/intents/`."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
    return destination
