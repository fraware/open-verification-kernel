"""Load GitHub Actions workflow YAML into structured dicts."""

from __future__ import annotations

from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover - PyYAML is a project dependency
    yaml = None  # type: ignore[assignment]


def load_workflow_text(text: str, *, path: str = "workflow.yml") -> dict[str, Any]:
    if yaml is None:
        raise RuntimeError("PyYAML is required to load GitHub Actions workflows")
    data = yaml.safe_load(text) or {}
    if not isinstance(data, dict):
        raise ValueError(f"{path}: workflow root must be a mapping")
    data.setdefault("_ovk_path", path)
    return data


def load_workflow_file(path: Path) -> dict[str, Any]:
    return load_workflow_text(path.read_text(encoding="utf-8"), path=path.as_posix())


def load_workflow_dir(root: Path) -> list[dict[str, Any]]:
    workflows: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*.yml")) + sorted(root.rglob("*.yaml")):
        workflows.append(load_workflow_file(path))
    return workflows
