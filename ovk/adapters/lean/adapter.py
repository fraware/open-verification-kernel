"""Lean adapter implementing the OVK external adapter contract."""

from __future__ import annotations

import json

from ovk.adapters.external.base_adapter import BaseExternalAdapter
from ovk.adapters.lean.deterministic import evaluate_lean_input
from ovk.paths import resource_path


class LeanAdapter(BaseExternalAdapter):
    backend_name = "lean"
    binary_name = "lean"
    input_language = "lean"

    def __init__(self) -> None:
        manifest_path = resource_path("adapters", "lean", "capability.json")
        self.capability_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    def _deterministic_evaluator(self):
        return evaluate_lean_input


ADAPTER = LeanAdapter()
