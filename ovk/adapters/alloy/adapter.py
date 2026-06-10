"""Alloy adapter implementing the OVK external adapter contract."""

from __future__ import annotations

import json
from pathlib import Path

from ovk.adapters.alloy.deterministic import evaluate_alloy_input
from ovk.adapters.external.base_adapter import BaseExternalAdapter


class AlloyAdapter(BaseExternalAdapter):
    backend_name = "alloy"
    binary_name = "alloy"
    input_language = "alloy"

    def __init__(self) -> None:
        manifest_path = Path("adapters/alloy/capability.json")
        self.capability_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    def _deterministic_evaluator(self):
        return evaluate_alloy_input


ADAPTER = AlloyAdapter()
