"""Dafny adapter implementing the OVK external adapter contract."""

from __future__ import annotations

import json

from ovk.adapters.dafny.deterministic import evaluate_dafny_input
from ovk.adapters.external.base_adapter import BaseExternalAdapter
from ovk.paths import resource_path


class DafnyAdapter(BaseExternalAdapter):
    backend_name = "dafny"
    binary_name = "dafny"
    input_language = "dafny"

    def __init__(self) -> None:
        manifest_path = resource_path("adapters", "dafny", "capability.json")
        self.capability_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    def _deterministic_evaluator(self):
        return evaluate_dafny_input


ADAPTER = DafnyAdapter()
