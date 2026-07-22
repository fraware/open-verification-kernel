"""Verus adapter implementing the OVK external adapter contract."""

from __future__ import annotations

import json

from ovk.adapters.external.base_adapter import BaseExternalAdapter
from ovk.adapters.verus.deterministic import evaluate_verus_input
from ovk.paths import resource_path


class VerusAdapter(BaseExternalAdapter):
    backend_name = "verus"
    binary_name = "verus"
    input_language = "verus"

    def __init__(self) -> None:
        manifest_path = resource_path("adapters", "verus", "capability.json")
        self.capability_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    def _deterministic_evaluator(self):
        return evaluate_verus_input


ADAPTER = VerusAdapter()
