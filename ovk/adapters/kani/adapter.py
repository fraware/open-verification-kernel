"""Kani adapter implementing the OVK external adapter contract."""

from __future__ import annotations

import json

from ovk.adapters.external.base_adapter import BaseExternalAdapter
from ovk.adapters.kani.deterministic import evaluate_kani_input
from ovk.paths import resource_path


class KaniAdapter(BaseExternalAdapter):
    """Kani Rust model-checking adapter."""

    backend_name = "kani"
    binary_name = "kani"
    input_language = "rust"

    def __init__(self) -> None:
        manifest_path = resource_path("adapters", "kani", "capability.json")
        self.capability_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    def _deterministic_evaluator(self):
        return evaluate_kani_input


ADAPTER = KaniAdapter()
