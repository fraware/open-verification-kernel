"""TLA+ adapter implementing the OVK external adapter contract."""

from __future__ import annotations

import json
from pathlib import Path

from ovk.adapters.external.base_adapter import BaseExternalAdapter
from ovk.adapters.tla.deterministic import evaluate_tla_input


class TlaAdapter(BaseExternalAdapter):
    """TLA+ / TLC backend adapter."""

    backend_name = "tla+"
    binary_name = "tlc"
    input_language = "tla"

    def __init__(self) -> None:
        manifest_path = Path("adapters/tla/capability.json")
        self.capability_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    def _deterministic_evaluator(self):
        return evaluate_tla_input


ADAPTER = TlaAdapter()
