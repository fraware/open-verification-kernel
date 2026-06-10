"""Cedar adapter implementing the OVK external adapter contract."""

from __future__ import annotations

import json
from pathlib import Path

from ovk.adapters.cedar.deterministic import evaluate_cedar_input
from ovk.adapters.external.base_adapter import BaseExternalAdapter


class CedarAdapter(BaseExternalAdapter):
    """Cedar policy backend adapter."""

    backend_name = "cedar"
    binary_name = "cedar"
    input_language = "cedar"

    def __init__(self) -> None:
        manifest_path = Path("adapters/cedar/capability.json")
        self.capability_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    def _deterministic_evaluator(self):
        return evaluate_cedar_input


ADAPTER = CedarAdapter()
