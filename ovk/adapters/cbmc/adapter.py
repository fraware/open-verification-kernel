"""CBMC adapter implementing the OVK external adapter contract."""

from __future__ import annotations

import json
from pathlib import Path

from ovk.adapters.cbmc.deterministic import evaluate_cbmc_input
from ovk.adapters.external.base_adapter import BaseExternalAdapter


class CbmcAdapter(BaseExternalAdapter):
    backend_name = "cbmc"
    binary_name = "cbmc"
    input_language = "c"

    def __init__(self) -> None:
        manifest_path = Path("adapters/cbmc/capability.json")
        self.capability_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    def _deterministic_evaluator(self):
        return evaluate_cbmc_input


ADAPTER = CbmcAdapter()
