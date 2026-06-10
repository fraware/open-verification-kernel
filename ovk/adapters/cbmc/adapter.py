"""CBMC adapter implementing the OVK external adapter contract."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from ovk.adapters.cbmc.deterministic import evaluate_cbmc_input
from ovk.adapters.contract import ProofObligation, RawBackendResult
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

    def run(self, obligation: ProofObligation) -> RawBackendResult:
        evaluator = self._deterministic_evaluator()
        status, counterexamples = evaluator(obligation.input)
        used_native = False
        if shutil.which(self.binary_name) is not None:
            probe = subprocess.run(
                [self.binary_name, "--version"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            used_native = probe.returncode == 0
        return RawBackendResult(
            backend=self.backend_name,
            status=status,
            counterexamples=counterexamples,
            used_native_binary=used_native,
        )


ADAPTER = CbmcAdapter()
