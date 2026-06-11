"""CBMC adapter implementing the OVK external adapter contract."""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

from ovk.adapters.cbmc.deterministic import evaluate_cbmc_input
from ovk.adapters.cbmc.harness_compiler import compile_cbmc_harness, obligation_has_runnable_harness
from ovk.adapters.cbmc.optional_runner import run_cbmc_harness
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

    def _native_result(self, obligation_input: dict[str, Any]) -> dict[str, Any] | None:
        if not obligation_has_runnable_harness(obligation_input):
            return None
        if shutil.which(self.binary_name) is None:
            return None
        compiled = compile_cbmc_harness(obligation_input)
        harness_path = Path(str(compiled["harness_path"]))
        return run_cbmc_harness(
            harness_path=harness_path,
            entry_function=str(compiled.get("entry_function", "harness")),
            unwind=int(compiled["unwind"]) if compiled.get("unwind") is not None else None,
            failure_mode=str(compiled.get("failure_mode", "cbmc_assertion_failed")),
        )

    def run(self, obligation: ProofObligation) -> RawBackendResult:
        native = self._native_result(obligation.input)
        if native is not None and native.get("used_native_binary"):
            return RawBackendResult(
                backend=self.backend_name,
                status=str(native.get("status", "unknown")),
                counterexamples=list(native.get("counterexamples", [])),
                used_native_binary=True,
            )

        evaluator = self._deterministic_evaluator()
        status, counterexamples = evaluator(obligation.input)
        return RawBackendResult(
            backend=self.backend_name,
            status=status,
            counterexamples=counterexamples,
            used_native_binary=False,
        )

    def evaluate_evidence(
        self,
        data: dict[str, Any],
        *,
        repo: str,
        head_sha: str,
        base_sha: str | None = None,
    ):
        from ovk.adapters.cbmc.evidence import evaluate_cbmc_harness

        return evaluate_cbmc_harness(data, repo=repo, head_sha=head_sha, base_sha=base_sha)


ADAPTER = CbmcAdapter()
