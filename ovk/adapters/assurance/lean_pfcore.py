"""Lean / PF-Core assurance verifier (VA-09) — real toolchain only."""

from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path
from shutil import which
from typing import Any, Mapping

from ovk.adapters.assurance._support import (
    AssuranceBackendMixin,
    accept_outcome,
    indeterminate_run_outcome,
    reject_outcome,
)
from ovk.assurance.pcs_hash import sha256_digest
from ovk.assurance.pin import resolve_pcs_root
from ovk.assurance.snapshot import ConfigurationSnapshot, build_configuration_snapshot
from ovk.core.execution_models import (
    AssuranceAbstention,
    AssuranceCapabilitySection,
    AssuranceDecisionSemantics,
    AssuranceExternalDependency,
    AssuranceFailureBehavior,
    AssuranceReplaySupport,
    AssuranceSnapshotSupport,
    AssuranceVerifierIdentity,
    BackendCapabilityManifest,
    BackendGuaranteeDeclaration,
    BackendToolIdentity,
)

GUARANTEE_CLASS = "formally_checked"

_DECISION_SPACE = [
    "accept",
    "reject",
    "indeterminate_execution_error",
    "indeterminate_out_of_scope",
    "indeterminate_insufficient_evidence",
]


def lean_available() -> bool:
    return which("lean") is not None


def resolve_lean_root(config: Mapping[str, Any] | None = None) -> Path | None:
    cfg = dict(config or {})
    explicit = cfg.get("lean_root") or os.environ.get("OVK_LEAN_ROOT")
    if explicit:
        path = Path(str(explicit)).expanduser().resolve()
        return path if path.is_dir() else None
    pcs = resolve_pcs_root()
    if pcs is not None:
        candidate = pcs / "lean"
        if candidate.is_dir():
            return candidate
    return None


class LeanPfCoreAssuranceAdapter(AssuranceBackendMixin):
    """Real Lean and/or PF-Core lake project invocation for assurance.

    Ordinary ``LeanAdapter`` deterministic_fallback remains non-assurance.
    Missing lean/lake => typed indeterminate.
    """

    backend_id = "lean-pfcore"
    adapter_id = "ovk-adapter-lean-pfcore"
    adapter_version = "0.1.0"
    _guarantee_type = "formal_proof"

    def __init__(self, *, timeout_ms: int = 120_000) -> None:
        self.timeout_ms = timeout_ms

    def supported_mutation_dimensions(self) -> list[str]:
        return ["alter_timeout"]

    def manifest(self) -> BackendCapabilityManifest:
        return BackendCapabilityManifest(
            capability_id="lean-pfcore-assurance-v1",
            tool=BackendToolIdentity(
                name=self.backend_id,
                adapter=self.adapter_id,
                adapter_version=self.adapter_version,
                version=self.adapter_version,
            ),
            backend_class="custom",
            guarantee=BackendGuaranteeDeclaration(
                type="formal_proof",
                meaning_of_pass="Lean/PF-Core toolchain accepted the pinned obligation.",
                meaning_of_fail="Lean/PF-Core rejected the obligation or reported errors.",
                meaning_of_unknown="Lean/lake missing, timed out, or unsupported input.",
            ),
            input_languages=["lean", "json"],
            supported_domains=["assurance", "formal"],
            supported_property_kinds=["formal_proof"],
            assumptions=["Lean toolchain and optional pcs-core/lean lake project are real."],
            limits=[
                "Ordinary lean deterministic_fallback adapter is NOT assurance_capable.",
                "Never invents passes without toolchain execution.",
            ],
            result_format="ovk.result.v1",
            timeout_behavior="unknown",
            assurance=AssuranceCapabilitySection(
                assurance_capable=True,
                verifier_identity=AssuranceVerifierIdentity(
                    verifier_id="ovk.assurance.lean_pfcore",
                    implementation_name="LeanPfCoreAssuranceAdapter",
                    entry_point="ovk.adapters.assurance.lean_pfcore.LeanPfCoreAssuranceAdapter",
                    pcs_profile_artifact_type="VerifierProfile.v1",
                ),
                decision_semantics=AssuranceDecisionSemantics(
                    decision_space=_DECISION_SPACE,  # type: ignore[arg-type]
                    guarantee_class=GUARANTEE_CLASS,  # type: ignore[arg-type]
                    supported_claim_ids=["claim.lean.pfcore"],
                    out_of_scope_claim_ids=["claim.full_global_noninterference"],
                ),
                mechanism_class="formal_proof",
                determinism="deterministic",
                evidence_channels=[
                    "stdout",
                    "stderr",
                    "raw_backend_result",
                    "normalized_result",
                    "proof",
                    "compiled_obligation",
                ],
                replay_support=AssuranceReplaySupport(
                    supported=True,
                    compares_raw_digest=True,
                    compares_normalized_digest=True,
                ),
                configuration_snapshot_support=AssuranceSnapshotSupport(
                    supported=True,
                    exports_pcs_profile=True,
                ),
                mutation_dimensions=self.supported_mutation_dimensions(),  # type: ignore[arg-type]
                abstention=AssuranceAbstention(allows_abstention=True),
                failure_behavior=AssuranceFailureBehavior(),
                external_dependencies=[
                    AssuranceExternalDependency(
                        dependency_id="lean",
                        kind="toolchain",
                        identity="lean",
                        optional=False,
                    )
                ],
                known_limits=["Requires lean; lake used when target is a lake package module."],
            ),
        )

    def snapshot_config(
        self,
        config: Mapping[str, Any] | None = None,
        *,
        environment: Mapping[str, str] | None = None,
    ) -> ConfigurationSnapshot:
        cfg = dict(config or {})
        cfg.setdefault("timeout_ms", self.timeout_ms)
        cfg.setdefault("mode", cfg.get("mode") or "lean_source")
        lean_root = resolve_lean_root(cfg)
        if lean_root is not None:
            cfg.setdefault("lean_root", str(lean_root))
        return build_configuration_snapshot(
            backend_id=self.backend_id,
            adapter_id=self.adapter_id,
            adapter_version=self.adapter_version,
            config=cfg,
            environment=environment,
            mechanism_class="formal_proof",
            determinism="deterministic",
            allows_abstention=True,
            guarantee_class=GUARANTEE_CLASS,
            decision_space=_DECISION_SPACE,
            supported_claim_ids=["claim.lean.pfcore"],
            out_of_scope_claim_ids=["claim.full_global_noninterference"],
            assumptions=["Real Lean/PF-Core execution only."],
            known_blind_spots=["Does not treat deterministic_fallback as formal proof."],
            external_dependencies=[
                {"dependency_id": "lean", "kind": "toolchain", "identity": "lean", "optional": False}
            ],
            entry_point="ovk.adapters.assurance.lean_pfcore.LeanPfCoreAssuranceAdapter",
            implementation_name="LeanPfCoreAssuranceAdapter",
            timeout_ms=int(cfg["timeout_ms"]),
            mutation_dimensions=self.supported_mutation_dimensions(),
        )

    def run_assurance(
        self,
        *,
        input_data: Mapping[str, Any],
        snapshot: ConfigurationSnapshot,
        config: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        cfg = dict(snapshot.config)
        if config:
            cfg.update(dict(config))
        if not lean_available():
            raise FileNotFoundError("lean binary not found")

        mode = str(input_data.get("mode") or cfg.get("mode") or "lean_source")
        timeout_ms = int(cfg.get("timeout_ms") or self.timeout_ms)
        lean_bin = which("lean")
        assert lean_bin is not None

        if mode == "lake_env":
            return self._run_lake_env(input_data=input_data, cfg=cfg, timeout_ms=timeout_ms)

        lean_source = input_data.get("lean_source")
        lean_file = input_data.get("lean_file")
        if isinstance(lean_file, str) and lean_file.strip():
            path = Path(lean_file).expanduser().resolve()
            if not path.is_file():
                return indeterminate_run_outcome(
                    reason="unsupported_input",
                    message=f"lean_file not found: {path}",
                    guarantee_class=GUARANTEE_CLASS,
                    command_argv=[lean_bin, str(path)],
                )
            source_text = path.read_text(encoding="utf-8")
            return self._run_lean_file(
                path=path,
                source_text=source_text,
                lean_bin=lean_bin,
                timeout_ms=timeout_ms,
                cleanup=None,
            )

        if not isinstance(lean_source, str) or not lean_source.strip():
            return indeterminate_run_outcome(
                reason="unsupported_input",
                message="lean_source or lean_file is required (no silent default smoke obligation)",
                guarantee_class=GUARANTEE_CLASS,
                command_argv=[lean_bin, "<lean_source>"],
            )

        with tempfile.TemporaryDirectory(prefix="ovk-lean-assurance-") as tmp:
            path = Path(tmp) / "Obligation.lean"
            path.write_text(lean_source, encoding="utf-8")
            return self._run_lean_file(
                path=path,
                source_text=lean_source,
                lean_bin=lean_bin,
                timeout_ms=timeout_ms,
                cleanup=tmp,
            )

    def _run_lean_file(
        self,
        *,
        path: Path,
        source_text: str,
        lean_bin: str,
        timeout_ms: int,
        cleanup: str | None,
    ) -> dict[str, Any]:
        command = [lean_bin, str(path)]
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=max(timeout_ms / 1000.0, 0.1),
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise TimeoutError(f"lean timed out after {timeout_ms}ms") from exc
        finally:
            # cleanup handled by TemporaryDirectory context when used
            _ = cleanup

        raw = {
            "command_tool": "lean",
            "exit_code": completed.returncode,
            "source_digest": sha256_digest(source_text),
            "mode": "lean_source",
            # stdout/stderr captured on the assurance outcome, not in raw digest body
        }
        if completed.returncode == 0:
            return accept_outcome(
                raw_result=raw,
                normalized_extra={"proof": {"tool": "lean", "source_digest": raw["source_digest"]}},
                stdout=completed.stdout or "pass",
                stderr=completed.stderr or "",
                guarantee_class=GUARANTEE_CLASS,
                command_argv=[lean_bin, "<obligation.lean>"],
                exit_code=0,
            )
        return reject_outcome(
            raw_result=raw,
            normalized_extra={
                "counterexamples": [{"stderr_digest": sha256_digest(completed.stderr or "")}],
                "proof": {"tool": "lean", "source_digest": raw["source_digest"], "failed": True},
            },
            stdout=completed.stdout or "fail",
            stderr=completed.stderr or "",
            guarantee_class=GUARANTEE_CLASS,
            command_argv=[lean_bin, "<obligation.lean>"],
            exit_code=completed.returncode,
        )

    def _run_lake_env(
        self,
        *,
        input_data: Mapping[str, Any],
        cfg: Mapping[str, Any],
        timeout_ms: int,
    ) -> dict[str, Any]:
        lake = which("lake")
        if lake is None:
            raise FileNotFoundError("lake binary not found")
        lean_root = resolve_lean_root(cfg)
        if lean_root is None:
            return indeterminate_run_outcome(
                reason="unsupported_input",
                message="lean_root / pcs-core lean project not found for lake_env mode",
                guarantee_class=GUARANTEE_CLASS,
                command_argv=["lake", "env", "lean"],
            )
        module = str(input_data.get("module") or cfg.get("module") or "PFCore.Basic")
        # `lake env lean --run` is not universal; use `lake env lean` with a tiny importer.
        with tempfile.TemporaryDirectory(prefix="ovk-lake-assurance-") as tmp:
            stub = Path(tmp) / "ImportCheck.lean"
            stub.write_text(f"import {module}\n#check True\n", encoding="utf-8")
            command = [lake, "env", "lean", str(stub)]
            try:
                completed = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    timeout=max(timeout_ms / 1000.0, 0.1),
                    check=False,
                    cwd=str(lean_root),
                )
            except subprocess.TimeoutExpired as exc:
                raise TimeoutError(f"lake env lean timed out after {timeout_ms}ms") from exc

            raw = {
                "command": command,
                "cwd": str(lean_root),
                "module": module,
                "exit_code": completed.returncode,
                "stdout": completed.stdout,
                "stderr": completed.stderr,
                "mode": "lake_env",
                "source_digest": sha256_digest({"module": module, "stub": stub.read_text(encoding="utf-8")}),
            }
            if completed.returncode == 0:
                return accept_outcome(
                    raw_result=raw,
                    normalized_extra={"proof": {"tool": "lake+lean", "module": module}},
                    stdout=completed.stdout or "pass",
                    stderr=completed.stderr or "",
                    guarantee_class=GUARANTEE_CLASS,
                    command_argv=command,
                )
            return reject_outcome(
                raw_result=raw,
                normalized_extra={
                    "counterexamples": [{"stderr": (completed.stderr or "")[:2000]}],
                    "proof": {"tool": "lake+lean", "module": module, "failed": True},
                },
                stdout=completed.stdout or "fail",
                stderr=completed.stderr or "",
                guarantee_class=GUARANTEE_CLASS,
                command_argv=command,
                exit_code=completed.returncode,
            )
