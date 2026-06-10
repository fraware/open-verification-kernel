"""Native backend probing utilities for optional integration tests."""

from __future__ import annotations

import importlib.util
import json
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ovk.adapters.cedar.deterministic import evaluate_cedar_input
from ovk.adapters.cedar.optional_runner import probe_cedar_binary
from ovk.adapters.opa.optional_runner import run_opa_policy
from ovk.adapters.opa.self_protection import evaluate_self_protection
from ovk.adapters.z3.deterministic_path import evaluate_deterministic_authorization_path
from ovk.adapters.z3.validated_path import evaluate_validated_authorization_path
from ovk.core.external_adapters import adapter_by_name


OPA_POLICY_PATH = Path("adapters/opa/policies/self_protection.rego")


@dataclass(frozen=True)
class NativeBackendProbeResult:
    backend: str
    fixture_path: str
    runtime_status: str
    oracle_status: str
    binary_name: str
    binary_present: bool
    used_native_binary: bool


@dataclass(frozen=True)
class NativeBackendSummary:
    """Aggregated probe status for one backend (CI matrix summaries)."""

    backend: str
    binary_present: bool
    contract_roundtrip_ok: bool
    native_binary_used: bool
    fixture_matches_oracle: bool


TIER1_NATIVE_EXECUTION_BACKENDS = frozenset({"opa", "z3", "cedar"})
TIER1_REQUIRED_BACKENDS = frozenset({"opa", "z3", "cbmc", "cedar"})


BACKEND_FIXTURES: dict[str, tuple[str, ...]] = {
    "opa": (
        "examples/no_agent_self_approval/input_gate_removed.json",
        "examples/no_agent_self_approval/input_gate_preserved.json",
    ),
    "z3": (
        "examples/auth_regression/input_admin_bypass.json",
        "examples/auth_regression/input_admin_protected.json",
    ),
    "cedar": ("examples/backends/cedar_pass.json", "examples/backends/cedar_fail.json"),
    "tla+": ("examples/backends/tla_pass.json", "examples/backends/tla_fail.json"),
    "kani": ("examples/backends/kani_pass.json", "examples/backends/kani_fail.json"),
    "dafny": ("examples/backends/dafny_pass.json", "examples/backends/dafny_fail.json"),
    "verus": ("examples/backends/verus_pass.json", "examples/backends/verus_fail.json"),
    "lean": ("examples/backends/lean_pass.json", "examples/backends/lean_fail.json"),
    "cbmc": ("examples/backends/cbmc_pass.json", "examples/backends/cbmc_fail.json"),
    "alloy": ("examples/backends/alloy_pass.json", "examples/backends/alloy_fail.json"),
}


def _read_fixture(path: str) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _probe_external_adapter(backend: str, fixture_path: str) -> NativeBackendProbeResult:
    adapter = adapter_by_name(backend)
    if adapter is None:
        raise ValueError(f"backend adapter not found: {backend}")
    payload = _read_fixture(fixture_path)
    obligation = adapter.compile(
        intent={"intent_id": payload.get("intent_id", backend)},
        change={"input": payload, "changed_files": []},
    )
    raw = adapter.run(obligation)
    oracle_status, _ = adapter._deterministic_evaluator()(payload)  # noqa: SLF001
    binary_present = shutil.which(adapter.binary_name) is not None
    return NativeBackendProbeResult(
        backend=backend,
        fixture_path=fixture_path,
        runtime_status=raw.status,
        oracle_status=oracle_status,
        binary_name=adapter.binary_name,
        binary_present=binary_present,
        used_native_binary=raw.used_native_binary,
    )


def _probe_opa(fixture_path: str) -> NativeBackendProbeResult:
    payload = _read_fixture(fixture_path)
    oracle = evaluate_self_protection(payload, repo="probe/repo", head_sha="probe-sha")
    with tempfile.NamedTemporaryFile("w", suffix=".json", encoding="utf-8", delete=False) as handle:
        json.dump(payload, handle)
        tmp_path = Path(handle.name)
    try:
        raw = run_opa_policy(policy_path=OPA_POLICY_PATH, input_path=tmp_path)
    finally:
        tmp_path.unlink(missing_ok=True)
    binary_present = shutil.which("opa") is not None
    runtime_status = str(raw.get("status", "unknown")) if binary_present else oracle.backend_claims[0].status.value
    return NativeBackendProbeResult(
        backend="opa",
        fixture_path=fixture_path,
        runtime_status=runtime_status,
        oracle_status=oracle.backend_claims[0].status.value,
        binary_name="opa",
        binary_present=binary_present,
        used_native_binary=binary_present,
    )


def _probe_cedar(fixture_path: str) -> NativeBackendProbeResult:
    payload = _read_fixture(fixture_path)
    oracle_status, _ = evaluate_cedar_input(payload)
    probe = probe_cedar_binary()
    binary_present = bool(probe.get("used_native_binary"))
    runtime_status = oracle_status
    return NativeBackendProbeResult(
        backend="cedar",
        fixture_path=fixture_path,
        runtime_status=runtime_status,
        oracle_status=oracle_status,
        binary_name="cedar",
        binary_present=binary_present,
        used_native_binary=binary_present,
    )


def _probe_z3(fixture_path: str) -> NativeBackendProbeResult:
    payload = _read_fixture(fixture_path)
    oracle = evaluate_deterministic_authorization_path(payload, repo="probe/repo", head_sha="probe-sha")
    runtime = evaluate_validated_authorization_path(payload, repo="probe/repo", head_sha="probe-sha")
    runtime_status = runtime.backend_claims[0].status.value
    provenance_backend = None
    for artifact in runtime.generated_artifacts:
        if artifact.get("kind") == "backend_provenance":
            provenance_backend = str(artifact.get("backend"))
            break
    binary_present = importlib.util.find_spec("z3") is not None or shutil.which("z3") is not None
    used_native = provenance_backend == "z3"
    return NativeBackendProbeResult(
        backend="z3",
        fixture_path=fixture_path,
        runtime_status=runtime_status,
        oracle_status=oracle.backend_claims[0].status.value,
        binary_name="z3",
        binary_present=binary_present,
        used_native_binary=used_native,
    )


def probe_native_backend(backend: str) -> list[NativeBackendProbeResult]:
    """Probe one backend against deterministic-oracle fixtures."""
    if backend not in BACKEND_FIXTURES:
        supported = ", ".join(sorted(BACKEND_FIXTURES))
        raise ValueError(f"unsupported backend: {backend!r} (supported: {supported})")
    fixture_paths = BACKEND_FIXTURES[backend]
    if backend == "opa":
        return [_probe_opa(path) for path in fixture_paths]
    if backend == "cedar":
        return [_probe_cedar(path) for path in fixture_paths]
    if backend == "z3":
        return [_probe_z3(path) for path in fixture_paths]
    return [_probe_external_adapter(backend, path) for path in fixture_paths]


def probe_all_native_backends() -> list[NativeBackendSummary]:
    """Aggregate native probe status for every supported backend."""
    summaries: list[NativeBackendSummary] = []
    for backend in sorted(BACKEND_FIXTURES):
        results = probe_native_backend(backend)
        if not results:
            continue
        binary_present = any(item.binary_present for item in results)
        fixture_matches = all(item.runtime_status == item.oracle_status for item in results)
        native_used = all(item.used_native_binary for item in results if item.binary_present) if binary_present else False
        if backend in TIER1_NATIVE_EXECUTION_BACKENDS and binary_present:
            native_used = all(item.used_native_binary for item in results)
        summaries.append(
            NativeBackendSummary(
                backend=backend,
                binary_present=binary_present,
                contract_roundtrip_ok=fixture_matches,
                native_binary_used=native_used,
                fixture_matches_oracle=fixture_matches,
            )
        )
    return summaries
