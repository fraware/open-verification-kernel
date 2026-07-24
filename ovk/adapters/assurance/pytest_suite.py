"""Pytest / integration-test assurance verifier (VA-07)."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Mapping

from ovk.adapters.assurance._support import (
    AssuranceBackendMixin,
    accept_outcome,
    indeterminate_run_outcome,
    reject_outcome,
)
from ovk.assurance.pcs_hash import sha256_digest
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

GUARANTEE_CLASS = "runtime_observed"

_DECISION_SPACE = [
    "accept",
    "reject",
    "indeterminate_execution_error",
    "indeterminate_out_of_scope",
    "indeterminate_insufficient_evidence",
]


def _parse_junit(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {"tests": 0, "failures": 0, "errors": 0, "skipped": 0, "cases": []}
    tree = ET.parse(path)
    root = tree.getroot()
    suites = [root] if root.tag == "testsuite" else list(root.findall("testsuite"))
    tests = failures = errors = skipped = 0
    cases: list[dict[str, Any]] = []
    for suite in suites:
        tests += int(suite.attrib.get("tests") or 0)
        failures += int(suite.attrib.get("failures") or 0)
        errors += int(suite.attrib.get("errors") or 0)
        skipped += int(suite.attrib.get("skipped") or 0)
        for case in suite.findall("testcase"):
            status = "passed"
            if case.find("failure") is not None:
                status = "failed"
            elif case.find("error") is not None:
                status = "error"
            elif case.find("skipped") is not None:
                status = "skipped"
            cases.append(
                {
                    "classname": case.attrib.get("classname"),
                    "name": case.attrib.get("name"),
                    "status": status,
                }
            )
    return {
        "tests": tests,
        "failures": failures,
        "errors": errors,
        "skipped": skipped,
        "cases": cases,
    }


class PytestSuiteAdapter(AssuranceBackendMixin):
    """Real pytest runner; observational/runtime_observed guarantee only."""

    backend_id = "pytest-suite"
    adapter_id = "ovk-adapter-pytest-suite"
    adapter_version = "0.1.0"
    _guarantee_type = "runtime_observation"

    def __init__(self, *, timeout_ms: int = 60_000) -> None:
        self.timeout_ms = timeout_ms

    def supported_mutation_dimensions(self) -> list[str]:
        return ["alter_timeout", "reduce_test_subset", "change_threshold"]

    def manifest(self) -> BackendCapabilityManifest:
        return BackendCapabilityManifest(
            capability_id="pytest-suite-v1",
            tool=BackendToolIdentity(
                name=self.backend_id,
                adapter=self.adapter_id,
                adapter_version=self.adapter_version,
                version=self.adapter_version,
            ),
            backend_class="custom",
            guarantee=BackendGuaranteeDeclaration(
                type="runtime_observation",
                meaning_of_pass="Pinned pytest suite subset exited successfully (observational only).",
                meaning_of_fail="Pinned pytest suite reported failures or errors.",
                meaning_of_unknown="pytest missing, timed out, or suite path unsupported.",
            ),
            input_languages=["python", "json"],
            supported_domains=["assurance", "testing"],
            supported_property_kinds=["runtime_observation"],
            assumptions=["Suite path is pinned; results are observational, not formal."],
            limits=["Never upgrades to formally_checked; junit/raw capture only."],
            result_format="ovk.result.v1",
            timeout_behavior="unknown",
            assurance=AssuranceCapabilitySection(
                assurance_capable=True,
                verifier_identity=AssuranceVerifierIdentity(
                    verifier_id="ovk.assurance.pytest_suite",
                    implementation_name="PytestSuiteAdapter",
                    entry_point="ovk.adapters.assurance.pytest_suite.PytestSuiteAdapter",
                    pcs_profile_artifact_type="VerifierProfile.v1",
                ),
                decision_semantics=AssuranceDecisionSemantics(
                    decision_space=_DECISION_SPACE,  # type: ignore[arg-type]
                    guarantee_class=GUARANTEE_CLASS,  # type: ignore[arg-type]
                    supported_claim_ids=["claim.pytest.runtime_observed"],
                    out_of_scope_claim_ids=[
                        "claim.formal.full_correctness",
                        "claim.certificate_checked",
                    ],
                ),
                mechanism_class="test_suite",
                determinism="deterministic",
                evidence_channels=[
                    "stdout",
                    "stderr",
                    "raw_backend_result",
                    "normalized_result",
                    "test_report",
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
                        dependency_id="pytest",
                        kind="library",
                        identity="pytest",
                        optional=False,
                    )
                ],
                known_limits=["runtime/test observation only; not a formal verifier"],
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
        cfg.setdefault("threshold", cfg.get("threshold", 0))  # max allowed failures
        if isinstance(cfg.get("suite_path"), str):
            cfg["suite_path"] = cfg["suite_path"].replace("\\", "/")
        suite = {
            "suite_path": cfg.get("suite_path"),
            "nodeids": cfg.get("nodeids") or cfg.get("test_ids") or [],
            "pytest_args": cfg.get("pytest_args") or [],
        }
        return build_configuration_snapshot(
            backend_id=self.backend_id,
            adapter_id=self.adapter_id,
            adapter_version=self.adapter_version,
            config=cfg,
            environment=environment,
            test_suite=suite,
            threshold=cfg.get("threshold"),
            mechanism_class="test_suite",
            determinism="deterministic",
            allows_abstention=True,
            guarantee_class=GUARANTEE_CLASS,
            decision_space=_DECISION_SPACE,
            supported_claim_ids=["claim.pytest.runtime_observed"],
            out_of_scope_claim_ids=["claim.formal.full_correctness"],
            assumptions=["Observational pytest execution only."],
            known_blind_spots=["Passing tests do not imply formal correctness."],
            external_dependencies=[
                {
                    "dependency_id": "pytest",
                    "kind": "library",
                    "identity": "pytest",
                    "optional": False,
                }
            ],
            entry_point="ovk.adapters.assurance.pytest_suite.PytestSuiteAdapter",
            implementation_name="PytestSuiteAdapter",
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
        argv_base = [sys.executable, "-m", "pytest"]

        suite_path = input_data.get("suite_path") or cfg.get("suite_path")
        if not suite_path:
            return indeterminate_run_outcome(
                reason="unsupported_input",
                message="suite_path is required",
                guarantee_class=GUARANTEE_CLASS,
                command_argv=argv_base,
            )
        suite = Path(str(suite_path)).expanduser()
        if not suite.exists():
            return indeterminate_run_outcome(
                reason="unsupported_input",
                message=f"suite_path does not exist: {suite}",
                guarantee_class=GUARANTEE_CLASS,
                command_argv=argv_base,
            )

        try:
            import pytest as _pytest  # noqa: F401
        except ImportError as exc:
            raise FileNotFoundError("pytest is not installed") from exc

        nodeids = list(input_data.get("nodeids") or cfg.get("nodeids") or cfg.get("test_ids") or [])
        extra_args = list(input_data.get("pytest_args") or cfg.get("pytest_args") or [])
        threshold = int(cfg.get("threshold") or 0)
        timeout_ms = int(cfg.get("timeout_ms") or self.timeout_ms)

        suite_recorded = str(suite_path).replace("\\", "/")
        with tempfile.TemporaryDirectory(prefix="ovk-pytest-") as tmp:
            junit_path = Path(tmp) / "junit.xml"
            exec_command = [
                *argv_base,
                str(suite),
                f"--junitxml={junit_path}",
                "-q",
                *extra_args,
                *nodeids,
            ]
            # Portable argv for evidence packs (no host interpreter / temp paths).
            recorded_command = [
                "python",
                "-m",
                "pytest",
                suite_recorded,
                "--junitxml=junit.xml",
                "-q",
                *extra_args,
                *nodeids,
            ]
            try:
                completed = subprocess.run(
                    exec_command,
                    capture_output=True,
                    text=True,
                    timeout=max(timeout_ms / 1000.0, 0.1),
                    check=False,
                    env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
                )
            except subprocess.TimeoutExpired as exc:
                raise TimeoutError(f"pytest timed out after {timeout_ms}ms") from exc

            junit = _parse_junit(junit_path)
            # Stable raw body: exclude ephemeral temp paths and host-local absolutes.
            raw = {
                "command_stable": [
                    "python",
                    "-m",
                    "pytest",
                    suite_recorded,
                    "-q",
                    *extra_args,
                    *nodeids,
                ],
                "exit_code": completed.returncode,
                "junit_summary": {
                    "tests": junit.get("tests"),
                    "failures": junit.get("failures"),
                    "errors": junit.get("errors"),
                    "skipped": junit.get("skipped"),
                    "cases": [
                        {
                            "classname": c.get("classname"),
                            "name": c.get("name"),
                            "status": c.get("status"),
                        }
                        for c in (junit.get("cases") or [])
                    ],
                },
                "suite_digest": sha256_digest(
                    {
                        "suite_path": suite_recorded,
                        "nodeids": nodeids,
                        "pytest_args": extra_args,
                    }
                ),
            }
            # Redact host-local paths from captured streams before packing.
            stdout_text = (completed.stdout or "pass").replace(str(junit_path), "junit.xml")
            stderr_text = (completed.stderr or "").replace(str(junit_path), "junit.xml")
            failures = int(junit.get("failures") or 0) + int(junit.get("errors") or 0)
            skipped = int(junit.get("skipped") or 0)
            normalized_extra = {
                "test_report": raw["junit_summary"],
                "failures": failures,
                "skipped": skipped,
                "threshold": threshold,
                "skipped_visible": skipped > 0,
            }
            if completed.returncode not in {0, 1}:
                # pytest usage / collection errors
                return indeterminate_run_outcome(
                    reason="parser_failure" if completed.returncode == 2 else "other",
                    message=(stderr_text or stdout_text or "pytest failed").strip()[:500],
                    raw_result=raw,
                    guarantee_class=GUARANTEE_CLASS,
                    command_argv=recorded_command,
                    exit_code=completed.returncode,
                )
            if failures <= threshold and completed.returncode == 0:
                return accept_outcome(
                    raw_result=raw,
                    normalized_extra=normalized_extra,
                    stdout=stdout_text,
                    stderr=stderr_text,
                    guarantee_class=GUARANTEE_CLASS,
                    command_argv=recorded_command,
                    exit_code=completed.returncode,
                )
            if failures > threshold or completed.returncode != 0:
                return reject_outcome(
                    raw_result=raw,
                    normalized_extra={**normalized_extra, "counterexamples": junit.get("cases")},
                    stdout=stdout_text or "fail",
                    stderr=stderr_text,
                    guarantee_class=GUARANTEE_CLASS,
                    command_argv=recorded_command,
                    exit_code=completed.returncode,
                )
            return accept_outcome(
                raw_result=raw,
                normalized_extra=normalized_extra,
                stdout=stdout_text,
                stderr=stderr_text,
                guarantee_class=GUARANTEE_CLASS,
                command_argv=recorded_command,
                exit_code=completed.returncode,
            )
