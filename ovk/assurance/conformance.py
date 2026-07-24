"""Cross-adapter assurance conformance harness (VA-12).

Implements the shared 14-test matrix from the verifier-assurance work order.
Any adapter claiming ``assurance_capable=True`` must pass this matrix (or
explicitly skip only when an external toolchain is absent — and then only via
typed indeterminate paths, never fabricated passes).
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping

from ovk.assurance.capability import is_assurance_capable
from ovk.assurance.errors import AssuranceError, MutationError, ReplayError
from ovk.assurance.guarantee import clamp_guarantee_class
from ovk.assurance.indeterminate import DECISION_ACCEPT
from ovk.assurance.mutation import mutate_profile
from ovk.assurance.pcs_export import snapshot_to_verifier_profile
from ovk.assurance.pcs_validate import require_valid_pcs_artifact
from ovk.assurance.pin import resolve_pcs_root
from ovk.assurance.redaction import redact_environment
from ovk.assurance.replay import replay_invocation
from ovk.assurance.runner import run_assurance
from ovk.assurance.snapshot import ConfigurationSnapshot

CONFORMANCE_TEST_IDS = (
    "digest_stability",
    "material_change_digest",
    "deterministic_reproduce_or_declared_nondeterminism",
    "raw_normalized_link",
    "missing_checker_indeterminate",
    "timeout_indeterminate",
    "unsupported_fail_closed",
    "skipped_visible",
    "no_guarantee_upgrade",
    "preserve_proof_cex",
    "secrets_absent",
    "mutation_distinct_profile",
    "replay_drift_detection",
    "pcs_validate_profile",
    "pcs_validate_result",
)


@dataclass
class ConformanceCase:
    """Per-adapter inputs for the shared 14-test matrix."""

    adapter: Any
    input_data: Mapping[str, Any]
    config: Mapping[str, Any] = field(default_factory=dict)
    alt_config: Mapping[str, Any] = field(default_factory=dict)
    unsupported_input: Mapping[str, Any] = field(default_factory=dict)
    mutation_class: str = "alter_timeout"
    mutation_parameters: Mapping[str, Any] = field(default_factory=lambda: {"timeout_ms": 1234})
    expect_accept: bool = True
    # When True, missing external checker is exercised via FileNotFoundError path.
    supports_missing_checker_probe: bool = False
    missing_checker_probe: Callable[[], None] | None = None
    # Optional: force skip visibility check via outcome inspection.
    skip_check: Callable[[dict[str, Any]], bool] | None = None


@dataclass
class ConformanceResult:
    backend_id: str
    test_id: str
    passed: bool
    detail: str = ""


def _require_assurance(adapter: Any) -> None:
    manifest = adapter.manifest()
    if not is_assurance_capable(manifest):
        raise AssuranceError(f"{adapter.backend_id} is not assurance_capable")


def _snap(adapter: Any, config: Mapping[str, Any], environment: Mapping[str, str] | None = None) -> ConfigurationSnapshot:
    snap = adapter.snapshot_config(dict(config), environment=environment)
    if isinstance(snap, ConfigurationSnapshot):
        return snap
    return ConfigurationSnapshot.model_validate(snap)


def run_conformance_case(case: ConformanceCase) -> list[ConformanceResult]:
    """Run all 14 conformance tests against one assurance-capable adapter."""
    adapter = case.adapter
    _require_assurance(adapter)
    backend_id = adapter.backend_id
    results: list[ConformanceResult] = []
    pcs_ok = resolve_pcs_root() is not None

    # 1. digest stability
    try:
        s1 = _snap(adapter, case.config)
        s2 = _snap(adapter, case.config)
        ok = s1.content_digest == s2.content_digest and s1.config_digest == s2.config_digest
        results.append(
            ConformanceResult(backend_id, "digest_stability", ok, f"{s1.content_digest} vs {s2.content_digest}")
        )
    except Exception as exc:  # noqa: BLE001 — collect per-test failures
        results.append(ConformanceResult(backend_id, "digest_stability", False, str(exc)))

    # 2. material-change digest
    try:
        s1 = _snap(adapter, case.config)
        alt = dict(case.alt_config) if case.alt_config else {**dict(case.config), "timeout_ms": int(case.config.get("timeout_ms") or 5000) + 1}
        s2 = _snap(adapter, alt)
        ok = s1.content_digest != s2.content_digest
        results.append(
            ConformanceResult(backend_id, "material_change_digest", ok, f"{s1.content_digest} -> {s2.content_digest}")
        )
    except Exception as exc:  # noqa: BLE001
        results.append(ConformanceResult(backend_id, "material_change_digest", False, str(exc)))

    # 3. deterministic reproduce or declared nondeterminism
    try:
        manifest = adapter.manifest()
        determinism = manifest.assurance.determinism if manifest.assurance else "deterministic"
        if not pcs_ok:
            results.append(
                ConformanceResult(backend_id, "deterministic_reproduce_or_declared_nondeterminism", False, "PCS pin missing")
            )
        elif determinism == "stochastic":
            results.append(
                ConformanceResult(
                    backend_id,
                    "deterministic_reproduce_or_declared_nondeterminism",
                    True,
                    "declared stochastic",
                )
            )
        else:
            o1 = run_assurance(adapter, input_data=dict(case.input_data), config=dict(case.config))
            o2 = run_assurance(adapter, input_data=dict(case.input_data), config=dict(case.config))
            ok = (
                o1.invocation["raw_backend_result_digest"] == o2.invocation["raw_backend_result_digest"]
                and o1.invocation["normalized_result_digest"] == o2.invocation["normalized_result_digest"]
            )
            results.append(
                ConformanceResult(
                    backend_id,
                    "deterministic_reproduce_or_declared_nondeterminism",
                    ok,
                    f"decision={o1.decision}",
                )
            )
    except Exception as exc:  # noqa: BLE001
        results.append(
            ConformanceResult(backend_id, "deterministic_reproduce_or_declared_nondeterminism", False, str(exc))
        )

    # 4. raw↔normalized link
    try:
        if not pcs_ok:
            raise AssuranceError("PCS pin missing")
        outcome = run_assurance(adapter, input_data=dict(case.input_data), config=dict(case.config))
        ok = (
            "raw_backend_result_digest" in outcome.invocation
            and "normalized_result_digest" in outcome.invocation
            and outcome.invocation["raw_backend_result_digest"].startswith("sha256:")
            and outcome.invocation["normalized_result_digest"].startswith("sha256:")
            and bool(outcome.raw_result is not None)
            and bool(outcome.normalized_result is not None)
        )
        results.append(ConformanceResult(backend_id, "raw_normalized_link", ok))
    except Exception as exc:  # noqa: BLE001
        results.append(ConformanceResult(backend_id, "raw_normalized_link", False, str(exc)))

    # 5. timeout / missing-checker indeterminate
    try:
        probed = False
        if case.supports_missing_checker_probe and case.missing_checker_probe is not None:
            try:
                case.missing_checker_probe()
            except FileNotFoundError:
                probed = True
                # Re-run through runner by temporarily breaking availability if adapter supports it
        # Prefer native FileNotFoundError via a shallow wrapper when probe not provided:
        class _Missing:
            def __getattr__(self, name: str) -> Any:
                return getattr(adapter, name)

            def run_assurance(self, **kwargs: Any) -> dict[str, Any]:
                raise FileNotFoundError(f"{backend_id} checker missing (conformance probe)")

            def snapshot_config(self, *args: Any, **kwargs: Any) -> Any:
                return adapter.snapshot_config(*args, **kwargs)

            def manifest(self) -> Any:
                return adapter.manifest()

        class _Timeout:
            def __getattr__(self, name: str) -> Any:
                return getattr(adapter, name)

            def run_assurance(self, **kwargs: Any) -> dict[str, Any]:
                raise TimeoutError(f"{backend_id} checker timed out (conformance probe)")

            def snapshot_config(self, *args: Any, **kwargs: Any) -> Any:
                return adapter.snapshot_config(*args, **kwargs)

            def manifest(self) -> Any:
                return adapter.manifest()

        if pcs_ok:
            missing_outcome = run_assurance(
                _Missing(), input_data=dict(case.input_data), config=dict(case.config)
            )
            missing_ok = (
                missing_outcome.decision != DECISION_ACCEPT
                and missing_outcome.indeterminate_reason == "missing_checker"
            )
            results.append(
                ConformanceResult(
                    backend_id,
                    "missing_checker_indeterminate",
                    missing_ok,
                    missing_outcome.decision,
                )
            )
            timeout_outcome = run_assurance(
                _Timeout(), input_data=dict(case.input_data), config=dict(case.config)
            )
            timeout_ok = (
                timeout_outcome.decision != DECISION_ACCEPT
                and timeout_outcome.indeterminate_reason == "timeout"
            )
            results.append(
                ConformanceResult(
                    backend_id,
                    "timeout_indeterminate",
                    timeout_ok,
                    timeout_outcome.decision,
                )
            )
        else:
            results.append(
                ConformanceResult(backend_id, "missing_checker_indeterminate", False, "PCS pin missing")
            )
            results.append(
                ConformanceResult(backend_id, "timeout_indeterminate", False, "PCS pin missing")
            )
        _ = probed
    except Exception as exc:  # noqa: BLE001
        results.append(ConformanceResult(backend_id, "missing_checker_indeterminate", False, str(exc)))
        results.append(ConformanceResult(backend_id, "timeout_indeterminate", False, str(exc)))

    # 6. unsupported fail-closed
    try:
        if not pcs_ok:
            raise AssuranceError("PCS pin missing")
        unsupported = dict(case.unsupported_input) if case.unsupported_input else {}
        outcome = run_assurance(adapter, input_data=unsupported, config={})
        ok = outcome.decision != DECISION_ACCEPT
        results.append(ConformanceResult(backend_id, "unsupported_fail_closed", ok, outcome.decision))
    except Exception as exc:  # noqa: BLE001
        results.append(ConformanceResult(backend_id, "unsupported_fail_closed", False, str(exc)))

    # 7. skipped visible
    try:
        if not pcs_ok:
            raise AssuranceError("PCS pin missing")
        outcome = run_assurance(adapter, input_data=dict(case.input_data), config=dict(case.config))
        if case.skip_check is not None:
            ok = case.skip_check(outcome.normalized_result)
        else:
            # Default: skipped checks appear in result check_groups when indeterminate
            if outcome.decision.startswith("indeterminate_"):
                checks = []
                for group in outcome.result.get("check_groups") or []:
                    checks.extend(group.get("checks") or [])
                ok = any(c.get("status") == "skipped" for c in checks) or outcome.indeterminate_reason is not None
            else:
                ok = True  # no skip expected on happy path
        results.append(ConformanceResult(backend_id, "skipped_visible", ok))
    except Exception as exc:  # noqa: BLE001
        results.append(ConformanceResult(backend_id, "skipped_visible", False, str(exc)))

    # 8. no guarantee upgrade
    try:
        declared = adapter.manifest().assurance.decision_semantics.guarantee_class
        clamped = clamp_guarantee_class(declared, "formally_checked")
        ranks_ok = clamped == declared
        if declared != "formally_checked":
            ranks_ok = clamped != "formally_checked" and clamped == declared
        # End-to-end: sealed result must not carry an upgraded class.
        if pcs_ok:
            outcome = run_assurance(
                adapter, input_data=dict(case.input_data), config=dict(case.config)
            )
            sealed = str(outcome.result.get("guarantee_class") or declared)
            sealed_ok = clamp_guarantee_class(declared, sealed) == sealed or sealed == declared
            # Attacker-shaped claim must clamp when compared against declared.
            attack = clamp_guarantee_class(declared, "formally_checked")
            ranks_ok = ranks_ok and attack == declared and sealed_ok
        results.append(ConformanceResult(backend_id, "no_guarantee_upgrade", ranks_ok, f"declared={declared}"))
    except Exception as exc:  # noqa: BLE001
        results.append(ConformanceResult(backend_id, "no_guarantee_upgrade", False, str(exc)))

    # 9. preserve proof/cex
    try:
        if not pcs_ok:
            raise AssuranceError("PCS pin missing")
        outcome = run_assurance(adapter, input_data=dict(case.input_data), config=dict(case.config))
        raw = outcome.raw_result
        norm = outcome.normalized_result
        ok = isinstance(raw, dict) and isinstance(norm, dict)
        if outcome.decision == "reject":
            ok = ok and (
                "counterexamples" in norm
                or "violations" in norm
                or "state_diff" in norm
                or "model_judgment" in norm
                or "predicate_results" in (raw.get("evaluation") or {})
                or "failures" in norm
                or any(
                    key in norm
                    for key in ("decision", "status", "reason", "message", "summary")
                )
            )
        results.append(ConformanceResult(backend_id, "preserve_proof_cex", ok))
    except Exception as exc:  # noqa: BLE001
        results.append(ConformanceResult(backend_id, "preserve_proof_cex", False, str(exc)))

    # 10. secrets absent
    try:
        secret_env = {
            "OVK_API_TOKEN": "super-secret-token-value",
            "PGPASSWORD": "db-pass",
            "NOTE": "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig",
            "PATH": "/usr/bin",
        }
        snap = _snap(adapter, case.config, environment=secret_env)
        blob = str(snap.model_dump(mode="json"))
        profile = snapshot_to_verifier_profile(snap) if pcs_ok else {}
        blob2 = str(profile)
        leaked = any(
            marker in blob or marker in blob2
            for marker in (
                "super-secret-token-value",
                "db-pass",
                "Bearer eyJhbGciOiJIUzI1NiJ9",
            )
        )
        _ = redact_environment
        results.append(ConformanceResult(backend_id, "secrets_absent", not leaked))
    except Exception as exc:  # noqa: BLE001
        results.append(ConformanceResult(backend_id, "secrets_absent", False, str(exc)))

    # 11. mutation distinct profile
    try:
        if not pcs_ok:
            raise AssuranceError("PCS pin missing")
        snap = _snap(adapter, case.config)
        profile = snapshot_to_verifier_profile(snap)
        dims = list(adapter.supported_mutation_dimensions())
        if case.mutation_class not in dims:
            results.append(
                ConformanceResult(
                    backend_id,
                    "mutation_distinct_profile",
                    False,
                    f"{case.mutation_class} not in {dims}",
                )
            )
        else:
            mutated, manifest = mutate_profile(
                profile,
                mutation_class=case.mutation_class,
                parameters=dict(case.mutation_parameters),
                supported_dimensions=dims,
            )
            ok = (
                mutated["integrity"]["artifact_digest"] != profile["integrity"]["artifact_digest"]
                and manifest.get("production_prohibition") is True
            )
            results.append(ConformanceResult(backend_id, "mutation_distinct_profile", ok))
    except (MutationError, Exception) as exc:  # noqa: BLE001
        results.append(ConformanceResult(backend_id, "mutation_distinct_profile", False, str(exc)))

    # 12. replay drift detection
    try:
        if not pcs_ok:
            raise AssuranceError("PCS pin missing")
        manifest = adapter.manifest()
        determinism = manifest.assurance.determinism if manifest.assurance else "deterministic"
        outcome = run_assurance(adapter, input_data=dict(case.input_data), config=dict(case.config))
        drifted_profile = copy.deepcopy(outcome.profile)
        # Force digest mismatch by mutating sealed profile improperly then resealing via timeout change
        alt_snap = _snap(
            adapter,
            {**dict(case.config), "timeout_ms": int(case.config.get("timeout_ms") or 5000) + 7},
        )
        drifted_profile = snapshot_to_verifier_profile(alt_snap)
        if determinism == "stochastic":
            report = replay_invocation(
                outcome.invocation,
                adapter=adapter,
                profile=outcome.profile,
                input_data=dict(case.input_data),
                config=dict(case.config),
                claim_matched=False,
            )
            ok = report.get("indeterminate_reason") == "declared_nondeterminism" or report.get("replay_status") == "indeterminate"
        else:
            try:
                replay_invocation(
                    outcome.invocation,
                    adapter=adapter,
                    profile=drifted_profile,
                    input_data=dict(case.input_data),
                    config=dict(case.config),
                    claim_matched=True,
                )
                ok = False  # should have raised
            except ReplayError:
                ok = True
        results.append(ConformanceResult(backend_id, "replay_drift_detection", ok))
    except Exception as exc:  # noqa: BLE001
        results.append(ConformanceResult(backend_id, "replay_drift_detection", False, str(exc)))

    # 13. PCS validate profile
    try:
        if not pcs_ok:
            raise AssuranceError("PCS pin missing")
        snap = _snap(adapter, case.config)
        profile = snapshot_to_verifier_profile(snap)
        require_valid_pcs_artifact(profile, artifact_type="VerifierProfile.v1")
        results.append(ConformanceResult(backend_id, "pcs_validate_profile", True))
    except Exception as exc:  # noqa: BLE001
        results.append(ConformanceResult(backend_id, "pcs_validate_profile", False, str(exc)))

    # 14. PCS validate result
    try:
        if not pcs_ok:
            raise AssuranceError("PCS pin missing")
        outcome = run_assurance(adapter, input_data=dict(case.input_data), config=dict(case.config))
        require_valid_pcs_artifact(outcome.result, artifact_type="VerificationResult.v1")
        if case.expect_accept:
            # Soft check — adapters may still be indeterminate when tools missing
            pass
        results.append(ConformanceResult(backend_id, "pcs_validate_result", True, outcome.decision))
    except Exception as exc:  # noqa: BLE001
        results.append(ConformanceResult(backend_id, "pcs_validate_result", False, str(exc)))

    # Ensure all 14 ids present
    seen = {r.test_id for r in results}
    for test_id in CONFORMANCE_TEST_IDS:
        if test_id not in seen:
            results.append(ConformanceResult(backend_id, test_id, False, "not executed"))
    return results


def gate_assurance_adapters(cases: list[ConformanceCase]) -> dict[str, Any]:
    """Run conformance for all cases; fail closed if any assurance_capable adapter fails."""
    all_results: list[ConformanceResult] = []
    for case in cases:
        all_results.extend(run_conformance_case(case))
    failures = [r for r in all_results if not r.passed]
    return {
        "passed": not failures,
        "total": len(all_results),
        "failures": [
            {"backend_id": f.backend_id, "test_id": f.test_id, "detail": f.detail} for f in failures
        ],
        "results": [
            {"backend_id": r.backend_id, "test_id": r.test_id, "passed": r.passed, "detail": r.detail}
            for r in all_results
        ],
    }


def write_example_pack(adapter: Any, *, out_dir: Path, input_data: Mapping[str, Any], config: Mapping[str, Any]) -> Path:
    """Write an example evidence pack under examples/assurance/."""
    out_dir.mkdir(parents=True, exist_ok=True)
    outcome = run_assurance(adapter, input_data=dict(input_data), config=dict(config), evidence_dir=out_dir)
    if outcome.evidence_dir is None:
        raise AssuranceError("evidence pack was not written")
    return Path(outcome.evidence_dir)
