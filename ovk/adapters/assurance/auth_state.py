"""Exact authoritative-state predicate evaluator (VA-06)."""

from __future__ import annotations

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
    AssuranceFailureBehavior,
    AssuranceReplaySupport,
    AssuranceSnapshotSupport,
    AssuranceVerifierIdentity,
    BackendCapabilityManifest,
    BackendGuaranteeDeclaration,
    BackendToolIdentity,
)

GUARANTEE_CLASS = "observational"

_DECISION_SPACE = [
    "accept",
    "reject",
    "indeterminate_execution_error",
    "indeterminate_out_of_scope",
    "indeterminate_insufficient_evidence",
]


def _resolve_path(data: Mapping[str, Any], path: str) -> Any:
    cur: Any = data
    for part in path.split("."):
        if not isinstance(cur, Mapping) or part not in cur:
            raise KeyError(path)
        cur = cur[part]
    return cur


def evaluate_predicates(
    authoritative_state: Mapping[str, Any],
    predicates: list[Mapping[str, Any]],
) -> dict[str, Any]:
    """Evaluate exact predicates over declared authoritative state materials.

    Supported predicate kinds:
    - ``field_equals``: path equals expected
    - ``digest_matches``: sha256 of path (or whole state) equals expected_digest
    - ``set_contains``: path (list/set) contains member
    - ``required_keys``: mapping at path contains all keys
    - ``state_machine_safe``: reuse approval-path reachability over embedded machine
    """
    results: list[dict[str, Any]] = []
    for index, predicate in enumerate(predicates):
        kind = str(predicate.get("kind") or "").strip()
        entry: dict[str, Any] = {"index": index, "kind": kind, "predicate": dict(predicate)}
        try:
            if kind == "field_equals":
                path = str(predicate["path"])
                actual = _resolve_path(authoritative_state, path)
                expected = predicate.get("expected")
                passed = actual == expected
                entry.update({"path": path, "actual": actual, "expected": expected, "passed": passed})
            elif kind == "digest_matches":
                path = predicate.get("path")
                material = authoritative_state if path in (None, "", ".") else _resolve_path(
                    authoritative_state, str(path)
                )
                actual_digest = sha256_digest(material)
                expected = str(predicate.get("expected_digest") or "")
                passed = actual_digest == expected
                entry.update(
                    {
                        "path": path or ".",
                        "actual_digest": actual_digest,
                        "expected_digest": expected,
                        "passed": passed,
                    }
                )
            elif kind == "set_contains":
                path = str(predicate["path"])
                collection = _resolve_path(authoritative_state, path)
                member = predicate.get("member")
                if isinstance(collection, (list, tuple, set, frozenset)):
                    passed = member in collection
                else:
                    raise TypeError(f"set_contains path {path!r} is not a collection")
                entry.update({"path": path, "member": member, "passed": passed})
            elif kind == "required_keys":
                path = str(predicate.get("path") or ".")
                mapping = (
                    authoritative_state
                    if path in (".", "")
                    else _resolve_path(authoritative_state, path)
                )
                if not isinstance(mapping, Mapping):
                    raise TypeError(f"required_keys path {path!r} is not a mapping")
                keys = [str(k) for k in predicate.get("keys") or []]
                missing = [k for k in keys if k not in mapping]
                passed = not missing
                entry.update({"path": path, "missing": missing, "passed": passed})
            elif kind == "state_machine_safe":
                from ovk.adapters.deployment.state_machine import find_skipped_approval_paths

                machine = predicate.get("machine")
                if not isinstance(machine, Mapping):
                    # Allow embedding under authoritative_state.machine
                    machine = authoritative_state.get("machine")
                if not isinstance(machine, Mapping):
                    raise ValueError("state_machine_safe requires machine mapping")
                counterexamples = find_skipped_approval_paths(dict(machine))
                passed = len(counterexamples) == 0
                entry.update({"counterexamples": counterexamples, "passed": passed})
            else:
                entry.update({"passed": False, "error": f"unsupported predicate kind: {kind}"})
                return {
                    "ok": False,
                    "unsupported": True,
                    "message": f"unsupported predicate kind: {kind}",
                    "results": results + [entry],
                }
        except KeyError as exc:
            entry.update({"passed": False, "error": f"missing path: {exc}"})
            return {
                "ok": False,
                "unsupported": True,
                "message": f"missing path: {exc}",
                "results": results + [entry],
            }
        except (TypeError, ValueError) as exc:
            entry.update({"passed": False, "error": str(exc)})
            return {
                "ok": False,
                "unsupported": True,
                "message": str(exc),
                "results": results + [entry],
            }
        results.append(entry)

    all_passed = all(bool(item.get("passed")) for item in results) and bool(results)
    return {"ok": all_passed, "unsupported": False, "results": results, "message": None}


class AuthoritativeStateAdapter(AssuranceBackendMixin):
    """Exact predicates over declared authoritative state materials."""

    backend_id = "auth-state-predicate"
    adapter_id = "ovk-adapter-auth-state-predicate"
    adapter_version = "0.1.0"
    _guarantee_type = "exact_predicate"

    def __init__(self, *, timeout_ms: int = 5_000) -> None:
        self.timeout_ms = timeout_ms

    def supported_mutation_dimensions(self) -> list[str]:
        return ["alter_timeout", "remove_authority_predicate", "remove_success_predicate"]

    def manifest(self) -> BackendCapabilityManifest:
        return BackendCapabilityManifest(
            capability_id="auth-state-predicate-v1",
            tool=BackendToolIdentity(
                name=self.backend_id,
                adapter=self.adapter_id,
                adapter_version=self.adapter_version,
                version=self.adapter_version,
            ),
            backend_class="custom",
            guarantee=BackendGuaranteeDeclaration(
                type="exact_predicate",
                meaning_of_pass="All declared predicates hold over the authoritative state materials.",
                meaning_of_fail="At least one declared predicate fails over the authoritative state.",
                meaning_of_unknown="Authoritative state missing, unsupported predicate, or checker error.",
            ),
            input_languages=["json"],
            supported_domains=["assurance", "authoritative_state"],
            supported_property_kinds=["exact_predicate", "invariant"],
            assumptions=["Caller supplies complete authoritative state materials and exact predicates."],
            limits=["Does not invent state; missing authoritative_state is indeterminate."],
            result_format="ovk.result.v1",
            timeout_behavior="unknown",
            assurance=AssuranceCapabilitySection(
                assurance_capable=True,
                verifier_identity=AssuranceVerifierIdentity(
                    verifier_id="ovk.assurance.auth_state_predicate",
                    implementation_name="AuthoritativeStateAdapter",
                    entry_point="ovk.adapters.assurance.auth_state.AuthoritativeStateAdapter",
                    pcs_profile_artifact_type="VerifierProfile.v1",
                ),
                decision_semantics=AssuranceDecisionSemantics(
                    decision_space=_DECISION_SPACE,  # type: ignore[arg-type]
                    guarantee_class=GUARANTEE_CLASS,  # type: ignore[arg-type]
                    supported_claim_ids=["claim.auth_state.exact_predicate"],
                    out_of_scope_claim_ids=["claim.formal.full_correctness"],
                ),
                mechanism_class="static_analysis",
                determinism="deterministic",
                evidence_channels=["raw_backend_result", "normalized_result", "counterexample", "compiled_obligation"],
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
                external_dependencies=[],
                known_limits=["exact predicates over declared materials only"],
                requires_authoritative_state=True,
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
        predicates = cfg.get("predicates")
        return build_configuration_snapshot(
            backend_id=self.backend_id,
            adapter_id=self.adapter_id,
            adapter_version=self.adapter_version,
            config=cfg,
            environment=environment,
            policy=predicates,
            mechanism_class="static_analysis",
            determinism="deterministic",
            allows_abstention=True,
            guarantee_class=GUARANTEE_CLASS,
            decision_space=_DECISION_SPACE,
            supported_claim_ids=["claim.auth_state.exact_predicate"],
            out_of_scope_claim_ids=["claim.formal.full_correctness"],
            assumptions=["Authoritative state materials are caller-declared and complete."],
            known_blind_spots=["Does not discover undeclared state materials."],
            entry_point="ovk.adapters.assurance.auth_state.AuthoritativeStateAdapter",
            implementation_name="AuthoritativeStateAdapter",
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
        argv = [self.adapter_id, "exact-predicate"]

        auth_state = input_data.get("authoritative_state")
        if not isinstance(auth_state, Mapping):
            return indeterminate_run_outcome(
                reason="missing_authoritative_state",
                message="input.authoritative_state mapping is required",
                raw_result={"input_keys": sorted(input_data.keys())},
                guarantee_class=GUARANTEE_CLASS,
                command_argv=argv,
            )

        predicates = input_data.get("predicates")
        if predicates is None:
            predicates = cfg.get("predicates")
        if not isinstance(predicates, list) or not predicates:
            return indeterminate_run_outcome(
                reason="unsupported_input",
                message="non-empty predicates list is required",
                raw_result={"authoritative_state_digest": sha256_digest(dict(auth_state))},
                guarantee_class=GUARANTEE_CLASS,
                command_argv=argv,
            )
        if not all(isinstance(item, Mapping) for item in predicates):
            return indeterminate_run_outcome(
                reason="unsupported_input",
                message="each predicate must be a mapping",
                guarantee_class=GUARANTEE_CLASS,
                command_argv=argv,
            )

        # Optional binding: if config declares expected state digest, enforce it.
        expected_state_digest = cfg.get("authoritative_state_digest")
        actual_state_digest = sha256_digest(dict(auth_state))
        if isinstance(expected_state_digest, str) and expected_state_digest != actual_state_digest:
            raw = {
                "authoritative_state_digest": actual_state_digest,
                "expected_authoritative_state_digest": expected_state_digest,
                "passed": False,
            }
            return reject_outcome(
                raw_result=raw,
                normalized_extra={"counterexamples": [raw], "state_digest": actual_state_digest},
                stdout="reject: authoritative_state_digest mismatch",
                guarantee_class=GUARANTEE_CLASS,
                command_argv=argv,
            )

        evaluation = evaluate_predicates(dict(auth_state), list(predicates))  # type: ignore[arg-type]
        raw = {
            "authoritative_state_digest": actual_state_digest,
            "predicate_count": len(predicates),
            "evaluation": evaluation,
        }
        if evaluation.get("unsupported"):
            return indeterminate_run_outcome(
                reason="unsupported_input",
                message=str(evaluation.get("message") or "unsupported predicate"),
                raw_result=raw,
                guarantee_class=GUARANTEE_CLASS,
                command_argv=argv,
            )
        if evaluation.get("ok"):
            return accept_outcome(
                raw_result=raw,
                normalized_extra={"state_digest": actual_state_digest, "predicate_results": evaluation["results"]},
                guarantee_class=GUARANTEE_CLASS,
                command_argv=argv,
            )
        failures = [item for item in evaluation.get("results") or [] if not item.get("passed")]
        return reject_outcome(
            raw_result=raw,
            normalized_extra={
                "state_digest": actual_state_digest,
                "counterexamples": failures,
                "predicate_results": evaluation.get("results"),
            },
            stdout="reject: predicate failure",
            guarantee_class=GUARANTEE_CLASS,
            command_argv=argv,
        )
