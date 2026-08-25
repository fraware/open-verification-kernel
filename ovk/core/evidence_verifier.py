"""Independent semantic verification for OVK evidence and bundles.

This verifier treats serialized evidence as untrusted input. For control-plane
v3 evidence it reconstructs the typed obligation, route, backend obligations,
attempts and normalized results from the sealed trace and recomputes every
content-addressed identity that is derivable from those objects. It also
replays aggregation and the conservative coverage/trust floors before checking
the stored evidence and bundle decisions.

The verifier intentionally does not call lane compilers or backend adapters.
That separation makes it useful for offline consumers and release-bundle
verification: it checks that the evidence is internally self-consistent and
that its advertised decision follows from the recorded execution semantics.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from pydantic import ValidationError

from ovk.compilers.authorization import CoveragePolicy, strict_allow_permitted
from ovk.core.backend_aggregation import aggregate_results
from ovk.core.bundle import content_digest
from ovk.core.coverage_policy_binding import coverage_policy_from_obligation, coverage_policy_payload
from ovk.core.decision import decide_with_reason
from ovk.core.evidence_integrity import verify_evidence_digest
from ovk.core.execution_models import (
    BackendObligation,
    ExecutionAttempt,
    NormalizedBackendResult,
    RoutingDecision,
    VerificationObligation,
    compute_abstraction_digest,
    compute_attempt_id,
    compute_backend_obligation_id,
    compute_obligation_id,
    compute_payload_digest,
    compute_routing_id,
)
from ovk.core.materials import compute_material_set_digest
from ovk.core.models import (
    BackendClaim,
    DecisionState,
    EvidenceBundle,
    MergeRecommendation,
    VerificationEvidence,
    VerificationStatus,
)
from ovk.core.router import ROUTER_VERSION

TRACE_SCHEMA = "ovk.control_plane_trace.v2"
VERIFIER_VERSION = "ovk.verifier.v1"
VERIFIER_REPORT_SCHEMA_ID = "https://openverification.dev/schemas/verifier.report.v1.schema.json"
EVIDENCE_V3_SCHEMA_ID = "https://openverification.dev/schemas/verification.evidence.v3.schema.json"
BUNDLE_V3_SCHEMA_ID = "https://openverification.dev/schemas/verification.bundle.v3.schema.json"

# Trust-critical v3 fields. A new evidence version is required if digest or
# decision semantics of this set change. Unknown names at this layer are
# rejected unless they live in the namespaced ``extensions`` map.
V3_TRUST_CRITICAL_FIELDS: frozenset[str] = frozenset(
    {
        "evidence_id",
        "schema_version",
        "subject",
        "intent",
        "backend_claims",
        "decision",
        "obligation_id",
        "routing_id",
        "material_set_digest",
        "compiler",
        "materials",
        "coverage",
        "requested_backends",
        "eligible_backends",
        "selected_backends",
        "attempted_backends",
        "executed_backends",
        "execution_attempts",
        "aggregation_policy",
        "routing_enforced",
        "generated_artifacts",
        "counterexamples",
        "change_origin",
        "ovk_version",
        "checker_id",
        "checker_version",
        "input_digest",
        "relevant_file_digests",
        "configuration_digest",
        "policy_digest",
        "started_at",
        "completed_at",
        "assumptions",
        "unknowns",
        "stderr",
        "exit_status",
        "evidence_digest",
        "signature",
    }
)
V3_ALLOWED_NONCRITICAL_FIELDS: frozenset[str] = frozenset({"extensions"})

VERIFIER_TCB_MODULES: tuple[str, ...] = (
    "ovk.core.evidence_verifier",
    "ovk.core.evidence_integrity",
    "ovk.core.bundle",
    "ovk.core.decision",
    "ovk.core.backend_aggregation",
    "ovk.core.coverage_policy_binding",
    "ovk.core.execution_models",
    "ovk.core.materials",
    "ovk.core.models",
    "ovk.core.router",
    "ovk.core.schema_validation",
    "ovk.core.output_validation",
    "ovk.core.release_bundle",
    "ovk.compilers.authorization.CoveragePolicy",
)


@dataclass(frozen=True)
class SemanticVerificationIssue:
    path: str
    message: str

    def to_dict(self) -> dict[str, str]:
        return {"path": self.path, "message": self.message}


@dataclass(frozen=True)
class SemanticVerificationReport:
    valid: bool
    issues: tuple[SemanticVerificationIssue, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "issues": [item.to_dict() for item in self.issues],
        }


def _issue(issues: list[SemanticVerificationIssue], path: str, message: str) -> None:
    issues.append(SemanticVerificationIssue(path=path, message=message))


def _trace_for(evidence: VerificationEvidence) -> dict[str, Any] | None:
    traces = [
        item
        for item in evidence.generated_artifacts
        if isinstance(item, dict)
        and item.get("kind") == "control_plane_trace"
        and item.get("schema_version") == TRACE_SCHEMA
    ]
    if len(traces) != 1:
        return None
    return dict(traces[0])


def _expected_claims(
    routing: RoutingDecision,
    backend_obligations: list[BackendObligation],
    attempts: list[ExecutionAttempt],
    results: list[NormalizedBackendResult],
) -> list[BackendClaim]:
    required = {item.backend: bool(item.required) for item in routing.selected}
    adapters = {item.backend: item.adapter_version for item in backend_obligations}
    attempt_by_backend = {item.backend: item for item in attempts}
    claims = [
        BackendClaim(
            backend=result.backend,
            guarantee_type=result.guarantee_type,
            status=result.status,
            assumptions=list(result.assumptions),
            limits=list(result.limits),
            tool_version=(attempt_by_backend.get(result.backend).tool_version if attempt_by_backend.get(result.backend) else None),
            adapter_version=adapters.get(result.backend),
            required=required.get(result.backend, True),
        )
        for result in sorted(results, key=lambda row: row.backend)
    ]
    if claims:
        return claims
    return [
        BackendClaim(
            backend="none",
            guarantee_type="none",
            status=VerificationStatus.UNKNOWN,
            assumptions=["No backend produced a claim."],
            limits=["Absence of backend evidence cannot allow."],
            required=True,
        )
    ]


def _expected_evidence_decision(
    *,
    obligation: VerificationObligation,
    routing: RoutingDecision,
    attempts: list[ExecutionAttempt],
    results: list[NormalizedBackendResult],
    routing_enforced: bool,
    coverage_policy: CoveragePolicy,
) -> tuple[str, str]:
    outcome = aggregate_results(
        obligation_id=obligation.obligation_id,
        selected=routing.selected,
        results=results,
        policy=routing.aggregation_policy,
        acceptable_guarantees=obligation.acceptable_guarantees,
        fallback_policy=routing.fallback_policy,
        attempts=attempts,
    )
    state = outcome.decision_state
    recommendation = outcome.merge_recommendation

    # The evidence projection applies semantic authorization floors after backend
    # aggregation. Recompute those floors from typed material and the exact
    # obligation-bound policy, never from the stored evidence decision.
    if state == DecisionState.ALLOW and not strict_allow_permitted(
        obligation.coverage, coverage_policy
    ):
        state = DecisionState.NEEDS_REVIEW
        recommendation = MergeRecommendation.REQUIRE_HUMAN_REVIEW

    if (
        routing_enforced
        and obligation.lane == "self_protection"
        and obligation.abstraction.get("metadata_trusted") is not True
        and state == DecisionState.ALLOW
    ):
        state = DecisionState.NEEDS_REVIEW
        recommendation = MergeRecommendation.REQUIRE_HUMAN_REVIEW

    return state.value, recommendation.value


def _reject_unknown_trust_fields(
    raw: Mapping[str, Any],
    *,
    path: str,
    issues: list[SemanticVerificationIssue],
) -> None:
    unknown = [
        key
        for key in raw.keys()
        if key not in V3_TRUST_CRITICAL_FIELDS and key not in V3_ALLOWED_NONCRITICAL_FIELDS
    ]
    for key in sorted(unknown):
        _issue(
            issues,
            f"{path}.{key}",
            "unknown trust-critical field is not in the frozen v3 set and is not namespaced under extensions",
        )


def _reject_unauthorized_fallback(
    item: VerificationEvidence,
    *,
    path: str,
    issues: list[SemanticVerificationIssue],
    attempts: list[Any] | None = None,
) -> None:
    decision = item.decision or {}
    if decision.get("fallback_accepted") or decision.get("fallback_used"):
        _issue(
            issues,
            f"{path}.decision.fallback_accepted",
            "strict fallback execution is disabled; a fallback claim cannot be authorized without a bound primary+fallback tuple",
        )
        if attempts is not None and len(attempts) < 2:
            _issue(
                issues,
                f"{path}.execution_attempts",
                "fallback claims require both the primary attempt and the fallback attempt",
            )


def verify_evidence_semantics(
    evidence: VerificationEvidence | Mapping[str, Any],
    *,
    path: str = "evidence",
) -> SemanticVerificationReport:
    """Independently verify one evidence record.

    Legacy v1/v2 evidence receives model-level and digest checks only because it
    predates the reconstructable control-plane trace. v3 evidence is required to
    carry exactly one v2 trace and is fully recomputed.

    Nearly-valid or hostile input returns an invalid report rather than raising.
    """
    try:
        return _verify_evidence_semantics(evidence, path=path)
    except Exception as exc:  # noqa: BLE001 - verifier TCB must fail closed
        return SemanticVerificationReport(
            valid=False,
            issues=(
                SemanticVerificationIssue(
                    path=path,
                    message=f"verifier rejected untrusted input: {type(exc).__name__}: {exc}",
                ),
            ),
        )


def _verify_evidence_semantics(
    evidence: VerificationEvidence | Mapping[str, Any],
    *,
    path: str = "evidence",
) -> SemanticVerificationReport:
    issues: list[SemanticVerificationIssue] = []
    try:
        item = evidence if isinstance(evidence, VerificationEvidence) else VerificationEvidence.model_validate(dict(evidence))
    except ValidationError as exc:
        return SemanticVerificationReport(
            valid=False,
            issues=(SemanticVerificationIssue(path=path, message=f"invalid evidence model: {exc}"),),
        )

    is_v3 = str(item.schema_version).startswith("ovk.evidence.v3")
    if is_v3:
        raw = dict(evidence) if isinstance(evidence, Mapping) else item.model_dump(mode="json")
        _reject_unknown_trust_fields(raw, path=path, issues=issues)

    if item.evidence_digest is not None and not verify_evidence_digest(item):
        _issue(issues, f"{path}.evidence_digest", "evidence_digest does not match canonical evidence payload")

    if not is_v3:
        return SemanticVerificationReport(valid=not issues, issues=tuple(issues))

    if not item.evidence_digest:
        _issue(issues, f"{path}.evidence_digest", "v3 evidence must be sealed with evidence_digest")

    trace = _trace_for(item)
    if trace is None:
        _issue(
            issues,
            f"{path}.generated_artifacts",
            f"v3 evidence must contain exactly one {TRACE_SCHEMA} control_plane_trace",
        )
        return SemanticVerificationReport(valid=False, issues=tuple(issues))

    try:
        obligation = VerificationObligation.model_validate(trace.get("obligation"))
        routing = RoutingDecision.model_validate(trace.get("routing"))
        backend_obligations = [BackendObligation.model_validate(row) for row in trace.get("backend_obligations") or []]
        attempts = [ExecutionAttempt.model_validate(row) for row in trace.get("execution_attempts") or []]
        results = [NormalizedBackendResult.model_validate(row) for row in trace.get("results") or []]
    except (ValidationError, TypeError) as exc:
        _issue(issues, f"{path}.generated_artifacts.control_plane_trace", f"typed trace is invalid: {exc}")
        return SemanticVerificationReport(valid=False, issues=tuple(issues))

    try:
        bound_coverage_policy = coverage_policy_from_obligation(obligation)
    except (TypeError, ValueError) as exc:
        _issue(
            issues,
            f"{path}.generated_artifacts.control_plane_trace.obligation.abstraction.coverage_policy",
            f"obligation-bound coverage policy is invalid: {exc}",
        )
        bound_coverage_policy = CoveragePolicy()
    else:
        trace_coverage_policy = trace.get("coverage_policy")
        if trace_coverage_policy is not None and trace_coverage_policy != coverage_policy_payload(bound_coverage_policy):
            _issue(
                issues,
                f"{path}.generated_artifacts.control_plane_trace.coverage_policy",
                "trace coverage_policy does not match obligation-bound coverage policy",
            )

    expected_obligation_id = compute_obligation_id(obligation)
    if obligation.obligation_id != expected_obligation_id:
        _issue(issues, f"{path}.obligation_id", "typed obligation_id is not canonical")
    if item.obligation_id != obligation.obligation_id:
        _issue(issues, f"{path}.obligation_id", "top-level obligation_id does not match typed trace")
    if obligation.abstraction_digest != compute_abstraction_digest(obligation.abstraction):
        _issue(issues, f"{path}.coverage", "abstraction_digest does not match abstraction")

    subject = {key: value for key, value in obligation.subject.model_dump(mode="json").items() if value is not None}
    if item.subject != subject:
        _issue(issues, f"{path}.subject", "evidence subject does not match typed obligation subject")
    if item.intent.get("intent_id") != obligation.intent_id:
        _issue(issues, f"{path}.intent.intent_id", "intent_id does not match typed obligation")
    if item.compiler != {
        "compiler_id": obligation.compiler_id,
        "compiler_version": obligation.compiler_version,
    }:
        _issue(issues, f"{path}.compiler", "compiler identity does not match typed obligation")

    material_payloads = [row.model_dump(mode="json") for row in obligation.materials]
    if item.materials != material_payloads:
        _issue(issues, f"{path}.materials", "top-level materials do not match typed obligation")
    material_set_digest = compute_material_set_digest(material_payloads)
    if item.material_set_digest != material_set_digest:
        _issue(issues, f"{path}.material_set_digest", "material_set_digest is not canonical")
    if trace.get("material_set_digest") != material_set_digest:
        _issue(issues, f"{path}.generated_artifacts.control_plane_trace.material_set_digest", "trace material_set_digest mismatch")
    if item.coverage != obligation.coverage.model_dump(mode="json"):
        _issue(issues, f"{path}.coverage", "coverage does not match typed obligation")

    if routing.obligation_id != obligation.obligation_id:
        _issue(issues, f"{path}.routing_id", "routing is bound to a different obligation")
    if routing.policy_digest != obligation.policy_digest:
        _issue(issues, f"{path}.policy_digest", "routing policy_digest does not match obligation")
    router_version = str(trace.get("router_version") or ROUTER_VERSION)
    expected_routing_id = compute_routing_id(
        obligation_id=routing.obligation_id,
        requested=list(routing.requested),
        eligible=list(routing.eligible),
        selected=list(routing.selected),
        rejected=list(routing.rejected),
        aggregation_policy=routing.aggregation_policy,
        fallback_policy=routing.fallback_policy,
        budget=routing.budget,
        policy_digest=routing.policy_digest,
        router_version=router_version,
        assessments=None,
    )
    if routing.routing_id != expected_routing_id:
        _issue(issues, f"{path}.routing_id", "typed routing_id is not canonical")
    if item.routing_id != routing.routing_id or trace.get("routing_id") != routing.routing_id:
        _issue(issues, f"{path}.routing_id", "routing_id differs across evidence and trace")
    if item.aggregation_policy != routing.aggregation_policy:
        _issue(issues, f"{path}.aggregation_policy", "aggregation_policy does not match typed route")

    routing_flags = [
        artifact
        for artifact in item.generated_artifacts
        if isinstance(artifact, dict) and artifact.get("kind") == "routing_enforced"
    ]
    if len(routing_flags) == 1 and bool(routing_flags[0].get("value")) != bool(item.routing_enforced):
        _issue(issues, f"{path}.routing_enforced", "routing_enforced does not match sealed control-plane flag")

    if item.requested_backends != list(routing.requested):
        _issue(issues, f"{path}.requested_backends", "requested backend set does not match route")
    eligible = [row.backend for row in routing.eligible]
    selected = [row.backend for row in routing.selected]
    if item.eligible_backends != eligible:
        _issue(issues, f"{path}.eligible_backends", "eligible backend set does not match route")
    if item.selected_backends != selected:
        _issue(issues, f"{path}.selected_backends", "selected backend set does not match route")

    seen_backend_obligation_ids: set[str] = set()
    selected_set = set(selected)
    for index, backend_obligation in enumerate(backend_obligations):
        row_path = f"{path}.generated_artifacts.control_plane_trace.backend_obligations[{index}]"
        if backend_obligation.backend_obligation_id in seen_backend_obligation_ids:
            _issue(issues, row_path, "duplicate backend_obligation_id")
        seen_backend_obligation_ids.add(backend_obligation.backend_obligation_id)
        if backend_obligation.payload_digest != compute_payload_digest(backend_obligation.payload):
            _issue(issues, row_path, "payload_digest is not canonical")
        if backend_obligation.backend_obligation_id != compute_backend_obligation_id(backend_obligation):
            _issue(issues, row_path, "backend_obligation_id is not canonical")
        if backend_obligation.obligation_id != obligation.obligation_id:
            _issue(issues, row_path, "backend obligation is bound to a different obligation")
        if backend_obligation.routing_id != routing.routing_id:
            _issue(issues, row_path, "backend obligation is bound to a different route")
        if backend_obligation.backend not in selected_set:
            _issue(issues, row_path, "backend obligation was not selected")

    backend_obligation_by_id = {row.backend_obligation_id: row for row in backend_obligations}
    selected_required = {row.backend: bool(row.required) for row in routing.selected}
    seen_attempt_ids: set[str] = set()
    for index, attempt in enumerate(attempts):
        row_path = f"{path}.execution_attempts[{index}]"
        if attempt.attempt_id in seen_attempt_ids:
            _issue(issues, row_path, "duplicate attempt_id")
        seen_attempt_ids.add(attempt.attempt_id)
        if attempt.attempt_id != compute_attempt_id(attempt):
            _issue(issues, row_path, "attempt_id is not canonical")
        compiled = backend_obligation_by_id.get(attempt.backend_obligation_id)
        if compiled is None:
            _issue(issues, row_path, "attempt references unknown backend_obligation_id")
        elif compiled.backend != attempt.backend:
            _issue(issues, row_path, "attempt backend does not match backend obligation")
        if attempt.backend not in selected_required:
            _issue(issues, row_path, "attempt backend was not selected")
        elif attempt.required != selected_required[attempt.backend]:
            _issue(issues, row_path, "attempt required flag does not match routing role")

    if item.execution_attempts != [row.model_dump(mode="json") for row in attempts]:
        _issue(issues, f"{path}.execution_attempts", "top-level attempts do not match typed trace")
    if item.attempted_backends != [row.backend for row in attempts]:
        _issue(issues, f"{path}.attempted_backends", "attempted backend list does not match attempts")
    if item.executed_backends != [row.backend for row in results]:
        _issue(issues, f"{path}.executed_backends", "executed backend list does not match results")

    attempt_ids = {row.attempt_id for row in attempts}
    for index, result in enumerate(results):
        row_path = f"{path}.generated_artifacts.control_plane_trace.results[{index}]"
        if result.attempt_id not in attempt_ids:
            _issue(issues, row_path, "normalized result references unknown attempt_id")
        if result.backend not in selected_required:
            _issue(issues, row_path, "normalized result backend was not selected")

    expected_claims = _expected_claims(routing, backend_obligations, attempts, results)
    observed_claims = sorted(item.backend_claims, key=lambda row: row.backend)
    if [row.model_dump(mode="json") for row in observed_claims] != [
        row.model_dump(mode="json") for row in expected_claims
    ]:
        _issue(issues, f"{path}.backend_claims", "backend claims do not match normalized execution results")

    try:
        expected_state, expected_recommendation = _expected_evidence_decision(
            obligation=obligation,
            routing=routing,
            attempts=attempts,
            results=results,
            routing_enforced=bool(item.routing_enforced),
            coverage_policy=bound_coverage_policy,
        )
    except (TypeError, ValueError) as exc:
        _issue(
            issues,
            f"{path}.decision",
            f"decision recomputation failed for untrusted trace: {type(exc).__name__}: {exc}",
        )
    else:
        if str(item.decision.get("decision_state")) != expected_state:
            _issue(issues, f"{path}.decision.decision_state", f"stored decision_state does not recompute to {expected_state}")
        if str(item.decision.get("merge_recommendation")) != expected_recommendation:
            _issue(
                issues,
                f"{path}.decision.merge_recommendation",
                f"stored merge_recommendation does not recompute to {expected_recommendation}",
            )

    expected_evidence_id = "ev-" + content_digest(
        {
            "obligation_id": obligation.obligation_id,
            "routing_id": routing.routing_id,
            "material_set_digest": material_set_digest,
            "results": [row.model_dump(mode="json") for row in expected_claims],
        }
    )[:24]
    if item.evidence_id != expected_evidence_id:
        _issue(issues, f"{path}.evidence_id", "evidence_id is not canonical")

    _reject_unauthorized_fallback(item, path=path, issues=issues, attempts=attempts)

    return SemanticVerificationReport(valid=not issues, issues=tuple(issues))


def verify_bundle_semantics(
    bundle: EvidenceBundle | Mapping[str, Any],
) -> SemanticVerificationReport:
    """Verify every evidence record, the bundle identity and final decision."""
    try:
        return _verify_bundle_semantics(bundle)
    except Exception as exc:  # noqa: BLE001 - verifier TCB must fail closed
        return SemanticVerificationReport(
            valid=False,
            issues=(
                SemanticVerificationIssue(
                    path="bundle",
                    message=f"verifier rejected untrusted input: {type(exc).__name__}: {exc}",
                ),
            ),
        )


def _verify_bundle_semantics(
    bundle: EvidenceBundle | Mapping[str, Any],
) -> SemanticVerificationReport:
    issues: list[SemanticVerificationIssue] = []
    try:
        parsed = bundle if isinstance(bundle, EvidenceBundle) else EvidenceBundle.model_validate(dict(bundle))
    except ValidationError as exc:
        return SemanticVerificationReport(
            valid=False,
            issues=(SemanticVerificationIssue(path="bundle", message=f"invalid bundle model: {exc}"),),
        )

    if not parsed.evidence:
        _issue(issues, "evidence", "bundle contains no evidence")
        return SemanticVerificationReport(valid=False, issues=tuple(issues))

    raw_rows = bundle.get("evidence") if isinstance(bundle, Mapping) else None
    for index, item in enumerate(parsed.evidence):
        raw_item: VerificationEvidence | Mapping[str, Any] = item
        if isinstance(raw_rows, list) and index < len(raw_rows) and isinstance(raw_rows[index], Mapping):
            raw_item = raw_rows[index]
        report = verify_evidence_semantics(raw_item, path=f"evidence[{index}]")
        issues.extend(report.issues)
        if item.subject != parsed.subject:
            _issue(issues, f"evidence[{index}].subject", "evidence subject does not equal bundle subject")

    fingerprint = content_digest(
        {
            "subject": parsed.subject,
            "evidence": [item.model_dump(mode="json") for item in parsed.evidence],
        }
    )[:16]
    if parsed.bundle_id != f"bundle-{fingerprint}":
        _issue(issues, "bundle_id", "bundle_id is not canonical")

    recomputed = decide_with_reason(parsed, enforce=True)
    stored_state = parsed.decision.get("decision_state")
    stored_merge = parsed.decision.get("merge_recommendation")
    if stored_state != recomputed.get("decision_state"):
        _issue(
            issues,
            "decision.decision_state",
            f"bundle decision_state does not recompute to {recomputed.get('decision_state')}",
        )
    if stored_merge != recomputed.get("merge_recommendation"):
        _issue(
            issues,
            "decision.merge_recommendation",
            f"bundle merge_recommendation does not recompute to {recomputed.get('merge_recommendation')}",
        )

    return SemanticVerificationReport(valid=not issues, issues=tuple(issues))


def _empty_checks() -> dict[str, bool]:
    return {
        "schema": False,
        "semantic_trace": False,
        "digests": False,
        "bundle_decision": False,
        "manifest": False,
        "attestation": False,
    }


def build_verifier_report(
    *,
    valid: bool,
    target_kind: str,
    target_path: str,
    issues: list[SemanticVerificationIssue] | tuple[SemanticVerificationIssue, ...],
    checks: dict[str, bool] | None = None,
    schema_ids: list[str] | None = None,
) -> dict[str, Any]:
    """Serialize a verifier.report.v1 document."""
    return {
        "schema_version": "ovk.verifier.report.v1",
        "verifier_version": VERIFIER_VERSION,
        "valid": valid,
        "target": {
            "kind": target_kind,
            "path": str(target_path),
            "schema_ids": schema_ids
            or [EVIDENCE_V3_SCHEMA_ID, BUNDLE_V3_SCHEMA_ID, VERIFIER_REPORT_SCHEMA_ID],
        },
        "checks": checks or _empty_checks(),
        "issues": [item.to_dict() if hasattr(item, "to_dict") else item for item in issues],
        "tcb_modules": list(VERIFIER_TCB_MODULES),
    }


def verify_serialized_artifact(path: Path) -> dict[str, Any]:
    """Verify a bundle file or release directory using the single verifier TCB.

    ``ovk validate-outputs`` is the directory form of this same TCB. This entry
    point never raises on hostile input; it returns an invalid report.
    """
    from ovk.core.output_validation import validate_output_directory
    from ovk.core.release_bundle import verify_release_bundle

    target = Path(path)
    checks = _empty_checks()
    issues: list[SemanticVerificationIssue] = []
    try:
        if target.is_dir():
            schema_failures = validate_output_directory(target)
            manifest_failures = verify_release_bundle(target)
            checks["schema"] = not schema_failures
            checks["manifest"] = not any("manifest" in item.lower() for item in manifest_failures)
            checks["attestation"] = not any("attestation" in item.lower() for item in schema_failures)
            for failure in schema_failures + manifest_failures:
                issues.append(SemanticVerificationIssue(path=str(target), message=failure))
            evidence_path = target / "ovk-evidence.json"
            if evidence_path.is_file():
                payload = json.loads(evidence_path.read_text(encoding="utf-8"))
                if isinstance(payload, dict) and "evidence" in payload:
                    semantic = verify_bundle_semantics(payload)
                else:
                    semantic = verify_evidence_semantics(payload)
                issues.extend(semantic.issues)
                checks["semantic_trace"] = not semantic.issues
                checks["digests"] = not any("digest" in item.message for item in semantic.issues)
                checks["bundle_decision"] = not any("decision" in item.path for item in semantic.issues)
            else:
                issues.append(
                    SemanticVerificationIssue(path="ovk-evidence.json", message="evidence bundle is missing")
                )
            return build_verifier_report(
                valid=not issues,
                target_kind="directory",
                target_path=str(target),
                issues=issues,
                checks=checks,
            )

        payload = json.loads(target.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            issues.append(SemanticVerificationIssue(path=str(target), message="artifact is not a JSON object"))
            return build_verifier_report(
                valid=False, target_kind="bundle", target_path=str(target), issues=issues, checks=checks
            )
        if "evidence" in payload and "bundle_id" in payload:
            semantic = verify_bundle_semantics(payload)
            checks["schema"] = True
            checks["semantic_trace"] = semantic.valid
            checks["digests"] = not any("digest" in item.message for item in semantic.issues)
            checks["bundle_decision"] = not any("decision" in item.path for item in semantic.issues)
            checks["manifest"] = True
            checks["attestation"] = True
            return build_verifier_report(
                valid=semantic.valid,
                target_kind="bundle",
                target_path=str(target),
                issues=list(semantic.issues),
                checks=checks,
            )
        semantic = verify_evidence_semantics(payload)
        checks["schema"] = True
        checks["semantic_trace"] = semantic.valid
        checks["digests"] = not any("digest" in item.message for item in semantic.issues)
        checks["bundle_decision"] = True
        checks["manifest"] = True
        checks["attestation"] = True
        return build_verifier_report(
            valid=semantic.valid,
            target_kind="evidence",
            target_path=str(target),
            issues=list(semantic.issues),
            checks=checks,
        )
    except Exception as exc:  # noqa: BLE001 - hostile files must not crash the verifier
        issues.append(
            SemanticVerificationIssue(
                path=str(target),
                message=f"verifier rejected untrusted input: {type(exc).__name__}: {exc}",
            )
        )
        return build_verifier_report(
            valid=False, target_kind="bundle", target_path=str(target), issues=issues, checks=checks
        )
