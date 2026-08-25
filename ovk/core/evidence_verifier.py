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

from dataclasses import dataclass
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


def verify_evidence_semantics(
    evidence: VerificationEvidence | Mapping[str, Any],
    *,
    path: str = "evidence",
) -> SemanticVerificationReport:
    """Independently verify one evidence record.

    Legacy v1/v2 evidence receives model-level and digest checks only because it
    predates the reconstructable control-plane trace. v3 evidence is required to
    carry exactly one v2 trace and is fully recomputed.
    """
    issues: list[SemanticVerificationIssue] = []
    try:
        item = evidence if isinstance(evidence, VerificationEvidence) else VerificationEvidence.model_validate(dict(evidence))
    except ValidationError as exc:
        return SemanticVerificationReport(
            valid=False,
            issues=(SemanticVerificationIssue(path=path, message=f"invalid evidence model: {exc}"),),
        )

    is_v3 = str(item.schema_version).startswith("ovk.evidence.v3")
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
    if item.policy_digest != obligation.policy_digest:
        _issue(issues, f"{path}.policy_digest", "top-level policy_digest does not match obligation")

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

    return SemanticVerificationReport(valid=not issues, issues=tuple(issues))


def verify_bundle_semantics(
    bundle: EvidenceBundle | Mapping[str, Any],
) -> SemanticVerificationReport:
    """Verify every evidence record, the bundle identity and final decision."""
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

    for index, item in enumerate(parsed.evidence):
        report = verify_evidence_semantics(item, path=f"evidence[{index}]")
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
