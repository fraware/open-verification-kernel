"""Experimental Lean RTK source/target *context* predictor.

Distinct from the target-native Lean oracle in #181–#182. It never invokes
Lean, checks a proof, reads an oracle result, or accesses target diagnostics.

Scope: typed theorem identity, source-evidence integrity reference, a declared
transitive support graph, and exact policy/checker/environment identity.
VALID is CONDITIONAL on externally authenticated inputs, on complete
support extraction, and on the soundness of the stated support abstraction.
No concrete-to-abstract refinement theorem is claimed. Do not run on an
unblinded holdout or report these predictions as empirically calibrated.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from experiments.rtk.lean_v2_preoracle import (
    FrozenCohort,
    FrozenLeanCase,
    Prediction,
    PredictionBundle,
    canonical_bytes,
    digest,
)

_SHA = r"^[0-9a-f]{64}$"
_GIT = r"^[0-9a-f]{40}$"
_SYM = r"^[A-Za-z_][A-Za-z0-9_.']*$"
_DECISION = Literal["VALID", "REVALIDATION_REQUIRED", "UNRESOLVED"]


class LeanSupportNode(BaseModel):
    """Declared transitive dependency node, not independently verified Lean data."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    symbol: str = Field(pattern=_SYM)
    semantic_sha256: str = Field(pattern=_SHA)
    dependencies: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def check_dependencies(self) -> "LeanSupportNode":
        if (
            len(set(self.dependencies)) != len(self.dependencies)
            or any(not isinstance(item, str) or not item for item in self.dependencies)
            or self.symbol in self.dependencies
        ):
            raise ValueError("duplicate, invalid or self-referential dependency")
        return self


class LeanContextManifest(BaseModel):
    """A precise asserted source/target theorem and its applicability context.

    Root/support identity is computed only from dependency-reachable nodes:
    unrelated repository changes are excluded deliberately. A producer must
    independently establish that each proof's COMPLETE semantic/axiom support
    has been included. A boolean assertion alone cannot discharge that proof.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["rtk.lean_v2.context_manifest.v1"]
    theorem_symbol: str = Field(pattern=_SYM)
    statement_sha256: str = Field(pattern=_SHA)
    checker_binary_sha256: str = Field(pattern=_SHA)
    checker_configuration_sha256: str = Field(pattern=_SHA)
    environment_sha256: str = Field(pattern=_SHA)
    relying_policy_sha256: str = Field(pattern=_SHA)
    trusted_axioms_sha256: str = Field(pattern=_SHA)
    source_extractor_sha256: str = Field(pattern=_SHA)
    support_claimed_complete: bool
    root_symbols: list[str] = Field(min_length=1)
    support_nodes: list[LeanSupportNode] = Field(min_length=1)

    @model_validator(mode="after")
    def check_graph_identity(self) -> "LeanContextManifest":
        symbols = [node.symbol for node in self.support_nodes]
        if len(set(symbols)) != len(symbols):
            raise ValueError("duplicate support symbols")
        if len(set(self.root_symbols)) != len(self.root_symbols):
            raise ValueError("duplicate root symbols")
        if any(not isinstance(x, str) or not x for x in self.root_symbols):
            raise ValueError("invalid root symbol")
        return self


class LeanHistoricalEvidence(BaseModel):
    """Only a supplied source receipt and proof bytes identity, no target verdict."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source_proof_sha256: str = Field(pattern=_SHA)
    native_acceptance_receipt_sha256: str = Field(pattern=_SHA)
    source_acceptance: Literal["ACCEPTED", "NOT_ESTABLISHED"]
    admissibility: Literal["active", "revoked", "expired", "unknown"]


class LeanTransportInput(BaseModel):
    """Exact case and two *pre-outcome* asserted support manifests."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    case: FrozenLeanCase
    source: LeanContextManifest
    target: LeanContextManifest
    evidence: LeanHistoricalEvidence


class LeanTransportDecision(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    case_id: str
    verdict: _DECISION
    reason_codes: list[str]
    evidence_reuse_conditionally_eligible: bool
    affected_support_symbols: list[str]
    # These are candidates for revalidation, not a proved minimal repair set.
    revalidation_obligations: list[str]
    source_support_sha256: str | None
    target_support_sha256: str | None
    formal_soundness_established: Literal[False] = False
    native_oracle_consulted: Literal[False] = False
    external_manifest_authority_verified: Literal[False] = False


class _InvalidSupport(Exception):
    """Unknown, cyclic or incompletely specified dependency support."""


def _support_identity(manifest: LeanContextManifest) -> tuple[str, dict[str, str]]:
    nodes = {node.symbol: node for node in manifest.support_nodes}
    active: set[str] = set()
    memo: dict[str, str] = {}

    def visit(symbol: str) -> str:
        if symbol in active:
            raise _InvalidSupport("dependency_cycle")
        if symbol in memo:
            return memo[symbol]
        node = nodes.get(symbol)
        if node is None:
            raise _InvalidSupport("missing_support_node")
        active.add(symbol)
        dependencies = sorted({
            dependency: visit(dependency) for dependency in node.dependencies
        }.items())
        active.remove(symbol)
        payload = json.dumps(
            {
                "symbol": symbol,
                "semantic_sha256": node.semantic_sha256,
                "dependencies": dependencies,
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        memo[symbol] = hashlib.sha256(payload).hexdigest()
        return memo[symbol]

    root_ids = sorted({
        name: visit(name) for name in manifest.root_symbols
    }.items())
    payload = json.dumps(root_ids, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest(), memo


def evaluate_lean_transport(raw: LeanTransportInput) -> LeanTransportDecision:
    """Predict under an explicitly declared, unproved closed-support assumption.

    No runtime Lean check is made, and a caller-supplied digest is *not* an
    authenticated native witness. Only independently observed checker results
    could validate whether this prediction is externally correct.
    """

    item = LeanTransportInput.model_validate(raw.model_dump(mode="json"))
    case, source, target, evidence = (
        item.case, item.source, item.target, item.evidence
    )
    # Prevent comparison across unrelated precommitted source/target cases.
    if (
        source.theorem_symbol != case.theorem_name
        or target.theorem_symbol != case.theorem_name
        or target.statement_sha256 != case.target_claim_sha256
        or digest(source) != case.source_context_sha256
        or digest(target) != case.target_context_sha256
        or evidence.source_proof_sha256 != case.source_evidence_sha256
        or evidence.native_acceptance_receipt_sha256
        != case.source_native_acceptance_sha256
    ):
        raise ValueError("transport inputs are not bound to frozen case")

    reasons: set[str] = set()
    affected: list[str] = []
    old_id: str | None = None
    new_id: str | None = None
    try:
        old_id, old_nodes = _support_identity(source)
        new_id, new_nodes = _support_identity(target)
    except _InvalidSupport as error:
        reasons.add("support_" + str(error))
        old_nodes = {}
        new_nodes = {}

    if not source.support_claimed_complete or not target.support_claimed_complete:
        reasons.add("support_completeness_unestablished")
    if evidence.source_acceptance != "ACCEPTED":
        reasons.add("source_native_acceptance_not_established")
    if evidence.admissibility == "unknown":
        reasons.add("prior_evidence_admissibility_unknown")

    invalid_context = bool(reasons)
    if invalid_context:
        verdict: _DECISION = "UNRESOLVED"
    else:
        if evidence.admissibility in {"revoked", "expired"}:
            reasons.add("prior_evidence_" + evidence.admissibility)
        fields = (
            ("statement_changed", source.statement_sha256, target.statement_sha256),
            ("checker_changed", source.checker_binary_sha256, target.checker_binary_sha256),
            (
                "checker_configuration_changed",
                source.checker_configuration_sha256,
                target.checker_configuration_sha256,
            ),
            ("environment_changed", source.environment_sha256, target.environment_sha256),
            ("relying_policy_changed", source.relying_policy_sha256, target.relying_policy_sha256),
            ("axiom_context_changed", source.trusted_axioms_sha256, target.trusted_axioms_sha256),
            ("extractor_changed", source.source_extractor_sha256, target.source_extractor_sha256),
        )
        for reason, old, new in fields:
            if old != new:
                reasons.add(reason)
        if old_id != new_id:
            reasons.add("transitive_support_changed")
            affected = sorted({
                name for name in set(old_nodes) | set(new_nodes)
                if old_nodes.get(name) != new_nodes.get(name)
            })
        verdict = "REVALIDATION_REQUIRED" if reasons else "VALID"

    obligations: list[str] = []
    if verdict == "REVALIDATION_REQUIRED":
        obligations.append("fresh_native_check_target_claim")
        obligations.extend("recheck_support:" + name for name in affected)
    elif verdict == "UNRESOLVED":
        obligations.append("reconstruct_and_authenticate_missing_context")
        obligations.append("fresh_native_check_target_claim")

    return LeanTransportDecision(
        case_id=case.case_id,
        verdict=verdict,
        reason_codes=sorted(reasons),
        evidence_reuse_conditionally_eligible=(verdict == "VALID"),
        affected_support_symbols=affected,
        revalidation_obligations=obligations,
        source_support_sha256=old_id,
        target_support_sha256=new_id,
    )


def make_prediction_bundle(
    cohort: FrozenCohort,
    inputs: list[LeanTransportInput],
    *,
    sut_commit: str,
    sut_adapter_id: str = "rtk.lean_context.v1-development",
) -> tuple[PredictionBundle, list[LeanTransportDecision]]:
    """Produce pre-oracle predictions bound exactly to a frozen cohort."""

    cohort = FrozenCohort.model_validate(cohort.model_dump(mode="json"))
    if sut_commit != cohort.sut_commit or sut_adapter_id != cohort.sut_adapter_id:
        raise ValueError("predictor must match frozen SUT identity")
    if len(inputs) != len(cohort.cases):
        raise ValueError("prediction inputs must cover exact cohort")
    decisions: list[LeanTransportDecision] = []
    predictions: list[Prediction] = []
    for case, raw in zip(cohort.cases, inputs, strict=True):
        if raw.case != case:
            raise ValueError("input order or frozen case identity mismatch")
        decision = evaluate_lean_transport(raw)
        decisions.append(decision)
        predictions.append(Prediction(
            case_id=case.case_id,
            input_sha256=digest(case),
            verdict=decision.verdict,
        ))
    return (
        PredictionBundle(
            schema_version="rtk.lean_v2.predictions.v1",
            cohort_sha256=digest(cohort),
            sut_commit=sut_commit,
            sut_adapter_id=sut_adapter_id,
            predictions=predictions,
        ),
        decisions,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cohort", required=True, type=Path)
    parser.add_argument("--inputs", required=True, type=Path)
    parser.add_argument("--predictions", required=True, type=Path)
    parser.add_argument("--decisions", required=True, type=Path)
    args = parser.parse_args()
    cohort = FrozenCohort.model_validate_json(args.cohort.read_text())
    inputs = [
        LeanTransportInput.model_validate(x)
        for x in json.loads(args.inputs.read_text())
    ]
    bundle, decisions = make_prediction_bundle(
        cohort, inputs, sut_commit=cohort.sut_commit,
        sut_adapter_id=cohort.sut_adapter_id,
    )
    if args.predictions.exists() or args.decisions.exists():
        parser.error("prediction outputs are immutable and must not exist")
    with args.predictions.open("x", encoding="utf-8") as output:
        output.write(json.dumps(bundle.model_dump(mode="json"), sort_keys=True, indent=2) + "\n")
    with args.decisions.open("x", encoding="utf-8") as output:
        output.write(json.dumps(
            [decision.model_dump(mode="json") for decision in decisions],
            sort_keys=True,
            indent=2,
        ) + "\n")
    print("PRE_ORACLE_CONTEXT_PREDICTIONS_WRITTEN")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
