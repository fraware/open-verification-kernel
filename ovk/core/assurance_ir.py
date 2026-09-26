"""Typed semantic interchange between source extractors and OVK obligations.

A valid Assurance IR is not verification evidence. It records a source-grounded
semantic model, its provenance, coverage, assumptions, and unresolved semantics.
"""

from __future__ import annotations

import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ovk.core.bundle import content_digest
from ovk.core.models import SourceRange, VerificationSubject


CoverageStatus = Literal["complete", "partial", "unknown", "inapplicable"]
PrincipalKind = Literal["human", "service", "agent", "anonymous", "unknown"]
ClaimOrigin = Literal["human", "repository", "policy", "imported", "ai_candidate"]
BindingKind = Literal["principal", "effect", "resource"]
BindingRelation = Literal["equal", "derived_equal", "distinct", "unknown"]

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]*$")
_EFFECT_RE = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)+$")


def _id(value: str) -> str:
    value = value.strip()
    if not _ID_RE.fullmatch(value):
        raise ValueError("semantic ids must be non-empty stable identifiers")
    return value


class SourceProvenance(BaseModel):
    extractor_id: str
    extractor_version: str
    subject: VerificationSubject
    source_ranges: list[SourceRange] = Field(default_factory=list)
    coverage: CoverageStatus = "unknown"
    assumptions: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class PrincipalRef(BaseModel):
    principal_id: str
    kind: PrincipalKind = "unknown"
    expression: str | None = None
    attributes: dict[str, Any] = Field(default_factory=dict)
    provenance: SourceProvenance

    _validate_id = field_validator("principal_id")(_id)


class ResourceRef(BaseModel):
    resource_id: str
    resource_type: str
    expression: str | None = None
    tenant_expression: str | None = None
    attributes: dict[str, Any] = Field(default_factory=dict)
    provenance: SourceProvenance

    _validate_id = field_validator("resource_id")(_id)


class EffectRef(BaseModel):
    effect_id: str
    name: str
    operation: str | None = None
    attributes: dict[str, Any] = Field(default_factory=dict)
    provenance: SourceProvenance

    _validate_id = field_validator("effect_id")(_id)

    @field_validator("name")
    @classmethod
    def namespaced_effect(cls, value: str) -> str:
        value = value.strip()
        if not _EFFECT_RE.fullmatch(value):
            raise ValueError("effect name must be namespaced, for example billing.invoice.refund")
        return value


class AuthorizationGuard(BaseModel):
    guard_id: str
    principal_ref: str
    effect_ref: str
    resource_ref: str
    decision_expression: str | None = None
    policy_ref: str | None = None
    provenance: SourceProvenance

    _validate_ids = field_validator("guard_id", "principal_ref", "effect_ref", "resource_ref")(_id)


class ProtectedEffect(BaseModel):
    protected_effect_id: str
    principal_ref: str
    effect_ref: str
    resource_ref: str
    sink: str
    severity: Literal["low", "medium", "high", "critical"] = "high"
    provenance: SourceProvenance

    _validate_ids = field_validator("protected_effect_id", "principal_ref", "effect_ref", "resource_ref")(_id)


class BindingConstraint(BaseModel):
    binding_id: str
    kind: BindingKind
    left_ref: str
    right_ref: str
    relation: BindingRelation = "unknown"
    expression: str | None = None
    provenance: SourceProvenance

    _validate_ids = field_validator("binding_id", "left_ref", "right_ref")(_id)


class PathCondition(BaseModel):
    condition_id: str
    expression: str
    provenance: SourceProvenance

    _validate_id = field_validator("condition_id")(_id)


class SemanticPath(BaseModel):
    path_id: str
    entrypoint: str
    protected_effect_ref: str
    guard_refs: list[str] = Field(default_factory=list)
    condition_refs: list[str] = Field(default_factory=list)
    call_chain: list[str] = Field(default_factory=list)
    provenance: SourceProvenance

    _validate_ids = field_validator("path_id", "protected_effect_ref")(_id)


class AssuranceClaim(BaseModel):
    """Semantic claim candidate.

    Approval is intentionally absent. Repository/PR-controlled claim content
    cannot authorize itself; trusted approval is separate external evidence.
    """

    model_config = ConfigDict(extra="forbid")

    claim_id: str
    property_kind: str
    statement: str
    origin: ClaimOrigin
    semantic_refs: list[str] = Field(default_factory=list)
    acceptable_guarantees: list[str] = Field(default_factory=list)
    assumptions: list[str] = Field(default_factory=list)
    provenance: SourceProvenance

    _validate_id = field_validator("claim_id")(_id)


class AssuranceIR(BaseModel):
    schema_version: Literal["ovk.assurance_ir.v1"] = "ovk.assurance_ir.v1"
    subject: VerificationSubject
    principals: list[PrincipalRef] = Field(default_factory=list)
    resources: list[ResourceRef] = Field(default_factory=list)
    effects: list[EffectRef] = Field(default_factory=list)
    guards: list[AuthorizationGuard] = Field(default_factory=list)
    protected_effects: list[ProtectedEffect] = Field(default_factory=list)
    bindings: list[BindingConstraint] = Field(default_factory=list)
    path_conditions: list[PathCondition] = Field(default_factory=list)
    semantic_paths: list[SemanticPath] = Field(default_factory=list)
    claims: list[AssuranceClaim] = Field(default_factory=list)
    assumptions: list[str] = Field(default_factory=list)
    unknowns: list[str] = Field(default_factory=list)
    ir_digest: str | None = None

    @model_validator(mode="after")
    def references_are_closed(self) -> "AssuranceIR":
        typed = {
            "principal": {item.principal_id for item in self.principals},
            "resource": {item.resource_id for item in self.resources},
            "effect": {item.effect_id for item in self.effects},
        }
        id_lists = {
            "principal": [item.principal_id for item in self.principals],
            "resource": [item.resource_id for item in self.resources],
            "effect": [item.effect_id for item in self.effects],
            "guard": [item.guard_id for item in self.guards],
            "protected_effect": [item.protected_effect_id for item in self.protected_effects],
            "binding": [item.binding_id for item in self.bindings],
            "condition": [item.condition_id for item in self.path_conditions],
            "path": [item.path_id for item in self.semantic_paths],
            "claim": [item.claim_id for item in self.claims],
        }
        for kind, values in id_lists.items():
            duplicates = sorted({value for value in values if values.count(value) > 1})
            if duplicates:
                raise ValueError(f"duplicate {kind} ids: {', '.join(duplicates)}")

        guards = set(id_lists["guard"])
        protected = set(id_lists["protected_effect"])
        conditions = set(id_lists["condition"])

        for guard in self.guards:
            self._require(typed["principal"], guard.principal_ref, guard.guard_id, "principal")
            self._require(typed["effect"], guard.effect_ref, guard.guard_id, "effect")
            self._require(typed["resource"], guard.resource_ref, guard.guard_id, "resource")

        for item in self.protected_effects:
            self._require(typed["principal"], item.principal_ref, item.protected_effect_id, "principal")
            self._require(typed["effect"], item.effect_ref, item.protected_effect_id, "effect")
            self._require(typed["resource"], item.resource_ref, item.protected_effect_id, "resource")

        for binding in self.bindings:
            self._require(typed[binding.kind], binding.left_ref, binding.binding_id, binding.kind)
            self._require(typed[binding.kind], binding.right_ref, binding.binding_id, binding.kind)

        for path in self.semantic_paths:
            self._require(protected, path.protected_effect_ref, path.path_id, "protected effect")
            for ref in path.guard_refs:
                self._require(guards, ref, path.path_id, "guard")
            for ref in path.condition_refs:
                self._require(conditions, ref, path.path_id, "condition")

        all_ids = set().union(*[set(values) for values in id_lists.values()])
        for claim in self.claims:
            for ref in claim.semantic_refs:
                self._require(all_ids, ref, claim.claim_id, "semantic object")

        if self.ir_digest is not None and self.ir_digest != compute_assurance_ir_digest(self):
            raise ValueError("ir_digest does not match canonical Assurance IR contents")
        return self

    @staticmethod
    def _require(known: set[str], ref: str, owner: str, kind: str) -> None:
        if ref not in known:
            raise ValueError(f"{owner} references unknown {kind} {ref}")


def assurance_ir_digest_input(ir: AssuranceIR) -> dict[str, Any]:
    payload = ir.model_dump(mode="json", exclude={"ir_digest"})
    sort_keys = {
        "principals": "principal_id",
        "resources": "resource_id",
        "effects": "effect_id",
        "guards": "guard_id",
        "protected_effects": "protected_effect_id",
        "bindings": "binding_id",
        "path_conditions": "condition_id",
        "semantic_paths": "path_id",
        "claims": "claim_id",
    }
    for field, key in sort_keys.items():
        payload[field] = sorted(payload[field], key=lambda item: str(item[key]))
    payload["assumptions"] = sorted(payload["assumptions"])
    payload["unknowns"] = sorted(payload["unknowns"])
    return payload


def compute_assurance_ir_digest(ir: AssuranceIR) -> str:
    return content_digest(assurance_ir_digest_input(ir))


def seal_assurance_ir(ir: AssuranceIR) -> AssuranceIR:
    return ir.model_copy(update={"ir_digest": compute_assurance_ir_digest(ir)})
