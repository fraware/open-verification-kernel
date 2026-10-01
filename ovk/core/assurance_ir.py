"""Typed semantic interchange model for repository assurance.

The Assurance IR sits between source/profile extraction and verification-obligation
compilation. Constructing a valid IR does not establish any security property.
Extractors must record provenance, abstraction coverage, unsupported semantics,
and assumptions explicitly.

The IR records what an extractor claims about a repository revision. Soundness of
source-to-IR extraction is a separate obligation from soundness of any verifier
that consumes the IR.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator

from ovk.core.bundle import content_digest
from ovk.core.models import SourceRange, VerificationSubject
from ovk.core.resource_identity import (
    ResourceIdentityTerm,
    ResourceInterpretation,
)


CoverageStatus = Literal["complete", "partial", "unknown", "inapplicable"]
AuthorizationCutSetCoverageStatus = Literal["complete", "partial", "unknown"]
GuardEffectiveness = Literal["established", "unproved"]
ValueOriginKind = Literal[
    "externally_bound_http_value",
    "server_configuration",
    "literal_constant",
    "derived_value",
    "request_state_attribute",
    "unknown_origin",
]
BypassAuthorityEvidenceStatus = Literal["established", "violated", "unknown"]
HelperEffectivenessStatus = Literal["established", "unproved"]
GuardEffectivenessEvidenceKind = Literal[
    "fail_closed_bearer_match_v1",
    "fail_closed_header_shared_secret_v1",
    "fail_closed_apikeyheader_shared_secret_v1",
]
GuardEffectivenessComparisonKind = Literal[
    "direct_inequality",
    "secrets_compare_digest",
    "hmac_compare_digest",
]
InterpretationCompatibilityRelation = Literal[
    "equal_on_acted_domain",
]
InterpretationCompatibilityEvidenceKind = Literal[
    "interpretation_contract_v1",
]
BindingRelation = Literal["equal", "same_tenant", "custom"]
BindingProjection = Literal["identity", "scope", "attribute"]
ContractTermKind = Literal["parameter", "return_attribute", "literal"]
ContractRelation = Literal["eq", "non_null"]
ContractDerivation = Literal["direct", "composed"]
ClaimKind = Literal[
    "protected_effect_integrity",
    "authorization",
    "tenant_isolation",
    "state_invariant",
    "information_flow",
    "custom",
]


class SemanticOrigin(BaseModel):
    """Source provenance for one semantic fact."""

    path: str
    extractor_id: str
    extractor_version: str
    source_range: SourceRange | None = None
    material_digest: str | None = None

    @field_validator("path", "extractor_id", "extractor_version")
    @classmethod
    def _non_empty(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("semantic provenance fields must be non-empty")
        return value


class PrincipalRef(BaseModel):
    """Symbolic principal derived from source or approved repository intent."""

    principal_id: str
    symbol: str
    principal_type: str | None = None
    origin: SemanticOrigin | None = None


class ResourceRef(BaseModel):
    """Symbolic resource whose identity may participate in proof obligations."""

    resource_id: str
    symbol: str
    resource_type: str | None = None
    tenant_symbol: str | None = None
    identity_term: ResourceIdentityTerm | None = None
    scope_term: ResourceIdentityTerm | None = None
    attribute_terms: dict[str, ResourceIdentityTerm] = Field(default_factory=dict)
    origin: SemanticOrigin | None = None


class EffectRef(BaseModel):
    """Open namespaced effect such as billing.invoice.refund."""

    effect_id: str
    name: str
    origin: SemanticOrigin | None = None

    @field_validator("name")
    @classmethod
    def _effect_name_non_empty(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("effect name must be non-empty")
        return value


class PathCondition(BaseModel):
    """A source-grounded predicate constraining a semantic path."""

    condition_id: str
    expression: str
    origin: SemanticOrigin | None = None

    @field_validator("expression")
    @classmethod
    def _expression_non_empty(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("path condition expression must be non-empty")
        return value


class AuthorizationGuard(BaseModel):
    """Candidate authorization decision observed on an execution path.

    effectiveness distinguishes source-grounded mediation from a proved
    authorization decision. Existing extractors default to established only
    where their source profile already validates the guard semantics.
    """

    guard_id: str
    principal_id: str
    effect_id: str
    resource_id: str
    effectiveness: GuardEffectiveness = "established"
    effectiveness_evidence_ids: list[str] = Field(default_factory=list)
    condition_ids: list[str] = Field(default_factory=list)
    origin: SemanticOrigin


class GuardEffectivenessEvidence(BaseModel):
    """Source-derived evidence that a candidate authorization guard fails closed."""

    evidence_id: str
    dependency_name: str
    evidence_kind: GuardEffectivenessEvidenceKind
    credential_parameter: str
    credential_attribute: str | None = None
    token_expression: str
    comparison_kind: GuardEffectivenessComparisonKind = "direct_inequality"
    assumptions: list[str] = Field(default_factory=list)
    origin: SemanticOrigin

    @field_validator(
        "evidence_id",
        "dependency_name",
        "credential_parameter",
        "token_expression",
    )
    @classmethod
    def _effectiveness_fields_non_empty(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError(
                "guard-effectiveness evidence fields must be non-empty"
            )
        return value

    @model_validator(mode="after")
    def _effectiveness_evidence_shape(self) -> "GuardEffectivenessEvidence":
        if self.evidence_kind == "fail_closed_bearer_match_v1":
            if (
                self.credential_attribute is None
                or not self.credential_attribute.strip()
            ):
                raise ValueError(
                    "bearer effectiveness evidence requires credential_attribute"
                )
            if self.comparison_kind != "direct_inequality":
                raise ValueError(
                    "bearer effectiveness evidence requires direct_inequality"
                )
        elif self.evidence_kind == "fail_closed_header_shared_secret_v1":
            if self.credential_attribute is not None:
                raise ValueError(
                    "header shared-secret evidence has no credential_attribute"
                )
            if self.comparison_kind != "secrets_compare_digest":
                raise ValueError(
                    "header shared-secret evidence requires secrets_compare_digest"
                )
        elif self.evidence_kind == "fail_closed_apikeyheader_shared_secret_v1":
            if self.credential_attribute is not None:
                raise ValueError(
                    "APIKeyHeader shared-secret evidence has no credential_attribute"
                )
            if self.comparison_kind != "hmac_compare_digest":
                raise ValueError(
                    "APIKeyHeader shared-secret evidence requires hmac_compare_digest"
                )
        return self


class InterpretationCompatibilityEvidence(BaseModel):
    """Evidence that authorization agrees with execution where execution proceeds.

    equal_on_acted_domain is directional. For every raw input accepted by
    the acted/execution interpretation, the authorized interpretation must
    accept that same input and produce the same semantic resource value.
    Authorization may accept additional inputs because those inputs do not
    reach the acted resource under this relation.

    Constructing this object does not itself prove the relation. evidence_kind
    identifies the independently checked contract that established it.
    """

    evidence_id: str
    authorized_interpretation: ResourceInterpretation
    acted_interpretation: ResourceInterpretation
    relation: InterpretationCompatibilityRelation = "equal_on_acted_domain"
    evidence_kind: InterpretationCompatibilityEvidenceKind
    assumptions: list[str] = Field(default_factory=list)
    origin: SemanticOrigin

    @field_validator("evidence_id")
    @classmethod
    def _compatibility_id_non_empty(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError(
                "interpretation compatibility evidence_id must be non-empty"
            )
        return value

    @model_validator(mode="after")
    def _compatibility_shape(self) -> "InterpretationCompatibilityEvidence":
        if (
            self.authorized_interpretation.input_origin
            != self.acted_interpretation.input_origin
        ):
            raise ValueError(
                "interpretation compatibility requires the same input_origin"
            )
        return self


class GuardDominanceEvidence(BaseModel):
    """Why an authorization guard is concluded to precede a protected effect.

    dominates is true only when the guard CFG node dominates the effect CFG
    node under a complete sink-reaching coverage region. Incomplete CFG
    coverage or ambiguous source-range binding must not yield a true PASS.
    """

    evidence_id: str
    guard_id: str
    protected_effect_id: str
    entrypoint: str
    guard_cfg_node_id: str | None = None
    effect_cfg_node_id: str | None = None
    control_flow_summary_digest: str | None = None
    dominates: bool = False
    coverage_status: CoverageStatus = "unknown"
    origin: SemanticOrigin

    @field_validator(
        "evidence_id",
        "guard_id",
        "protected_effect_id",
        "entrypoint",
    )
    @classmethod
    def _dominance_fields_non_empty(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("guard-dominance evidence fields must be non-empty")
        return value


class AuthorizationControlPointEvidence(BaseModel):
    """Explicit security identity for one authorizing control-flow point.

    Raw handler-local edge strings are not security identities. An authorizing
    cut member must bind guard, protected effect, principal/effect/resource,
    CFG digest, entrypoint, and the local edge endpoints together. Each control
    point also binds the exact underlying bypass-authority evidence id (#154).
    """

    evidence_id: str
    guard_id: str
    protected_effect_id: str
    principal_id: str
    effect_id: str
    resource_id: str
    entrypoint: str
    control_flow_summary_digest: str
    edge_id: str
    scoped_edge_id: str
    bypass_evidence_id: str
    origin: SemanticOrigin

    @field_validator(
        "evidence_id",
        "guard_id",
        "protected_effect_id",
        "principal_id",
        "effect_id",
        "resource_id",
        "entrypoint",
        "control_flow_summary_digest",
        "edge_id",
        "scoped_edge_id",
        "bypass_evidence_id",
    )
    @classmethod
    def _control_point_fields_non_empty(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError(
                "authorization control-point evidence fields must be non-empty"
            )
        return value

    @model_validator(mode="after")
    def _scoped_edge_matches_components(self) -> "AuthorizationControlPointEvidence":
        from ovk.compilers.authorization.handler_control_flow import (
            scoped_control_flow_edge_id_from_local,
        )

        expected = scoped_control_flow_edge_id_from_local(
            control_flow_summary_digest=self.control_flow_summary_digest,
            entrypoint=self.entrypoint,
            local_edge_id=self.edge_id,
        )
        if self.scoped_edge_id != expected:
            raise ValueError(
                "scoped_edge_id must equal ScopedEdge(CFG digest, entrypoint, local edge)"
            )
        return self


class AuthorizationCutSetEvidence(BaseModel):
    """Structural evidence that control points intercept sink-reaching paths.

    This object records graph coverage only. Membership in guard_ids,
    node_control_points, or edge_control_points does not establish
    authorization effectiveness or principal/effect/resource binding. Those
    remain separate verification obligations.

    node_control_points and edge_control_points are the generic control-flow
    vocabulary for cut members. guard_ids / guard_cfg_node_ids remain the
    guard-bound view of node cuts when candidates originate as authorization
    guards.

    unresolved_guard_ids records body cut candidates whose source-to-CFG binding
    was ambiguous or missing. Any unresolved candidate forces unknown coverage;
    the resolved subset alone must not emit a complete uncovered-path refutation.
    """

    evidence_id: str
    protected_effect_id: str
    entrypoint: str
    guard_ids: list[str] = Field(default_factory=list)
    guard_cfg_node_ids: dict[str, str] = Field(default_factory=dict)
    unresolved_guard_ids: list[str] = Field(default_factory=list)
    node_control_points: list[str] = Field(default_factory=list)
    edge_control_points: list[str] = Field(default_factory=list)
    entry_cfg_node_id: str | None = None
    effect_cfg_node_id: str | None = None
    control_flow_summary_digest: str | None = None
    covers_all_paths: bool = False
    coverage_status: AuthorizationCutSetCoverageStatus = "unknown"
    uncovered_path_node_ids: list[str] = Field(default_factory=list)
    reason: str
    origin: SemanticOrigin

    @field_validator(
        "evidence_id",
        "protected_effect_id",
        "entrypoint",
        "reason",
    )
    @classmethod
    def _cut_set_fields_non_empty(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("authorization cut-set evidence fields must be non-empty")
        return value

    @field_validator(
        "entry_cfg_node_id",
        "effect_cfg_node_id",
        "control_flow_summary_digest",
    )
    @classmethod
    def _cut_set_optional_fields_non_empty(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        if not value:
            raise ValueError("authorization cut-set evidence fields must be non-empty")
        return value

    @model_validator(mode="after")
    def _cut_set_shape(self) -> "AuthorizationCutSetEvidence":
        if len(set(self.guard_ids)) != len(self.guard_ids):
            raise ValueError("authorization cut-set guard_ids must be unique")
        if len(set(self.unresolved_guard_ids)) != len(self.unresolved_guard_ids):
            raise ValueError(
                "authorization cut-set unresolved_guard_ids must be unique"
            )
        if len(set(self.node_control_points)) != len(self.node_control_points):
            raise ValueError(
                "authorization cut-set node_control_points must be unique"
            )
        if len(set(self.edge_control_points)) != len(self.edge_control_points):
            raise ValueError(
                "authorization cut-set edge_control_points must be unique"
            )
        if set(self.guard_ids) & set(self.unresolved_guard_ids):
            raise ValueError(
                "authorization cut-set guard_ids and unresolved_guard_ids must be disjoint"
            )
        if set(self.guard_cfg_node_ids) != set(self.guard_ids):
            raise ValueError(
                "authorization cut-set guard node map must match guard_ids"
            )
        if any(not guard_id.strip() for guard_id in self.guard_ids):
            raise ValueError("authorization cut-set guard ids must be non-empty")
        if any(not guard_id.strip() for guard_id in self.unresolved_guard_ids):
            raise ValueError(
                "authorization cut-set unresolved guard ids must be non-empty"
            )
        if any(not node_id.strip() for node_id in self.node_control_points):
            raise ValueError(
                "authorization cut-set node control points must be non-empty"
            )
        if any(not edge_id.strip() for edge_id in self.edge_control_points):
            raise ValueError(
                "authorization cut-set edge control points must be non-empty"
            )
        if any(
            not node_id.strip()
            for node_id in self.guard_cfg_node_ids.values()
        ):
            raise ValueError(
                "authorization cut-set guard CFG node ids must be non-empty"
            )
        if self.unresolved_guard_ids:
            if self.covers_all_paths:
                raise ValueError(
                    "positive authorization cut-set evidence cannot leave guards unresolved"
                )
            if self.coverage_status != "unknown":
                raise ValueError(
                    "unresolved authorization cut-set candidates require unknown coverage"
                )
            if self.uncovered_path_node_ids:
                raise ValueError(
                    "unresolved authorization cut-set candidates cannot carry an uncovered path"
                )
        if self.covers_all_paths or self.coverage_status == "complete":
            if self.unresolved_guard_ids:
                raise ValueError(
                    "complete authorization cut-set evidence cannot leave guards unresolved"
                )
            if (
                self.entry_cfg_node_id is None
                or self.effect_cfg_node_id is None
                or self.control_flow_summary_digest is None
            ):
                raise ValueError(
                    "complete authorization cut-set evidence requires CFG endpoints and digest"
                )
        cut_nodes = set(self.node_control_points)
        if not cut_nodes and not self.edge_control_points:
            # Legacy node-only evidence records cuts only via guard_cfg_node_ids.
            cut_nodes = set(self.guard_cfg_node_ids.values())
        binding_nodes = set(self.guard_cfg_node_ids.values())
        if (
            self.entry_cfg_node_id is not None
            and self.entry_cfg_node_id in (cut_nodes | binding_nodes)
            and self.entry_cfg_node_id in cut_nodes
        ):
            raise ValueError(
                "authorization cut-set cannot use the entry node as a guard"
            )
        if (
            self.effect_cfg_node_id is not None
            and self.effect_cfg_node_id in cut_nodes
        ):
            raise ValueError(
                "authorization cut-set cannot use the effect node as a guard"
            )
        if (
            self.entry_cfg_node_id is not None
            and self.effect_cfg_node_id is not None
            and self.entry_cfg_node_id == self.effect_cfg_node_id
        ):
            raise ValueError(
                "authorization cut-set entry and effect nodes must differ"
            )
        if self.uncovered_path_node_ids:
            if (
                self.entry_cfg_node_id is None
                or self.effect_cfg_node_id is None
                or self.uncovered_path_node_ids[0] != self.entry_cfg_node_id
                or self.uncovered_path_node_ids[-1] != self.effect_cfg_node_id
            ):
                raise ValueError(
                    "authorization cut-set uncovered path must connect entry to effect"
                )
            if cut_nodes & set(self.uncovered_path_node_ids):
                raise ValueError(
                    "authorization cut-set uncovered path must avoid guard nodes"
                )
        if self.covers_all_paths:
            if self.coverage_status != "complete":
                raise ValueError(
                    "positive authorization cut-set evidence requires complete coverage"
                )
            if not (
                self.guard_ids
                or self.node_control_points
                or self.edge_control_points
            ):
                raise ValueError(
                    "positive authorization cut-set evidence requires control points"
                )
            if self.uncovered_path_node_ids:
                raise ValueError(
                    "positive authorization cut-set evidence cannot carry an uncovered path"
                )
        elif (
            self.coverage_status == "complete"
            and not self.uncovered_path_node_ids
        ):
            raise ValueError(
                "complete negative authorization cut-set evidence requires an uncovered path"
            )
        return self


class ValueOriginEvidence(BaseModel):
    """Evidence-bearing classification of where a runtime value came from.

    This is not a trusted/untrusted Boolean and does not authorize bypasses.
    """

    evidence_id: str
    value_id: str
    origin_kind: ValueOriginKind
    source_expression: str
    dependencies: list[str] = Field(default_factory=list)
    origin: SemanticOrigin

    @field_validator("evidence_id", "value_id", "source_expression")
    @classmethod
    def _origin_fields_non_empty(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("value-origin evidence fields must be non-empty")
        return value


class HelperEffectivenessEvidence(BaseModel):
    """First-class body-helper implementation evidence for Assurance IR (#152).

    Records the resolved callee identity and digests. Status remains unproved
    until a machine-checkable authorization predicate is modeled; digests exist
    so incremental fragments cannot stale-reuse across helper body changes.
    """

    evidence_id: str
    helper_name: str
    qualified_symbol: str
    definition_path: str
    definition_line: int
    source_digest: str
    implementation_digest: str
    status: HelperEffectivenessStatus = "unproved"
    reason: str
    origin: SemanticOrigin

    @field_validator(
        "evidence_id",
        "helper_name",
        "qualified_symbol",
        "definition_path",
        "source_digest",
        "implementation_digest",
        "reason",
    )
    @classmethod
    def _helper_fields_non_empty(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("helper-effectiveness evidence fields must be non-empty")
        return value

    @field_validator("definition_line")
    @classmethod
    def _helper_line_non_negative(cls, value: int) -> int:
        if value < 0:
            raise ValueError("helper definition_line must be non-negative")
        return value


class BypassAuthorityEvidence(BaseModel):
    """Durable evidence for a source-grounded bypass authorization mechanism.

    Status alone does not authorize a Protected Effect. Authorization requires
    governed profile mapping, proved writers, and a bound branch-outcome
    control point. Field names never imply security meaning.

    ``control_point_edge_id`` is the handler-local CFG edge id used by the
    cut-set graph theorem. Cross-handler security matching must use
    ``AuthorizationControlPointEvidence`` (CFG digest + entrypoint + binding).
    """

    evidence_id: str
    field_name: str
    read_expression: str
    read_origin: SemanticOrigin
    status: BypassAuthorityEvidenceStatus = "unknown"
    control_point_edge_id: str | None = None
    control_flow_summary_digest: str | None = None
    entrypoint: str | None = None
    writer_evidence_ids: list[str] = Field(default_factory=list)
    closed_world_scope_digest: str | None = None
    assumptions: list[str] = Field(default_factory=list)
    reason: str
    origin: SemanticOrigin

    @field_validator(
        "evidence_id",
        "field_name",
        "read_expression",
        "reason",
    )
    @classmethod
    def _bypass_fields_non_empty(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("bypass-authority evidence fields must be non-empty")
        return value

    @field_validator(
        "control_point_edge_id",
        "closed_world_scope_digest",
        "control_flow_summary_digest",
        "entrypoint",
    )
    @classmethod
    def _bypass_optional_non_empty(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        if not value:
            raise ValueError("bypass-authority evidence fields must be non-empty")
        return value

    @model_validator(mode="after")
    def _bypass_shape(self) -> "BypassAuthorityEvidence":
        if len(set(self.writer_evidence_ids)) != len(self.writer_evidence_ids):
            raise ValueError("bypass-authority writer_evidence_ids must be unique")
        if any(not item.strip() for item in self.writer_evidence_ids):
            raise ValueError("bypass-authority writer_evidence_ids must be non-empty")
        if any(not item.strip() for item in self.assumptions):
            raise ValueError("bypass-authority assumptions must be non-empty")
        if self.status == "established":
            if self.control_point_edge_id is None:
                raise ValueError(
                    "established bypass-authority evidence requires a control-point edge"
                )
            if self.control_flow_summary_digest is None:
                raise ValueError(
                    "established bypass-authority evidence requires a CFG digest"
                )
            if self.entrypoint is None:
                raise ValueError(
                    "established bypass-authority evidence requires an entrypoint"
                )
            if not self.writer_evidence_ids:
                raise ValueError(
                    "established bypass-authority evidence requires writer evidence"
                )
            if self.closed_world_scope_digest is None:
                raise ValueError(
                    "established bypass-authority evidence requires a closed-world digest"
                )
        return self


class ProtectedEffect(BaseModel):
    """Security-sensitive effect whose execution requires assurance."""

    protected_effect_id: str
    principal_id: str
    effect_id: str
    resource_id: str
    condition_ids: list[str] = Field(default_factory=list)
    origin: SemanticOrigin


class ContractTerm(BaseModel):
    """Serializable term used in interprocedural pre/postconditions."""

    kind: ContractTermKind
    name: str | None = None
    value: str | None = None

    @model_validator(mode="after")
    def _shape_is_valid(self) -> "ContractTerm":
        if self.kind in {"parameter", "return_attribute"}:
            if self.name is None or not self.name.strip():
                raise ValueError(f"{self.kind} contract term requires name")
            if self.value is not None:
                raise ValueError(f"{self.kind} contract term does not accept value")
        elif self.kind == "literal":
            if self.value is None:
                raise ValueError("literal contract term requires value")
            if self.name is not None:
                raise ValueError("literal contract term does not accept name")
        return self

    @classmethod
    def parameter(cls, name: str) -> "ContractTerm":
        return cls(kind="parameter", name=name)

    @classmethod
    def return_attribute(cls, name: str) -> "ContractTerm":
        return cls(kind="return_attribute", name=name)

    @classmethod
    def literal(cls, value: str) -> "ContractTerm":
        return cls(kind="literal", value=value)


class ContractPredicate(BaseModel):
    """Decidable predicate in the v1 interprocedural contract language."""

    relation: ContractRelation
    left: ContractTerm
    right: ContractTerm | None = None

    @model_validator(mode="after")
    def _predicate_shape(self) -> "ContractPredicate":
        if self.relation == "non_null":
            if self.right is not None:
                raise ValueError("non_null predicate is unary")
            if self.left.kind != "parameter":
                raise ValueError("v1 non_null predicate requires a parameter term")
        elif self.relation == "eq":
            if self.right is None:
                raise ValueError("eq predicate requires right term")
        return self


class FunctionContract(BaseModel):
    """Named, source-grounded pre/post contract for a callable."""

    contract_id: str
    qualified_name: str
    derivation: ContractDerivation = "direct"
    depends_on: list[str] = Field(default_factory=list)
    positional_parameters: list[str] = Field(default_factory=list)
    preconditions: list[ContractPredicate] = Field(default_factory=list)
    postconditions: list[ContractPredicate] = Field(default_factory=list)
    origin: SemanticOrigin

    @field_validator("qualified_name")
    @classmethod
    def _qualified_name_non_empty(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("function contract qualified_name must be non-empty")
        return value


class ContractUse(BaseModel):
    """One source-grounded consumption of a FunctionContract."""

    use_id: str
    contract_id: str
    qualified_name: str
    resource_id: str
    established_attributes: list[str] = Field(default_factory=list)
    origin: SemanticOrigin

    @field_validator("use_id", "contract_id", "qualified_name", "resource_id")
    @classmethod
    def _contract_use_fields_non_empty(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("contract use fields must be non-empty")
        return value


class ResourceReturnContract(BaseModel):
    """Source-derived postcondition for a function returning a resource."""

    contract_id: str
    qualified_name: str
    return_scope_parameter: str
    return_scope_attribute: str
    requires_non_null_argument: bool = True
    origin: SemanticOrigin

    @field_validator("qualified_name", "return_scope_parameter", "return_scope_attribute")
    @classmethod
    def _contract_fields_non_empty(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("resource return contract fields must be non-empty")
        return value


class ResourceBinding(BaseModel):
    """Required relationship between authorized and acted-upon resources."""

    binding_id: str
    authorized_resource_id: str
    acted_resource_id: str
    relation: BindingRelation = "equal"
    authorized_projection: BindingProjection = "identity"
    acted_projection: BindingProjection = "identity"
    authorized_attribute: str | None = None
    acted_attribute: str | None = None
    predicate: str | None = None
    condition_ids: list[str] = Field(default_factory=list)
    origin: SemanticOrigin

    @model_validator(mode="after")
    def _binding_shape(self) -> "ResourceBinding":
        if self.relation == "custom" and (self.predicate is None or not self.predicate.strip()):
            raise ValueError("custom resource binding requires predicate")
        if self.authorized_projection == "attribute":
            if self.authorized_attribute is None or not self.authorized_attribute.strip():
                raise ValueError("authorized attribute projection requires authorized_attribute")
        elif self.authorized_attribute is not None:
            raise ValueError("authorized_attribute requires attribute projection")
        if self.acted_projection == "attribute":
            if self.acted_attribute is None or not self.acted_attribute.strip():
                raise ValueError("acted attribute projection requires acted_attribute")
        elif self.acted_attribute is not None:
            raise ValueError("acted_attribute requires attribute projection")
        return self


class SemanticPath(BaseModel):
    """One source-grounded path from entrypoint toward protected behavior."""

    path_id: str
    entrypoint: str
    guard_ids: list[str] = Field(default_factory=list)
    protected_effect_ids: list[str] = Field(default_factory=list)
    binding_ids: list[str] = Field(default_factory=list)
    contract_use_ids: list[str] = Field(default_factory=list)
    condition_ids: list[str] = Field(default_factory=list)
    coverage_status: CoverageStatus | None = None
    unsupported_constructs: list[str] = Field(default_factory=list)
    coverage_assumptions: list[str] = Field(default_factory=list)
    origin: SemanticOrigin | None = None


class AssuranceClaim(BaseModel):
    """Durable semantic claim to be compiled into verification obligations later."""

    claim_id: str
    claim_kind: ClaimKind
    statement: str
    subject_ids: list[str] = Field(default_factory=list)
    assumption_ids: list[str] = Field(default_factory=list)
    acceptable_guarantees: list[str] = Field(default_factory=list)
    origin: SemanticOrigin | None = None

    @field_validator("statement")
    @classmethod
    def _statement_non_empty(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("assurance claim statement must be non-empty")
        return value


class AssuranceCoverage(BaseModel):
    """Extractor coverage over the source profile represented by this IR."""

    status: CoverageStatus
    confidence: float = Field(ge=0.0, le=1.0)
    supported_constructs: list[str] = Field(default_factory=list)
    unsupported_constructs: list[str] = Field(default_factory=list)
    assumptions: list[str] = Field(default_factory=list)


class AssuranceExtractorIdentity(BaseModel):
    extractor_id: str
    extractor_version: str
    source_profile_id: str | None = None


class AssuranceIR(BaseModel):
    """Canonical semantic interchange object for a repository revision."""

    schema_version: Literal["ovk.assurance_ir.v1"] = "ovk.assurance_ir.v1"
    subject: VerificationSubject
    extractor: AssuranceExtractorIdentity
    coverage: AssuranceCoverage

    principals: list[PrincipalRef] = Field(default_factory=list)
    resources: list[ResourceRef] = Field(default_factory=list)
    effects: list[EffectRef] = Field(default_factory=list)
    conditions: list[PathCondition] = Field(default_factory=list)
    guards: list[AuthorizationGuard] = Field(default_factory=list)
    guard_effectiveness_evidence: list[GuardEffectivenessEvidence] = Field(
        default_factory=list
    )
    interpretation_compatibility_evidence: list[
        InterpretationCompatibilityEvidence
    ] = Field(default_factory=list)
    guard_dominance_evidence: list[GuardDominanceEvidence] = Field(
        default_factory=list
    )
    authorization_cut_set_evidence: list[AuthorizationCutSetEvidence] = Field(
        default_factory=list
    )
    authorization_control_point_evidence: list[
        AuthorizationControlPointEvidence
    ] = Field(default_factory=list)
    value_origin_evidence: list[ValueOriginEvidence] = Field(
        default_factory=list
    )
    bypass_authority_evidence: list[BypassAuthorityEvidence] = Field(
        default_factory=list
    )
    helper_effectiveness_evidence: list[HelperEffectivenessEvidence] = Field(
        default_factory=list
    )
    protected_effects: list[ProtectedEffect] = Field(default_factory=list)
    resource_bindings: list[ResourceBinding] = Field(default_factory=list)
    resource_return_contracts: list[ResourceReturnContract] = Field(default_factory=list)
    function_contracts: list[FunctionContract] = Field(default_factory=list)
    contract_uses: list[ContractUse] = Field(default_factory=list)
    paths: list[SemanticPath] = Field(default_factory=list)
    claims: list[AssuranceClaim] = Field(default_factory=list)
    assumptions: dict[str, str] = Field(default_factory=dict)

    def canonical_payload(self) -> dict:
        """Return order-stable JSON payload for identity and evidence binding."""

        payload = self.model_dump(mode="json")
        collection_keys = {
            "principals": "principal_id",
            "resources": "resource_id",
            "effects": "effect_id",
            "conditions": "condition_id",
            "guards": "guard_id",
            "guard_effectiveness_evidence": "evidence_id",
            "interpretation_compatibility_evidence": "evidence_id",
            "guard_dominance_evidence": "evidence_id",
            "authorization_cut_set_evidence": "evidence_id",
            "authorization_control_point_evidence": "evidence_id",
            "value_origin_evidence": "evidence_id",
            "bypass_authority_evidence": "evidence_id",
            "helper_effectiveness_evidence": "evidence_id",
            "protected_effects": "protected_effect_id",
            "resource_bindings": "binding_id",
            "resource_return_contracts": "contract_id",
            "function_contracts": "contract_id",
            "contract_uses": "use_id",
            "paths": "path_id",
            "claims": "claim_id",
        }
        for field_name, identity_key in collection_keys.items():
            payload[field_name] = sorted(payload[field_name], key=lambda item: item[identity_key])

        resources_by_id = {
            resource.resource_id: resource
            for resource in self.resources
        }
        for item in payload["resources"]:
            resource = resources_by_id[item["resource_id"]]
            if resource.identity_term is not None:
                item["identity_term"] = resource.identity_term.canonical_payload()
            if resource.scope_term is not None:
                item["scope_term"] = resource.scope_term.canonical_payload()
            item["attribute_terms"] = {
                name: term.canonical_payload()
                for name, term in sorted(resource.attribute_terms.items())
            }

        payload["coverage"]["supported_constructs"] = sorted(payload["coverage"]["supported_constructs"])
        payload["coverage"]["unsupported_constructs"] = sorted(payload["coverage"]["unsupported_constructs"])
        payload["coverage"]["assumptions"] = sorted(payload["coverage"]["assumptions"])

        for field_name in ("guards", "protected_effects", "resource_bindings", "paths"):
            for item in payload[field_name]:
                if "condition_ids" in item:
                    item["condition_ids"] = sorted(item["condition_ids"])
                if "effectiveness_evidence_ids" in item:
                    item["effectiveness_evidence_ids"] = sorted(
                        item["effectiveness_evidence_ids"]
                    )

        for item in payload["guard_effectiveness_evidence"]:
            item["assumptions"] = sorted(item["assumptions"])

        for item in payload["interpretation_compatibility_evidence"]:
            item["assumptions"] = sorted(item["assumptions"])

        for item in payload["bypass_authority_evidence"]:
            item["writer_evidence_ids"] = sorted(item["writer_evidence_ids"])
            item["assumptions"] = sorted(item["assumptions"])

        for item in payload["authorization_cut_set_evidence"]:
            item["guard_ids"] = sorted(item["guard_ids"])
            item["unresolved_guard_ids"] = sorted(item["unresolved_guard_ids"])
            item["guard_cfg_node_ids"] = dict(
                sorted(item["guard_cfg_node_ids"].items())
            )
            item["node_control_points"] = sorted(item["node_control_points"])
            item["edge_control_points"] = sorted(item["edge_control_points"])
            if not item["node_control_points"]:
                item.pop("node_control_points", None)
            if not item["edge_control_points"]:
                item.pop("edge_control_points", None)

        for item in payload["paths"]:
            item["guard_ids"] = sorted(item["guard_ids"])
            item["protected_effect_ids"] = sorted(item["protected_effect_ids"])
            item["binding_ids"] = sorted(item["binding_ids"])
            item["contract_use_ids"] = sorted(item["contract_use_ids"])
            item["unsupported_constructs"] = sorted(item["unsupported_constructs"])
            item["coverage_assumptions"] = sorted(item["coverage_assumptions"])

        for item in payload["function_contracts"]:
            item["depends_on"] = sorted(item["depends_on"])
            item["preconditions"] = sorted(
                item["preconditions"],
                key=lambda pred: content_digest(pred),
            )
            item["postconditions"] = sorted(
                item["postconditions"],
                key=lambda pred: content_digest(pred),
            )

        for item in payload["contract_uses"]:
            item["established_attributes"] = sorted(item["established_attributes"])

        for item in payload["claims"]:
            item["subject_ids"] = sorted(item["subject_ids"])
            item["assumption_ids"] = sorted(item["assumption_ids"])
            item["acceptable_guarantees"] = sorted(item["acceptable_guarantees"])

        payload["assumptions"] = dict(sorted(payload["assumptions"].items()))

        # Preserve v1 content identity for IRs that do not use the additive
        # interpretation-compatibility evidence extension.
        if not self.interpretation_compatibility_evidence:
            payload.pop("interpretation_compatibility_evidence", None)
        # Preserve prior identity when no CFG dominance evidence is present.
        if not self.guard_dominance_evidence:
            payload.pop("guard_dominance_evidence", None)
        if not self.authorization_cut_set_evidence:
            payload.pop("authorization_cut_set_evidence", None)
        if not self.authorization_control_point_evidence:
            payload.pop("authorization_control_point_evidence", None)
        if not self.value_origin_evidence:
            payload.pop("value_origin_evidence", None)
        if not self.bypass_authority_evidence:
            payload.pop("bypass_authority_evidence", None)
        if not self.helper_effectiveness_evidence:
            payload.pop("helper_effectiveness_evidence", None)
        return payload

    @property
    def assurance_ir_digest(self) -> str:
        """Content identity for this normalized semantic model."""

        return content_digest(self.canonical_payload())


def compute_assurance_ir_digest(ir: AssuranceIR | dict) -> str:
    """Compute the v1 Assurance IR content digest."""

    parsed = ir if isinstance(ir, AssuranceIR) else AssuranceIR.model_validate(ir)
    return parsed.assurance_ir_digest
