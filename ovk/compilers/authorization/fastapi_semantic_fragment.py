"""Bind one cached FastAPI route syntax summary into semantic IR fragments.

The binder is profile-aware and contract-version-aware, while RouteFileSummary is
profile-independent. This separation permits safe reuse of unchanged syntax
summaries and, later, already-bound semantic fragments when their dependencies
remain identical.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Any, Mapping

from ovk.compilers.authorization.material_loader import AuthMaterials
from ovk.compilers.authorization.body_helper_contracts import (
    analyze_body_helper_implementation,
    helper_name_locally_rebound_in_handler,
)
from ovk.compilers.authorization.fastapi_route_summary import (
    CallSummary,
    ExpressionSummary,
    RouteDependencySummary,
    RouteFileSummary,
    RouteHandlerSummary,
)
from ovk.compilers.authorization.authorization_cut_set import (
    build_authorization_cut_set_evidence,
)
from ovk.compilers.authorization.guard_cfg_dominance import (
    build_guard_dominance_evidence,
)
from ovk.compilers.authorization.handler_control_flow import (
    coverage_authoritative_for,
    find_nodes_covering_line,
)
from ovk.core.assurance_ir import (
    AssuranceCoverage,
    AssuranceExtractorIdentity,
    AssuranceIR,
    AuthorizationCutSetEvidence,
    AuthorizationGuard,
    ContractUse,
    EffectRef,
    FunctionContract,
    GuardDominanceEvidence,
    GuardEffectivenessEvidence,
    HelperEffectivenessEvidence,
    PrincipalRef,
    ProtectedEffect,
    ResourceBinding,
    ResourceRef,
    ResourceReturnContract,
    SemanticOrigin,
    SemanticPath,
    ValueOriginEvidence,
)
from ovk.core.bundle import content_digest
from ovk.core.models import VerificationSubject
from ovk.core.resource_identity import ResourceIdentityTerm


def _semantic_id(prefix: str, value: str) -> str:
    return f"{prefix}:{content_digest(value)[:16]}"


def _typed_contract_projection(
    contract: FunctionContract,
    return_attribute: str,
):
    matches = []
    for predicate in contract.postconditions:
        if (
            predicate.relation == "eq"
            and predicate.right is not None
            and predicate.left.kind == "return_attribute"
            and predicate.left.name == return_attribute
            and predicate.right.kind in {"parameter", "literal"}
            and (
                (
                    predicate.right.kind == "parameter"
                    and predicate.right.name is not None
                )
                or (
                    predicate.right.kind == "literal"
                    and predicate.right.value is not None
                )
            )
        ):
            matches.append(predicate)
    return matches[0] if len(matches) == 1 else None


def _requires_non_null_parameter(
    contract: FunctionContract,
    parameter_name: str,
) -> bool:
    return any(
        predicate.relation == "non_null"
        and predicate.left.kind == "parameter"
        and predicate.left.name == parameter_name
        for predicate in contract.preconditions
    )


def _actual_argument(
    call: CallSummary,
    *,
    parameter_name: str,
    positional_parameters: list[str],
):
    keyword = call.keyword(parameter_name)
    if keyword is not None:
        return keyword
    if parameter_name not in positional_parameters:
        return None
    index = positional_parameters.index(parameter_name)
    if len(call.positional_arguments) <= index:
        return None
    return call.positional_arguments[index]


def _instantiate_contract_attributes(
    *,
    call: CallSummary,
    contract: FunctionContract,
) -> tuple[dict[str, ResourceIdentityTerm], set[str], set[str]]:
    terms: dict[str, ResourceIdentityTerm] = {}
    omitted: set[str] = set()
    unresolved: set[str] = set()

    for predicate in contract.postconditions:
        if (
            predicate.relation != "eq"
            or predicate.right is None
            or predicate.left.kind != "return_attribute"
            or predicate.left.name is None
            or predicate.right.kind not in {"parameter", "literal"}
        ):
            continue

        attribute = predicate.left.name
        if predicate.right.kind == "literal":
            if predicate.right.value is None:
                continue
            terms[attribute] = ResourceIdentityTerm.literal(
                predicate.right.value
            )
            continue

        parameter = predicate.right.name
        if parameter is None:
            continue
        argument = _actual_argument(
            call,
            parameter_name=parameter,
            positional_parameters=contract.positional_parameters,
        )
        if argument is None:
            omitted.add(attribute)
            continue
        if (
            _requires_non_null_parameter(contract, parameter)
            and not argument.provably_non_null
        ):
            unresolved.add(attribute)
            continue
        if argument.term is None:
            unresolved.add(attribute)
            continue
        terms[attribute] = argument.term

    return terms, omitted, unresolved


def _prior_scope_assertion(
    *,
    handler: RouteHandlerSummary,
    sink_call: CallSummary,
    identity_expression: ExpressionSummary,
    profile: Any,
) -> tuple[
    ResourceIdentityTerm | None,
    SemanticOrigin | None,
    str | None,
]:
    """Resolve a configured fail-closed scope assertion before one sink.

    Only assertions about the exact acted resource expression are relevant.
    Distinct asserted authorization resources are treated as ambiguous instead
    of selecting one silently.
    """
    matches: list[tuple[ResourceIdentityTerm, SemanticOrigin]] = []
    expected_resource = identity_expression.rendered

    for assertion_call in handler.calls:
        if assertion_call.line >= sink_call.line:
            continue
        resolved = profile.scope_assertion_names(
            assertion_call.full_name,
            assertion_call.leaf_name,
        )
        if resolved is None:
            continue

        assertion_key, semantics = resolved
        if len(assertion_call.positional_arguments) <= semantics.acted_scope_arg:
            return (
                None,
                None,
                f"unsupported_scope_assertion_signature:{assertion_key}",
            )

        acted_scope = assertion_call.positional_arguments[
            semantics.acted_scope_arg
        ]
        expected_scope = (
            f"{expected_resource}.{semantics.acted_scope_attribute}"
        )
        if acted_scope.rendered != expected_scope:
            continue

        if (
            len(assertion_call.positional_arguments)
            <= semantics.authorized_resource_arg
        ):
            return (
                None,
                None,
                f"unsupported_scope_assertion_signature:{assertion_key}",
            )

        authorized_resource = assertion_call.positional_arguments[
            semantics.authorized_resource_arg
        ]
        if authorized_resource.term is None:
            return (
                None,
                None,
                "unsupported_scope_assertion_authorized_resource:"
                f"{assertion_key}",
            )

        matches.append((authorized_resource.term, assertion_call.origin))

    if not matches:
        return None, None, None

    term_ids = {term.term_id for term, _origin in matches}
    if len(term_ids) != 1:
        return None, None, "ambiguous_scope_assertions"

    # Calls are source ordered. Use the latest equivalent assertion as the
    # provenance point closest to the protected sink.
    return matches[-1][0], matches[-1][1], None


def _matching_ownership_assertions(
    *,
    handler: RouteHandlerSummary,
    sink_call: CallSummary,
    identity_expression: ExpressionSummary,
    effect_name: str,
    profile: Any,
) -> tuple[list[Any], str | None]:
    """Return matching fail-closed ownership assertions before one sink."""

    matches = []
    expected_principal_prefix = profile.principal_parameter + "."

    for assertion in handler.ownership_assertions:
        if assertion.line >= sink_call.line:
            continue

        resolved = profile.ownership_assertion_names(
            assertion.loader_full_name,
            assertion.loader_leaf_name,
        )
        if resolved is None:
            continue
        assertion_key, semantics = resolved

        if effect_name not in semantics.authorized_effects:
            continue
        if (
            assertion.resource_identity_attribute
            != semantics.resource_identity_attribute
        ):
            continue
        if assertion.resource_key.rendered != identity_expression.rendered:
            continue
        if assertion.owner_attribute != semantics.owner_attribute:
            continue
        if assertion.principal_attribute != semantics.principal_attribute:
            continue
        if (
            assertion.principal_expression.rendered
            != expected_principal_prefix + semantics.principal_attribute
        ):
            continue
        if not semantics.allow_missing_resource:
            return (
                [],
                "ownership_assertion_missing_resource_policy_mismatch:"
                + assertion_key,
            )
        if (
            assertion.presence_test == "truthy"
            and not semantics.truthy_when_present
        ):
            return (
                [],
                "ownership_assertion_truthiness_unproved:" + assertion_key,
            )
        if assertion.presence_test not in {"truthy", "is_not_none"}:
            return (
                [],
                "unsupported_ownership_presence_test:" + assertion_key,
            )

        matches.append(assertion)

    if not matches:
        return [], None

    identities = {
        (
            assertion.resource_key.rendered,
            assertion.owner_attribute,
            assertion.principal_expression.rendered,
        )
        for assertion in matches
    }
    if len(identities) != 1:
        return [], "ambiguous_ownership_assertions"

    return matches, None


def _matching_body_authorization_helpers(
    *,
    handler: RouteHandlerSummary,
    sink_call: CallSummary,
    effect_name: str,
    acted_resource_symbol: str | None,
    identity_expression_rendered: str | None,
    profile: Any,
) -> list[tuple[CallSummary, Any]]:
    """Return profile-declared body authorization helper calls before a sink.

    Near-miss helpers absent from the profile are ignored (stay Unknown).
    Principal and resource argument binding are explicit profile fields —
    silent acted_id mapping is refused.
    """

    matches: list[tuple[CallSummary, Any]] = []
    resolver = getattr(profile, "body_authorization_helper_names", None)
    if resolver is None:
        return matches

    for call in handler.calls:
        if call.line >= sink_call.line:
            continue
        resolved = resolver(call.full_name, call.leaf_name)
        if resolved is None:
            continue
        _helper_key, semantics = resolved
        if effect_name not in semantics.authorized_effects:
            continue
        args = call.positional_arguments
        if len(args) <= semantics.principal_arg:
            continue
        if args[semantics.principal_arg].rendered != profile.principal_parameter:
            continue
        if semantics.resource_arg is not None:
            if len(args) <= semantics.resource_arg:
                continue
            if (
                identity_expression_rendered is None
                or args[semantics.resource_arg].rendered
                != identity_expression_rendered
            ):
                continue
        elif semantics.authorized_resource is not None:
            if acted_resource_symbol != semantics.authorized_resource:
                continue
        else:
            continue
        matches.append((call, semantics))
    return matches


@dataclass(frozen=True)
class FastApiFileSemanticFragment:
    """Semantic objects produced by one source file under one binding context."""

    path: str
    source_digest: str
    profile_digest: str
    contract_dependencies: dict[str, str | None] = field(default_factory=dict)
    guard_effectiveness_dependencies: dict[str, str | None] = field(
        default_factory=dict
    )
    helper_implementation_dependencies: dict[str, str | None] = field(
        default_factory=dict
    )
    route_attachment_digest: str = field(
        default_factory=lambda: content_digest([])
    )
    unsupported_constructs: tuple[str, ...] = ()
    principals: tuple[PrincipalRef, ...] = ()
    resources: tuple[ResourceRef, ...] = ()
    effects: tuple[EffectRef, ...] = ()
    guards: tuple[AuthorizationGuard, ...] = ()
    guard_dominance_evidence: tuple[GuardDominanceEvidence, ...] = ()
    authorization_cut_set_evidence: tuple[AuthorizationCutSetEvidence, ...] = ()
    value_origin_evidence: tuple[ValueOriginEvidence, ...] = ()
    helper_effectiveness_evidence: tuple[HelperEffectivenessEvidence, ...] = ()
    protected_effects: tuple[ProtectedEffect, ...] = ()
    resource_bindings: tuple[ResourceBinding, ...] = ()
    contract_uses: tuple[ContractUse, ...] = ()
    paths: tuple[SemanticPath, ...] = ()


def profile_semantic_digest(profile: Any) -> str:
    """Digest all profile fields that influence semantic route binding."""

    payload = {
        "sink_effects": dict(sorted(profile.sink_effects.items())),
        "sink_identity_args": dict(sorted(profile.sink_identity_args.items())),
        "sink_static_resources": dict(
            sorted(profile.sink_static_resources.items())
        ),
        "sink_scope_keywords": dict(sorted(profile.sink_scope_keywords.items())),
        "sink_missing_scope_unconstrained": sorted(
            profile.sink_missing_scope_unconstrained
        ),
        "scope_assertions": {
            key: {
                "acted_scope_arg": semantics.acted_scope_arg,
                "authorized_resource_arg": semantics.authorized_resource_arg,
                "acted_scope_attribute": semantics.acted_scope_attribute,
            }
            for key, semantics in sorted(profile.scope_assertions.items())
        },
        "ownership_assertions": {
            key: {
                "resource_identity_attribute": semantics.resource_identity_attribute,
                "owner_attribute": semantics.owner_attribute,
                "principal_attribute": semantics.principal_attribute,
                "authorized_effects": sorted(semantics.authorized_effects),
                "allow_missing_resource": semantics.allow_missing_resource,
                "truthy_when_present": semantics.truthy_when_present,
            }
            for key, semantics in sorted(profile.ownership_assertions.items())
        },
        "sink_contracts": dict(sorted(profile.sink_contracts.items())),
        "sink_contract_scope_attributes": dict(
            sorted(profile.sink_contract_scope_attributes.items())
        ),
        "sink_contract_identity_attributes": dict(
            sorted(profile.sink_contract_identity_attributes.items())
        ),
        "sink_binding_relations": dict(
            sorted(profile.sink_binding_relations.items())
        ),
        "sink_binding_authorized_projections": dict(
            sorted(profile.sink_binding_authorized_projections.items())
        ),
        "sink_binding_acted_projections": dict(
            sorted(profile.sink_binding_acted_projections.items())
        ),
        "sink_binding_authorized_attributes": dict(
            sorted(profile.sink_binding_authorized_attributes.items())
        ),
        "sink_binding_acted_attributes": dict(
            sorted(profile.sink_binding_acted_attributes.items())
        ),
        "dependency_guard_resources": dict(
            sorted(profile.dependency_guard_resources.items())
        ),
        "dependency_guard_effects": {
            key: sorted(value)
            for key, value in sorted(profile.dependency_guard_effects.items())
        },
        "route_dependency_guard_resources": dict(
            sorted(profile.route_dependency_guard_resources.items())
        ),
        "route_dependency_guard_effects": {
            key: sorted(value)
            for key, value in sorted(
                profile.route_dependency_guard_effects.items()
            )
        },
        "body_authorization_helpers": {
            key: {
                "authorized_effects": sorted(value.authorized_effects),
                "principal_arg": value.principal_arg,
                "resource_arg": value.resource_arg,
                "authorized_resource": value.authorized_resource,
            }
            for key, value in sorted(
                getattr(profile, "body_authorization_helpers", {}).items()
            )
        },
        "principal_parameter": profile.principal_parameter,
        "python_import_roots": list(
            getattr(profile, "python_import_roots", []) or []
        ),
    }
    return content_digest(payload)


def _bind_external_router_path_interpretations(
    handler: RouteHandlerSummary,
    *,
    external_fastapi_route_owners: frozenset[str],
) -> RouteHandlerSummary:
    """Apply bounded path interpretation after external route-owner proof."""

    if (
        handler.router_symbol is None
        or handler.router_symbol not in external_fastapi_route_owners
        or not handler.path_parameter_interpretations
    ):
        return handler

    candidates = {
        item.parameter_name: item.term
        for item in handler.path_parameter_interpretations
    }

    def bind_expression(expression: ExpressionSummary) -> ExpressionSummary:
        term = expression.term
        candidate = candidates.get(expression.rendered)
        if (
            candidate is None
            or term is None
            or term.kind != "symbol"
            or term.interpretation is not None
            or term.value != expression.rendered
        ):
            return expression
        return replace(expression, term=candidate)

    calls = tuple(
        replace(
            call,
            positional_arguments=tuple(
                bind_expression(argument)
                for argument in call.positional_arguments
            ),
            keyword_arguments=tuple(
                (name, bind_expression(argument))
                for name, argument in call.keyword_arguments
            ),
        )
        for call in handler.calls
    )
    ownership_assertions = tuple(
        replace(
            assertion,
            resource_key=bind_expression(assertion.resource_key),
            principal_expression=bind_expression(
                assertion.principal_expression
            ),
        )
        for assertion in handler.ownership_assertions
    )
    return replace(
        handler,
        calls=calls,
        ownership_assertions=ownership_assertions,
    )


def bind_route_file_summary(
    file_summary: RouteFileSummary,
    *,
    profile: Any,
    contracts_by_name: Mapping[str, FunctionContract],
    guard_effectiveness_by_name: Mapping[str, GuardEffectivenessEvidence] | None = None,
    external_route_dependencies_by_router: Mapping[
        str,
        tuple[RouteDependencySummary, ...],
    ] | None = None,
    external_fastapi_route_owners: frozenset[str] | None = None,
    route_attachment_digest: str | None = None,
    source_files: Mapping[str, str] | None = None,
) -> FastApiFileSemanticFragment:
    """Bind one file summary against current profile and function contracts."""

    guard_effectiveness_by_name = guard_effectiveness_by_name or {}
    external_route_dependencies_by_router = (
        external_route_dependencies_by_router or {}
    )
    external_fastapi_route_owners = (
        external_fastapi_route_owners or frozenset()
    )
    effective_attachment_digest = (
        route_attachment_digest
        if route_attachment_digest is not None
        else content_digest([])
    )
    principals: dict[str, PrincipalRef] = {}
    resources: dict[str, ResourceRef] = {}
    effects: dict[str, EffectRef] = {}
    guards: dict[str, AuthorizationGuard] = {}
    dominance_evidence: dict[str, GuardDominanceEvidence] = {}
    cut_set_evidence: dict[str, AuthorizationCutSetEvidence] = {}
    value_origins: dict[str, ValueOriginEvidence] = {}
    protected: dict[str, ProtectedEffect] = {}
    bindings: dict[str, ResourceBinding] = {}
    contract_uses: dict[str, ContractUse] = {}
    paths: dict[str, SemanticPath] = {}
    unsupported: list[str] = []
    dependencies: dict[str, str | None] = {}
    guard_effectiveness_dependencies: dict[str, str | None] = {}
    helper_implementation_dependencies: dict[str, str | None] = {}
    helper_effectiveness_evidence: dict[str, HelperEffectivenessEvidence] = {}

    for handler_summary in file_summary.handlers:
        handler = _bind_external_router_path_interpretations(
            handler_summary,
            external_fastapi_route_owners=external_fastapi_route_owners,
        )
        cfg = handler.control_flow
        if cfg is not None and cfg.unsupported_constructs:
            for construct in cfg.unsupported_constructs:
                unsupported.append(
                    f"{file_summary.path}:{handler.handler_name}:"
                    f"cfg_unsupported:{construct}"
                )
        elif handler.has_control_flow:
            unsupported.append(
                f"{file_summary.path}:{handler.handler_name}:"
                "control_flow_outside_profile"
            )

        for origin_item in handler.value_origins:
            value_origins[origin_item.evidence_id] = origin_item

        dependency_by_name = {
            item.dependency_name: item
            for item in handler.dependencies
        }

        effective_route_dependencies: dict[
            tuple[str, str | None, str | None],
            RouteDependencySummary,
        ] = {
            (item.full_name, item.leaf_name, item.factory_call): item
            for item in external_route_dependencies_by_router.get(
                handler.router_symbol or "",
                (),
            )
        }
        for item in handler.route_dependencies:
            effective_route_dependencies[
                (item.full_name, item.leaf_name, item.factory_call)
            ] = item

        principal_symbol = profile.principal_parameter
        principal_id = _semantic_id("principal", principal_symbol)
        principals.setdefault(
            principal_id,
            PrincipalRef(
                principal_id=principal_id,
                symbol=principal_symbol,
                principal_type="fastapi_dependency_result",
                origin=handler.origin,
            ),
        )

        for call in handler.calls:
            sink = profile.sink_effect_names(
                call.full_name,
                call.leaf_name,
            )
            if sink is None:
                continue
            sink_key, effect_name = sink
            sink_unsupported_start = len(unsupported)
            static_resource = profile.static_resource_for_sink(sink_key)
            if static_resource is not None:
                identity_expression = ExpressionSummary(
                    rendered=f"$static:{static_resource}",
                    term=ResourceIdentityTerm.literal(static_resource),
                    provably_non_null=True,
                    origin=call.origin,
                )
                identity_term = identity_expression.term
            else:
                identity_index = profile.identity_arg(sink_key)
                if len(call.positional_arguments) <= identity_index:
                    unsupported.append(
                        f"{file_summary.path}:{handler.handler_name}:"
                        f"unsupported_sink_identity_signature:{sink_key}"
                    )
                    continue

                identity_expression = call.positional_arguments[identity_index]
                identity_term = None
                if (
                    profile.contract_identity_attribute_for_sink(sink_key)
                    is None
                ):
                    identity_term = identity_expression.term
                    if identity_term is None:
                        unsupported.append(
                            f"{file_summary.path}:{handler.handler_name}:"
                            f"unsupported_sink_identity_expression:{sink_key}"
                        )
                        continue

            scope_term: ResourceIdentityTerm | None = None
            scope_origin: SemanticOrigin | None = None
            contract_attribute_terms: dict[str, ResourceIdentityTerm] = {}
            expected_contract_name = profile.contract_for_sink(sink_key)
            inferred_contract: FunctionContract | None = None
            if expected_contract_name is not None:
                inferred_contract = contracts_by_name.get(
                    expected_contract_name
                )
                dependencies[expected_contract_name] = (
                    inferred_contract.contract_id
                    if inferred_contract is not None
                    else None
                )
                if call.resolved_qualified_name != expected_contract_name:
                    unsupported.append(
                        f"{file_summary.path}:{handler.handler_name}:"
                        f"sink_contract_target_unresolved:"
                        f"{sink_key}:{expected_contract_name}"
                    )
                    inferred_contract = None
                elif inferred_contract is None:
                    unsupported.append(
                        f"{file_summary.path}:{handler.handler_name}:"
                        f"required_sink_contract_missing:"
                        f"{expected_contract_name}"
                    )

            if inferred_contract is not None:
                (
                    contract_attribute_terms,
                    omitted_contract_attributes,
                    unresolved_contract_attributes,
                ) = _instantiate_contract_attributes(
                    call=call,
                    contract=inferred_contract,
                )

                scope_attribute = (
                    profile.contract_scope_attribute_for_sink(sink_key)
                )
                if scope_attribute is not None:
                    scope_post = _typed_contract_projection(
                        inferred_contract,
                        scope_attribute,
                    )
                    if scope_post is None:
                        unsupported.append(
                            f"{file_summary.path}:{handler.handler_name}:"
                            f"required_scope_postcondition_missing:"
                            f"{expected_contract_name}:{scope_attribute}"
                        )
                    elif scope_attribute in contract_attribute_terms:
                        scope_term = contract_attribute_terms[scope_attribute]
                        scope_origin = call.origin
                    elif scope_attribute in omitted_contract_attributes:
                        scope_term = ResourceIdentityTerm.symbol(
                            f"$scope:{file_summary.path}:"
                            f"{handler.handler_name}:{call.line}"
                        )
                        scope_origin = call.origin
                    else:
                        unsupported.append(
                            f"{file_summary.path}:{handler.handler_name}:"
                            f"contract_precondition_unproved:"
                            f"{expected_contract_name}:{scope_attribute}"
                        )

                identity_attribute = (
                    profile.contract_identity_attribute_for_sink(sink_key)
                )
                if identity_attribute is not None:
                    identity_post = _typed_contract_projection(
                        inferred_contract,
                        identity_attribute,
                    )
                    if identity_post is None:
                        unsupported.append(
                            f"{file_summary.path}:{handler.handler_name}:"
                            f"required_identity_postcondition_missing:"
                            f"{expected_contract_name}:{identity_attribute}"
                        )
                    elif identity_attribute in contract_attribute_terms:
                        identity_term = contract_attribute_terms[
                            identity_attribute
                        ]
                    else:
                        unsupported.append(
                            f"{file_summary.path}:{handler.handler_name}:"
                            "required_identity_argument_or_precondition_unproved:"
                            f"{expected_contract_name}:{identity_attribute}"
                        )

                _ = unresolved_contract_attributes

            elif expected_contract_name is None:
                scope_keyword = profile.scope_keyword(sink_key)
                if scope_keyword is not None:
                    scope_expression = call.keyword(scope_keyword)
                    if scope_expression is not None:
                        scope_term = scope_expression.term
                        if scope_term is None:
                            unsupported.append(
                                f"{file_summary.path}:{handler.handler_name}:"
                                f"unsupported_sink_scope_expression:{sink_key}"
                            )
                        else:
                            scope_origin = call.origin
                    elif not profile.missing_scope_is_unconstrained(sink_key):
                        unsupported.append(
                            f"{file_summary.path}:{handler.handler_name}:"
                            f"required_sink_scope_missing:{sink_key}"
                        )

            if scope_term is None and profile.scope_assertions:
                (
                    asserted_scope,
                    assertion_origin,
                    assertion_problem,
                ) = _prior_scope_assertion(
                    handler=handler,
                    sink_call=call,
                    identity_expression=identity_expression,
                    profile=profile,
                )
                if assertion_problem is not None:
                    unsupported.append(
                        f"{file_summary.path}:{handler.handler_name}:"
                        f"{assertion_problem}"
                    )
                elif asserted_scope is not None:
                    scope_term = asserted_scope
                    scope_origin = assertion_origin

            if (
                scope_term is None
                and profile.missing_scope_is_unconstrained(sink_key)
            ):
                scope_term = ResourceIdentityTerm.symbol(
                    f"$scope:{file_summary.path}:"
                    f"{handler.handler_name}:{call.line}"
                )
                scope_origin = call.origin

            effect_id = _semantic_id("effect", effect_name)
            acted_id = (
                _semantic_id("resource", f"static:{static_resource}")
                if static_resource is not None
                else _semantic_id(
                    "resource",
                    (
                        f"{file_summary.path}:{handler.handler_name}:"
                        f"{call.line}:{identity_expression.rendered}"
                    ),
                )
            )
            protected_id = _semantic_id(
                "protected",
                f"{acted_id}:{effect_name}",
            )
            effects.setdefault(
                effect_id,
                EffectRef(
                    effect_id=effect_id,
                    name=effect_name,
                    origin=call.origin,
                ),
            )
            resources[acted_id] = ResourceRef(
                resource_id=acted_id,
                symbol=(
                    static_resource
                    if static_resource is not None
                    else identity_expression.rendered
                ),
                identity_term=identity_term,
                scope_term=scope_term,
                attribute_terms=contract_attribute_terms,
                origin=identity_expression.origin,
            )

            contract_use_ids: list[str] = []
            if inferred_contract is not None:
                use_id = _semantic_id(
                    "contract-use",
                    (
                        f"{file_summary.path}:{handler.handler_name}:"
                        f"{call.line}:{inferred_contract.contract_id}:"
                        f"{acted_id}"
                    ),
                )
                contract_uses[use_id] = ContractUse(
                    use_id=use_id,
                    contract_id=inferred_contract.contract_id,
                    qualified_name=inferred_contract.qualified_name,
                    resource_id=acted_id,
                    established_attributes=sorted(
                        contract_attribute_terms
                    ),
                    origin=call.origin,
                )
                contract_use_ids.append(use_id)

            guard_ids: list[str] = []
            body_guard_ids: set[str] = set()
            body_cut_candidate_guard_ids: set[str] = set()
            binding_ids: list[str] = []
            route_dependency_candidate = False

            ownership_assertions, ownership_problem = (
                _matching_ownership_assertions(
                    handler=handler,
                    sink_call=call,
                    identity_expression=identity_expression,
                    effect_name=effect_name,
                    profile=profile,
                )
            )
            if ownership_problem is not None:
                unsupported.append(
                    f"{file_summary.path}:{handler.handler_name}:"
                    f"{ownership_problem}"
                )
            else:
                for ownership_assertion in ownership_assertions:
                    ownership_guard_id = _semantic_id(
                        "guard",
                        (
                            f"{file_summary.path}:{handler.handler_name}:"
                            f"{ownership_assertion.line}:ownership:"
                            f"{effect_name}:{identity_expression.rendered}:"
                            f"{ownership_assertion.owner_attribute}:"
                            f"{ownership_assertion.principal_expression.rendered}"
                        ),
                    )
                    guards[ownership_guard_id] = AuthorizationGuard(
                        guard_id=ownership_guard_id,
                        principal_id=principal_id,
                        effect_id=effect_id,
                        resource_id=acted_id,
                        origin=ownership_assertion.origin,
                    )
                    guard_ids.append(ownership_guard_id)
                    # Ownership stays off the CFG-dominance body_guard_ids path
                    # (continuation / fail-closed semantics). It is a cut-set
                    # body candidate because its origin is handler-body local.
                    body_cut_candidate_guard_ids.add(ownership_guard_id)

            for helper_call, helper_semantics in _matching_body_authorization_helpers(
                handler=handler,
                sink_call=call,
                effect_name=effect_name,
                acted_resource_symbol=(
                    static_resource
                    if static_resource is not None
                    else None
                ),
                identity_expression_rendered=(
                    None
                    if static_resource is not None
                    else identity_expression.rendered
                ),
                profile=profile,
            ):
                helper_key = (
                    profile.body_authorization_helper_names(
                        helper_call.full_name,
                        helper_call.leaf_name,
                    )
                    or (helper_call.leaf_name or helper_call.full_name, helper_semantics)
                )[0]
                if helper_semantics.authorized_resource is not None:
                    # Match static sink resource identity encoding.
                    helper_resource_id = _semantic_id(
                        "resource",
                        f"static:{helper_semantics.authorized_resource}",
                    )
                    if helper_resource_id != acted_id:
                        # Explicit authorized_resource that does not match the
                        # acted sink resource cannot authorize this PE.
                        continue
                else:
                    helper_resource_id = acted_id
                helper_leaf = helper_key.split(".")[-1]
                implementation = analyze_body_helper_implementation(
                    source_files or {file_summary.path: ""},
                    helper_name=helper_leaf,
                )
                helper_implementation_dependencies[helper_key] = (
                    implementation.implementation_digest or None
                )
                effectiveness = (
                    "established"
                    if implementation.status == "established"
                    else "unproved"
                )
                effectiveness_reason = implementation.reason
                # Module-level fail-closed evidence must not authorize a
                # callsite where the helper name is locally rebound.
                if effectiveness == "established":
                    handler_source = (source_files or {}).get(file_summary.path)
                    trusted_line = (
                        implementation.line
                        if implementation.path == file_summary.path
                        else None
                    )
                    if handler_source is None or helper_name_locally_rebound_in_handler(
                        handler_source,
                        handler_name=handler.handler_name,
                        helper_name=helper_leaf,
                        call_line=helper_call.line,
                        trusted_definition_line=trusted_line,
                    ):
                        effectiveness = "unproved"
                        effectiveness_reason = "helper_callsite_name_rebound"
                helper_evidence = HelperEffectivenessEvidence(
                    evidence_id=implementation.evidence_id
                    or _semantic_id(
                        "bhe",
                        f"{helper_key}:{implementation.path}:{implementation.line}",
                    ),
                    helper_name=helper_key,
                    qualified_symbol=implementation.qualified_symbol
                    or f"{implementation.path}:{helper_leaf}@{implementation.line}",
                    definition_path=implementation.path,
                    definition_line=implementation.line,
                    source_digest=implementation.source_digest
                    or content_digest(""),
                    implementation_digest=implementation.implementation_digest
                    or content_digest(""),
                    status="established" if effectiveness == "established" else "unproved",
                    reason=effectiveness_reason,
                    origin=helper_call.origin,
                )
                helper_effectiveness_evidence[helper_evidence.evidence_id] = (
                    helper_evidence
                )
                evidence_ids: list[str] = [helper_evidence.evidence_id]
                body_helper_guard_id = _semantic_id(
                    "guard",
                    (
                        f"{file_summary.path}:{handler.handler_name}:"
                        f"{helper_call.line}:body_auth:{helper_key}:"
                        f"{effect_name}:{helper_resource_id}:"
                        f"{effectiveness}:{effectiveness_reason}"
                    ),
                )
                guards[body_helper_guard_id] = AuthorizationGuard(
                    guard_id=body_helper_guard_id,
                    principal_id=principal_id,
                    effect_id=effect_id,
                    resource_id=helper_resource_id,
                    effectiveness=effectiveness,
                    effectiveness_evidence_ids=evidence_ids,
                    origin=helper_call.origin,
                )
                guard_ids.append(body_helper_guard_id)
                # Call-style body helpers participate in both CFG dominance
                # and the cut-set candidate universe only when established.
                if effectiveness == "established":
                    body_guard_ids.add(body_helper_guard_id)
                    body_cut_candidate_guard_ids.add(body_helper_guard_id)

            for (
                dep_name,
                allowed_effects,
            ) in profile.dependency_guard_effects.items():
                if effect_name not in allowed_effects:
                    continue
                dep_record = dependency_by_name.get(dep_name)
                resource_symbol = profile.dependency_guard_resources.get(
                    dep_name
                )
                if dep_record is None or resource_symbol is None:
                    continue
                if (
                    dep_record.parameter_name
                    != profile.principal_parameter
                ):
                    unsupported.append(
                        f"{file_summary.path}:{handler.handler_name}:"
                        f"dependency_principal_mismatch:{dep_name}"
                    )
                    continue

                guard_resource_id = _semantic_id(
                    "resource",
                    resource_symbol,
                )
                resources.setdefault(
                    guard_resource_id,
                    ResourceRef(
                        resource_id=guard_resource_id,
                        symbol=resource_symbol,
                        identity_term=ResourceIdentityTerm.symbol(
                            resource_symbol
                        ),
                        origin=dep_record.origin,
                    ),
                )
                guard_id = _semantic_id(
                    "guard",
                    (
                        f"{file_summary.path}:{handler.handler_name}:"
                        f"{dep_name}:{effect_name}:{resource_symbol}"
                    ),
                )
                guards[guard_id] = AuthorizationGuard(
                    guard_id=guard_id,
                    principal_id=principal_id,
                    effect_id=effect_id,
                    resource_id=guard_resource_id,
                    origin=dep_record.origin,
                )
                guard_ids.append(guard_id)

                relation = profile.binding_relation_for_sink(sink_key)
                authorized_projection = (
                    profile.binding_authorized_projection_for_sink(
                        sink_key
                    )
                )
                acted_projection = (
                    profile.binding_acted_projection_for_sink(sink_key)
                )
                authorized_attribute = (
                    profile.binding_authorized_attribute_for_sink(
                        sink_key
                    )
                )
                acted_attribute = (
                    profile.binding_acted_attribute_for_sink(sink_key)
                )
                binding_id = _semantic_id(
                    "binding",
                    (
                        f"{guard_id}:{guard_resource_id}:{acted_id}:"
                        f"{relation}:{authorized_projection}:"
                        f"{acted_projection}:{authorized_attribute}:"
                        f"{acted_attribute}"
                    ),
                )
                bindings[binding_id] = ResourceBinding(
                    binding_id=binding_id,
                    authorized_resource_id=guard_resource_id,
                    acted_resource_id=acted_id,
                    relation=relation,
                    authorized_projection=authorized_projection,
                    acted_projection=acted_projection,
                    authorized_attribute=authorized_attribute,
                    acted_attribute=acted_attribute,
                    origin=scope_origin or call.origin,
                )
                binding_ids.append(binding_id)

            for route_dependency in sorted(
                effective_route_dependencies.values(),
                key=lambda item: (
                    item.full_name,
                    item.leaf_name or "",
                    item.factory_call or "",
                    item.source_kind,
                ),
            ):
                resolved_route_guard = profile.route_dependency_guard_names(
                    route_dependency.full_name,
                    route_dependency.leaf_name,
                )
                if resolved_route_guard is None:
                    continue
                (
                    route_guard_key,
                    route_resource_symbol,
                    route_allowed_effects,
                ) = resolved_route_guard
                if effect_name not in route_allowed_effects:
                    continue

                guard_resource_id = _semantic_id(
                    "resource",
                    f"static:{route_resource_symbol}",
                )
                resources.setdefault(
                    guard_resource_id,
                    ResourceRef(
                        resource_id=guard_resource_id,
                        symbol=route_resource_symbol,
                        identity_term=ResourceIdentityTerm.literal(
                            route_resource_symbol
                        ),
                        origin=route_dependency.origin,
                    ),
                )
                dependency_identity = (
                    route_dependency.factory_call
                    or route_guard_key
                )
                guard_id = _semantic_id(
                    "guard",
                    (
                        f"{file_summary.path}:{handler.handler_name}:"
                        f"route-dependency:{dependency_identity}:"
                        f"{effect_name}:{route_resource_symbol}"
                    ),
                )
                effectiveness_evidence = None
                if route_dependency.factory_call is None:
                    effectiveness_evidence = (
                        guard_effectiveness_by_name.get(route_guard_key)
                    )
                    guard_effectiveness_dependencies[route_guard_key] = (
                        effectiveness_evidence.evidence_id
                        if effectiveness_evidence is not None
                        else None
                    )
                guards[guard_id] = AuthorizationGuard(
                    guard_id=guard_id,
                    principal_id=principal_id,
                    effect_id=effect_id,
                    resource_id=guard_resource_id,
                    effectiveness=(
                        "established"
                        if effectiveness_evidence is not None
                        else "unproved"
                    ),
                    effectiveness_evidence_ids=(
                        [effectiveness_evidence.evidence_id]
                        if effectiveness_evidence is not None
                        else []
                    ),
                    origin=route_dependency.origin,
                )
                guard_ids.append(guard_id)

                if (
                    static_resource is not None
                    and route_resource_symbol == static_resource
                ):
                    route_dependency_candidate = True

            protected[protected_id] = ProtectedEffect(
                protected_effect_id=protected_id,
                principal_id=principal_id,
                effect_id=effect_id,
                resource_id=acted_id,
                origin=call.origin,
            )
            path_id = _semantic_id(
                "path",
                (
                    f"{handler.method}:{handler.route_path}:"
                    f"{handler.handler_name}:{protected_id}"
                ),
            )
            local_unsupported = list(
                unsupported[sink_unsupported_start:]
            )
            if not route_dependency_candidate:
                if cfg is not None:
                    sink_nodes = find_nodes_covering_line(cfg, call.line)
                    sink_authoritative = bool(sink_nodes) and all(
                        coverage_authoritative_for(cfg, node.node_id)
                        for node in sink_nodes
                    )
                    if not sink_authoritative:
                        for construct in cfg.unsupported_constructs:
                            local_unsupported.append(
                                f"{file_summary.path}:{handler.handler_name}:"
                                f"cfg_unsupported:{construct}"
                            )
                        # Preserve historical local marker for partial sinks.
                        for control_line in handler.unsupported_control_flow_lines:
                            if control_line < call.line:
                                local_unsupported.append(
                                    f"{file_summary.path}:{handler.handler_name}:"
                                    f"control_flow_before_protected_effect:{control_line}"
                                )
                else:
                    for control_line in handler.unsupported_control_flow_lines:
                        if control_line < call.line:
                            local_unsupported.append(
                                f"{file_summary.path}:{handler.handler_name}:"
                                f"control_flow_before_protected_effect:{control_line}"
                            )
            local_unsupported = sorted(set(local_unsupported))
            local_coverage_status = (
                "partial" if local_unsupported else "complete"
            )

            entrypoint = f"{handler.method} {handler.route_path}"
            for guard_id in sorted(body_guard_ids):
                guard = guards[guard_id]
                evidence = build_guard_dominance_evidence(
                    guard=guard,
                    effect=protected[protected_id],
                    entrypoint=entrypoint,
                    cfg=cfg,
                    origin=handler.origin,
                )
                dominance_evidence[evidence.evidence_id] = evidence

            cut_candidates = [
                guards[guard_id]
                for guard_id in sorted(body_cut_candidate_guard_ids)
                if guard_id in guards
            ]
            cut_evidence = build_authorization_cut_set_evidence(
                effect=protected[protected_id],
                entrypoint=entrypoint,
                cfg=cfg,
                candidate_guards=cut_candidates,
                origin=handler.origin,
                allow_boolean_short_circuit_branch_guard_ids=frozenset(
                    body_cut_candidate_guard_ids
                ),
            )
            if cut_evidence is not None:
                cut_set_evidence[cut_evidence.evidence_id] = cut_evidence

            paths[path_id] = SemanticPath(
                path_id=path_id,
                entrypoint=entrypoint,
                guard_ids=sorted(guard_ids),
                protected_effect_ids=[protected_id],
                binding_ids=sorted(binding_ids),
                contract_use_ids=sorted(contract_use_ids),
                coverage_status=local_coverage_status,
                unsupported_constructs=local_unsupported,
                coverage_assumptions=list(_PROFILE_ASSUMPTIONS),
                origin=handler.origin,
            )

    return FastApiFileSemanticFragment(
        path=file_summary.path,
        source_digest=file_summary.source_digest,
        profile_digest=profile_semantic_digest(profile),
        contract_dependencies=dict(sorted(dependencies.items())),
        guard_effectiveness_dependencies=dict(
            sorted(guard_effectiveness_dependencies.items())
        ),
        helper_implementation_dependencies=dict(
            sorted(helper_implementation_dependencies.items())
        ),
        route_attachment_digest=effective_attachment_digest,
        unsupported_constructs=tuple(sorted(set(unsupported))),
        principals=tuple(
            sorted(principals.values(), key=lambda item: item.principal_id)
        ),
        resources=tuple(
            sorted(resources.values(), key=lambda item: item.resource_id)
        ),
        effects=tuple(
            sorted(effects.values(), key=lambda item: item.effect_id)
        ),
        guards=tuple(
            sorted(guards.values(), key=lambda item: item.guard_id)
        ),
        guard_dominance_evidence=tuple(
            sorted(
                dominance_evidence.values(),
                key=lambda item: item.evidence_id,
            )
        ),
        authorization_cut_set_evidence=tuple(
            sorted(
                cut_set_evidence.values(),
                key=lambda item: item.evidence_id,
            )
        ),
        value_origin_evidence=tuple(
            sorted(
                value_origins.values(),
                key=lambda item: item.evidence_id,
            )
        ),
        helper_effectiveness_evidence=tuple(
            sorted(
                helper_effectiveness_evidence.values(),
                key=lambda item: item.evidence_id,
            )
        ),
        protected_effects=tuple(
            sorted(
                protected.values(),
                key=lambda item: item.protected_effect_id,
            )
        ),
        resource_bindings=tuple(
            sorted(bindings.values(), key=lambda item: item.binding_id)
        ),
        contract_uses=tuple(
            sorted(contract_uses.values(), key=lambda item: item.use_id)
        ),
        paths=tuple(
            sorted(paths.values(), key=lambda item: item.path_id)
        ),
    )


def fragment_dependencies_match(
    fragment: FastApiFileSemanticFragment,
    *,
    profile: Any,
    contracts_by_name: Mapping[str, FunctionContract],
    guard_effectiveness_by_name: Mapping[str, GuardEffectivenessEvidence] | None = None,
    route_attachment_digest: str | None = None,
    source_files: Mapping[str, str] | None = None,
) -> bool:
    """Return whether profile and consumed contract versions are unchanged."""

    guard_effectiveness_by_name = guard_effectiveness_by_name or {}
    if fragment.profile_digest != profile_semantic_digest(profile):
        return False
    effective_attachment_digest = (
        route_attachment_digest
        if route_attachment_digest is not None
        else content_digest([])
    )
    if fragment.route_attachment_digest != effective_attachment_digest:
        return False
    current = {
        name: (
            contracts_by_name[name].contract_id
            if name in contracts_by_name
            else None
        )
        for name in fragment.contract_dependencies
    }
    if current != fragment.contract_dependencies:
        return False
    current_guard_effectiveness = {
        name: (
            guard_effectiveness_by_name[name].evidence_id
            if name in guard_effectiveness_by_name
            else None
        )
        for name in fragment.guard_effectiveness_dependencies
    }
    if (
        current_guard_effectiveness
        != fragment.guard_effectiveness_dependencies
    ):
        return False
    # Helper implementation digests must match the current source universe
    # (same files full binding would see). Missing source_files refuses reuse.
    if fragment.helper_implementation_dependencies:
        if source_files is None:
            return False
        current_helper_digests: dict[str, str | None] = {}
        for helper_key in fragment.helper_implementation_dependencies:
            leaf = helper_key.split(".")[-1]
            implementation = analyze_body_helper_implementation(
                source_files,
                helper_name=leaf,
            )
            current_helper_digests[helper_key] = (
                implementation.implementation_digest or None
            )
        if current_helper_digests != fragment.helper_implementation_dependencies:
            return False
    return True



_SUPPORTED_CONSTRUCTS = [
    "static_fastapi_route_decorator",
    "depends_or_security_default_parameter",
    "direct_route_decorator_dependency",
    "direct_apirouter_constructor_dependency",
    "direct_fastapi_include_router_dependency",
    "source_proved_apirouter_wrapper",
    "route_dependency_factory_candidate",
    "configured_static_sink_resource",
    "route_dependency_candidate_mediation",
    "straight_line_handler",
    "bounded_handler_cfg",
    "fail_fast_none_guard",
    "configured_service_call_sink",
    "configured_fail_closed_resource_scope_assertion",
    "configured_fail_closed_resource_ownership_assertion",
    "configured_body_authorization_helper",
    "configured_sink_scope_keyword",
    "source_derived_resource_return_contract",
    "typed_function_contract",
    "return_attribute_projection",
    "constructor_alias_to_service_method",
]

_PROFILE_ASSUMPTIONS = [
    "Configured dependency guards authorize the declared route resource for the declared effects.",
    "Configured route-decorator, APIRouter-constructor, and bounded FastAPI include_router dependencies are candidate entrypoint mediators only; factory-produced dependency callables remain unproved until source-derived returned-callable semantics establish their effectiveness.",
    "Configured static sink resources denote endpoint/capability identities independent of request data and handler-local control flow.",
    "Configured service-call sinks faithfully identify protected effects.",
    "Configured sink identity argument denotes the acted resource identity only when no source-derived identity contract is required.",
    "Configured sink scope keyword denotes the acted resource scope when no source contract is required.",
    "Configured resource-scope assertion helpers fail closed: normal continuation establishes equality between the configured acted-resource attribute and authorization-resource argument.",
    "Configured resource-ownership assertions fail closed: normal continuation establishes that a present loaded resource has the configured owner/principal equality; truthiness-style presence checks rely on the explicit profile truthy-when-present assumption.",
    "Configured body authorization helpers authorize the declared effects when invoked in the handler body with the profile principal; helper names outside the profile never authorize.",
    "Source-derived function contracts are consumed only after resolving the configured service method.",
    "Only profile-selected contract attributes become required identity/scope/binding proof obligations.",
    "Conditional return contracts require the caller's non-null argument precondition to be established.",
    "Missing scope under a resolved source contract is modeled as unconstrained.",
    "Missing manually declared scope marked unconstrained is an explicit conservative over-approximation.",
]


def assemble_fastapi_assurance_ir(
    *,
    materials: AuthMaterials,
    function_contracts: list[FunctionContract],
    resource_return_contracts: list[ResourceReturnContract],
    fragments: Mapping[str, FastApiFileSemanticFragment],
    guard_effectiveness_evidence: list[GuardEffectivenessEvidence] | None = None,
    syntax_errors: Mapping[str, str] | None = None,
    missing_route_summary_paths: list[str] | None = None,
) -> AssuranceIR:
    """Assemble complete Assurance IR from deterministic per-file fragments."""

    principals: dict[str, PrincipalRef] = {}
    resources: dict[str, ResourceRef] = {}
    effects: dict[str, EffectRef] = {}
    guards: dict[str, AuthorizationGuard] = {}
    dominance_evidence: dict[str, GuardDominanceEvidence] = {}
    cut_set_evidence: dict[str, AuthorizationCutSetEvidence] = {}
    value_origins: dict[str, ValueOriginEvidence] = {}
    helper_effectiveness: dict[str, HelperEffectivenessEvidence] = {}
    protected: dict[str, ProtectedEffect] = {}
    bindings: dict[str, ResourceBinding] = {}
    contract_uses: dict[str, ContractUse] = {}
    paths: dict[str, SemanticPath] = {}
    unsupported: list[str] = []

    if not materials.has_head():
        unsupported.append("head_materials_missing")

    for path, message in sorted((syntax_errors or {}).items()):
        unsupported.append(f"{path}:syntax_error:{message}")

    for path in sorted(missing_route_summary_paths or []):
        unsupported.append(f"{path}:route_summary_missing")

    for path, fragment in sorted(fragments.items()):
        if path != fragment.path:
            raise ValueError(
                f"fragment map path {path!r} does not match fragment path "
                f"{fragment.path!r}"
            )
        unsupported.extend(fragment.unsupported_constructs)
        for item in fragment.principals:
            principals.setdefault(item.principal_id, item)
        for item in fragment.resources:
            resources[item.resource_id] = item
        for item in fragment.effects:
            effects.setdefault(item.effect_id, item)
        for item in fragment.guards:
            guards[item.guard_id] = item
        for item in fragment.guard_dominance_evidence:
            dominance_evidence[item.evidence_id] = item
        for item in fragment.authorization_cut_set_evidence:
            cut_set_evidence[item.evidence_id] = item
        for item in fragment.value_origin_evidence:
            value_origins[item.evidence_id] = item
        for item in fragment.helper_effectiveness_evidence:
            helper_effectiveness[item.evidence_id] = item
        for item in fragment.protected_effects:
            protected[item.protected_effect_id] = item
        for item in fragment.resource_bindings:
            bindings[item.binding_id] = item
        for item in fragment.contract_uses:
            contract_uses[item.use_id] = item
        for item in fragment.paths:
            paths[item.path_id] = item

    if not materials.has_head():
        coverage_status = "unknown"
        confidence = 0.0
    elif unsupported:
        coverage_status = "partial"
        confidence = 0.5
    else:
        coverage_status = "complete"
        confidence = 1.0

    return AssuranceIR(
        subject=VerificationSubject(
            repo=materials.repo or "unknown/repo",
            base_sha=materials.base_revision,
            head_sha=materials.head_revision or "unknown",
        ),
        extractor=AssuranceExtractorIdentity(
            extractor_id="assurance.fastapi.dependency_effects.ast_v1",
            extractor_version="0.76.0",
            source_profile_id="assurance.fastapi.dependency_effects.ast_v1",
        ),
        coverage=AssuranceCoverage(
            status=coverage_status,
            confidence=confidence,
            supported_constructs=list(_SUPPORTED_CONSTRUCTS),
            unsupported_constructs=sorted(set(unsupported)),
            assumptions=list(_PROFILE_ASSUMPTIONS),
        ),
        principals=sorted(
            principals.values(),
            key=lambda item: item.principal_id,
        ),
        resources=sorted(
            resources.values(),
            key=lambda item: item.resource_id,
        ),
        effects=sorted(
            effects.values(),
            key=lambda item: item.effect_id,
        ),
        guards=sorted(
            guards.values(),
            key=lambda item: item.guard_id,
        ),
        guard_effectiveness_evidence=sorted(
            guard_effectiveness_evidence or [],
            key=lambda item: item.evidence_id,
        ),
        guard_dominance_evidence=sorted(
            dominance_evidence.values(),
            key=lambda item: item.evidence_id,
        ),
        authorization_cut_set_evidence=sorted(
            cut_set_evidence.values(),
            key=lambda item: item.evidence_id,
        ),
        value_origin_evidence=sorted(
            value_origins.values(),
            key=lambda item: item.evidence_id,
        ),
        helper_effectiveness_evidence=sorted(
            helper_effectiveness.values(),
            key=lambda item: item.evidence_id,
        ),
        protected_effects=sorted(
            protected.values(),
            key=lambda item: item.protected_effect_id,
        ),
        resource_bindings=sorted(
            bindings.values(),
            key=lambda item: item.binding_id,
        ),
        resource_return_contracts=resource_return_contracts,
        function_contracts=function_contracts,
        contract_uses=sorted(
            contract_uses.values(),
            key=lambda item: item.use_id,
        ),
        paths=sorted(
            paths.values(),
            key=lambda item: item.path_id,
        ),
    )
