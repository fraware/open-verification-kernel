"""FastAPI dependency-to-effect Assurance IR profile.

This additive profile models a common production FastAPI authorization shape:

    user = Depends(require_workspace_member)
    ...
    await svc.get(resource_id, workspace_id=workspace_id)

The dependency is an authorization decision over a declared route resource.
A configured service call is the protected effect. The profile can require the
acted resource's scope to equal the resource authorized by the dependency.

The profile is intentionally narrow and advisory. Unsupported control flow,
dynamic routes, unsupported dependency forms, or unresolved sink signatures
lower extraction coverage instead of being silently ignored.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field

from ovk.compilers.authorization.base import normalize_path
from ovk.compilers.authorization.material_loader import AuthMaterials
from ovk.compilers.authorization.resource_return_contracts import (
    infer_function_contracts,
    infer_resource_return_contracts,
)
from ovk.core.assurance_ir import (
    AssuranceCoverage,
    AssuranceExtractorIdentity,
    AssuranceIR,
    AuthorizationGuard,
    BindingProjection,
    BindingRelation,
    ContractUse,
    EffectRef,
    PrincipalRef,
    ProtectedEffect,
    ResourceBinding,
    ResourceRef,
    SemanticOrigin,
    SemanticPath,
)
from ovk.core.bundle import content_digest
from ovk.core.models import SourceRange, VerificationSubject
from ovk.core.resource_identity import ResourceIdentityTerm


_SOURCE_PROFILE_ID = "assurance.fastapi.dependency_effects.ast_v1"
_HTTP_METHODS = frozenset({"get", "post", "put", "patch", "delete", "options", "head"})
_CONTROL_FLOW = (ast.If, ast.For, ast.AsyncFor, ast.While, ast.Try, ast.Match, ast.With, ast.AsyncWith)


@dataclass(frozen=True)
class FastApiDependencyEffectProfile:
    """Explicit semantics for dependency guards and protected service calls."""

    sink_effects: dict[str, str]
    sink_identity_args: dict[str, int] = field(default_factory=dict)
    sink_scope_keywords: dict[str, str] = field(default_factory=dict)
    sink_missing_scope_unconstrained: frozenset[str] = frozenset()
    # Sink key -> source-derived contract qualified name, e.g. AgentService.get.
    sink_contracts: dict[str, str] = field(default_factory=dict)
    # Sink key -> returned attribute whose equality contract denotes resource scope.
    sink_contract_scope_attributes: dict[str, str] = field(default_factory=dict)
    # Sink key -> returned attribute whose equality contract denotes resource identity.
    sink_contract_identity_attributes: dict[str, str] = field(default_factory=dict)

    # Per-sink authorization/resource binding semantics.
    sink_binding_relations: dict[str, BindingRelation] = field(default_factory=dict)
    sink_binding_authorized_projections: dict[str, BindingProjection] = field(default_factory=dict)
    sink_binding_acted_projections: dict[str, BindingProjection] = field(default_factory=dict)
    sink_binding_authorized_attributes: dict[str, str] = field(default_factory=dict)
    sink_binding_acted_attributes: dict[str, str] = field(default_factory=dict)

    # Dependency name -> handler parameter holding the authorized resource key.
    dependency_guard_resources: dict[str, str] = field(default_factory=dict)
    # Dependency name -> effect names the dependency authorizes in this profile.
    dependency_guard_effects: dict[str, tuple[str, ...]] = field(default_factory=dict)

    principal_parameter: str = "user"

    def sink_effect(self, call: ast.Call) -> tuple[str, str] | None:
        full = ast.unparse(call.func)
        leaf = _name_of(call.func)
        for key in (full, leaf):
            if key and key in self.sink_effects:
                return key, self.sink_effects[key]
        return None

    def identity_arg(self, sink_key: str) -> int:
        return int(self.sink_identity_args.get(sink_key, 0))

    def scope_keyword(self, sink_key: str) -> str | None:
        return self.sink_scope_keywords.get(sink_key)

    def missing_scope_is_unconstrained(self, sink_key: str) -> bool:
        return sink_key in self.sink_missing_scope_unconstrained

    def contract_for_sink(self, sink_key: str) -> str | None:
        return self.sink_contracts.get(sink_key)

    def contract_scope_attribute_for_sink(self, sink_key: str) -> str | None:
        return self.sink_contract_scope_attributes.get(sink_key)

    def contract_identity_attribute_for_sink(self, sink_key: str) -> str | None:
        return self.sink_contract_identity_attributes.get(sink_key)

    def binding_relation_for_sink(self, sink_key: str) -> BindingRelation:
        return self.sink_binding_relations.get(sink_key, "same_tenant")

    def binding_authorized_projection_for_sink(self, sink_key: str) -> BindingProjection:
        return self.sink_binding_authorized_projections.get(sink_key, "identity")

    def binding_acted_projection_for_sink(self, sink_key: str) -> BindingProjection:
        return self.sink_binding_acted_projections.get(sink_key, "scope")

    def binding_authorized_attribute_for_sink(self, sink_key: str) -> str | None:
        return self.sink_binding_authorized_attributes.get(sink_key)

    def binding_acted_attribute_for_sink(self, sink_key: str) -> str | None:
        return self.sink_binding_acted_attributes.get(sink_key)


def _name_of(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _const_str(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _origin(path: str, node: ast.AST) -> SemanticOrigin:
    return SemanticOrigin(
        path=path,
        extractor_id=_SOURCE_PROFILE_ID,
        extractor_version="0.1.0",
        source_range=SourceRange(
            path=path,
            start_line=getattr(node, "lineno", None),
            end_line=getattr(node, "end_lineno", getattr(node, "lineno", None)),
        ),
    )


def _semantic_id(prefix: str, value: str) -> str:
    return f"{prefix}:{content_digest(value)[:16]}"


def _route_decorator(node: ast.FunctionDef | ast.AsyncFunctionDef) -> tuple[str, str] | None:
    for decorator in node.decorator_list:
        if not isinstance(decorator, ast.Call) or not isinstance(decorator.func, ast.Attribute):
            continue
        method = decorator.func.attr.lower()
        if method not in _HTTP_METHODS or not decorator.args:
            continue
        route = _const_str(decorator.args[0])
        if route is None:
            continue
        return method.upper(), normalize_path("", route)
    return None


def _has_control_flow(handler: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    return any(isinstance(node, _CONTROL_FLOW) for statement in handler.body for node in ast.walk(statement))


def _body_calls(handler: ast.FunctionDef | ast.AsyncFunctionDef) -> list[ast.Call]:
    calls = [
        node
        for statement in handler.body
        for node in ast.walk(statement)
        if isinstance(node, ast.Call)
    ]
    return sorted(calls, key=lambda item: (getattr(item, "lineno", 0), getattr(item, "col_offset", 0)))


def _depends_name(node: ast.AST | None) -> str | None:
    if not isinstance(node, ast.Call) or _name_of(node.func) not in {"Depends", "Security"}:
        return None
    if not node.args:
        return None
    return _name_of(node.args[0])


def _dependency_parameters(
    handler: ast.FunctionDef | ast.AsyncFunctionDef,
) -> list[tuple[str, str, ast.AST]]:
    """Return (parameter_name, dependency_name, source_node)."""

    found: list[tuple[str, str, ast.AST]] = []
    positional = list(handler.args.posonlyargs) + list(handler.args.args)
    defaults = list(handler.args.defaults)
    if defaults:
        for arg, default in zip(positional[-len(defaults):], defaults):
            dep = _depends_name(default)
            if dep:
                found.append((arg.arg, dep, default))

    for arg, default in zip(handler.args.kwonlyargs, handler.args.kw_defaults):
        dep = _depends_name(default)
        if dep:
            found.append((arg.arg, dep, default))
    return found


def _keyword_value(call: ast.Call, name: str) -> ast.AST | None:
    for keyword in call.keywords:
        if keyword.arg == name:
            return keyword.value
    return None


def _symbol_term(node: ast.AST) -> ResourceIdentityTerm | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, (str, int, bool)):
        return ResourceIdentityTerm.literal(str(node.value))
    if isinstance(node, (ast.Name, ast.Attribute, ast.Subscript)):
        return ResourceIdentityTerm.symbol(ast.unparse(node))
    return None


def _constructor_aliases(
    handler: ast.FunctionDef | ast.AsyncFunctionDef,
) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for statement in handler.body:
        if not isinstance(statement, ast.Assign) or len(statement.targets) != 1:
            continue
        target = statement.targets[0]
        if not isinstance(target, ast.Name) or not isinstance(statement.value, ast.Call):
            continue
        constructor = _name_of(statement.value.func)
        if constructor:
            aliases[target.id] = constructor
    return aliases


def _resolved_call_qualified_name(
    call: ast.Call,
    constructor_aliases: dict[str, str],
) -> str | None:
    if not isinstance(call.func, ast.Attribute):
        return None

    receiver = call.func.value
    if isinstance(receiver, ast.Name):
        constructor = constructor_aliases.get(receiver.id)
        if constructor:
            return f"{constructor}.{call.func.attr}"

    if isinstance(receiver, ast.Call):
        constructor = _name_of(receiver.func)
        if constructor:
            return f"{constructor}.{call.func.attr}"
    return None


def _annotation_excludes_none(annotation: ast.AST | None) -> bool:
    if annotation is None:
        return False
    rendered = ast.unparse(annotation)
    return "None" not in rendered and "Optional" not in rendered


def _provably_non_null_parameters(
    handler: ast.FunctionDef | ast.AsyncFunctionDef,
) -> set[str]:
    result: set[str] = set()
    positional = list(handler.args.posonlyargs) + list(handler.args.args)
    default_count = len(handler.args.defaults)
    required_positional = positional[:-default_count] if default_count else positional
    for arg in required_positional:
        if _annotation_excludes_none(arg.annotation):
            result.add(arg.arg)

    for arg, default in zip(handler.args.kwonlyargs, handler.args.kw_defaults):
        if default is None and _annotation_excludes_none(arg.annotation):
            result.add(arg.arg)
    return result


def _expr_provably_non_null(node: ast.AST, non_null_parameters: set[str]) -> bool:
    if isinstance(node, ast.Constant):
        return node.value is not None
    return isinstance(node, ast.Name) and node.id in non_null_parameters


def _actual_argument_for_parameter(
    call: ast.Call,
    *,
    parameter_name: str,
    contract_parameter_order: list[str],
) -> ast.AST | None:
    keyword = _keyword_value(call, parameter_name)
    if keyword is not None:
        return keyword
    if parameter_name not in contract_parameter_order:
        return None
    index = contract_parameter_order.index(parameter_name)
    if len(call.args) <= index:
        return None
    return call.args[index]


def _typed_contract_projection(
    *,
    contract,
    return_attribute: str,
):
    """Return the unique eq(return.<attr>, parameter) postcondition."""

    matches = []
    for predicate in contract.postconditions:
        if (
            predicate.relation == "eq"
            and predicate.right is not None
            and predicate.left.kind == "return_attribute"
            and predicate.left.name == return_attribute
            and predicate.right.kind in {"parameter", "literal"}
            and (
                (predicate.right.kind == "parameter" and predicate.right.name is not None)
                or (predicate.right.kind == "literal" and predicate.right.value is not None)
            )
        ):
            matches.append(predicate)
    if len(matches) != 1:
        return None
    return matches[0]


def _requires_non_null_parameter(contract, parameter_name: str) -> bool:
    return any(
        predicate.relation == "non_null"
        and predicate.left.kind == "parameter"
        and predicate.left.name == parameter_name
        for predicate in contract.preconditions
    )


def _instantiate_contract_attributes(
    *,
    call: ast.Call,
    contract,
    non_null_parameters: set[str],
) -> tuple[dict[str, ResourceIdentityTerm], set[str], set[str]]:
    """Instantiate proven return-attribute equalities at one call site.

    Returns:
      terms: proven return attribute -> actual argument term
      omitted: attributes whose source parameter is omitted at this call
      unresolved: attributes whose source argument/precondition cannot be proved
    """

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
            or (
                predicate.right.kind == "parameter"
                and predicate.right.name is None
            )
            or (
                predicate.right.kind == "literal"
                and predicate.right.value is None
            )
        ):
            continue

        attribute = predicate.left.name

        if predicate.right.kind == "literal":
            assert predicate.right.value is not None
            terms[attribute] = ResourceIdentityTerm.literal(predicate.right.value)
            continue

        parameter = predicate.right.name
        assert parameter is not None
        argument = _actual_argument_for_parameter(
            call,
            parameter_name=parameter,
            contract_parameter_order=contract.positional_parameters,
        )
        if argument is None:
            omitted.add(attribute)
            continue

        if (
            _requires_non_null_parameter(contract, parameter)
            and not _expr_provably_non_null(argument, non_null_parameters)
        ):
            unresolved.add(attribute)
            continue

        term = _symbol_term(argument)
        if term is None:
            unresolved.add(attribute)
            continue
        terms[attribute] = term

    return terms, omitted, unresolved


class FastApiDependencyEffectExtractor:
    """Compile the dependency-guard/service-effect FastAPI subset to Assurance IR."""

    source_profile_id = _SOURCE_PROFILE_ID

    def compile(
        self,
        materials: AuthMaterials,
        profile: FastApiDependencyEffectProfile,
    ) -> AssuranceIR:
        subject = VerificationSubject(
            repo=materials.repo or "unknown/repo",
            base_sha=materials.base_revision,
            head_sha=materials.head_revision or "unknown",
        )
        principals: dict[str, PrincipalRef] = {}
        resources: dict[str, ResourceRef] = {}
        effects: dict[str, EffectRef] = {}
        guards: dict[str, AuthorizationGuard] = {}
        protected: dict[str, ProtectedEffect] = {}
        bindings: dict[str, ResourceBinding] = {}
        contract_uses: dict[str, ContractUse] = {}
        paths: dict[str, SemanticPath] = {}
        unsupported: list[str] = []
        function_contracts = infer_function_contracts(materials)
        resource_return_contracts = infer_resource_return_contracts(materials)
        contracts_by_name = {
            contract.qualified_name: contract
            for contract in function_contracts
        }

        if not materials.has_head():
            unsupported.append("head_materials_missing")

        for path, source in sorted(materials.head_files.items()):
            try:
                tree = ast.parse(source, filename=path)
            except SyntaxError as exc:
                unsupported.append(f"{path}:syntax_error:{exc.msg}")
                continue

            for handler in tree.body:
                if not isinstance(handler, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                route = _route_decorator(handler)
                if route is None:
                    continue
                method, route_path = route
                if _has_control_flow(handler):
                    unsupported.append(f"{path}:{handler.name}:control_flow_outside_profile")

                dependency_params = _dependency_parameters(handler)
                dependency_by_name = {dep: (param, node) for param, dep, node in dependency_params}
                constructor_aliases = _constructor_aliases(handler)
                non_null_parameters = _provably_non_null_parameters(handler)
                calls = _body_calls(handler)

                principal_symbol = profile.principal_parameter
                principal_id = _semantic_id("principal", principal_symbol)
                principals.setdefault(
                    principal_id,
                    PrincipalRef(
                        principal_id=principal_id,
                        symbol=principal_symbol,
                        principal_type="fastapi_dependency_result",
                        origin=_origin(path, handler),
                    ),
                )

                for call in calls:
                    sink = profile.sink_effect(call)
                    if sink is None:
                        continue
                    sink_key, effect_name = sink
                    identity_index = profile.identity_arg(sink_key)
                    if len(call.args) <= identity_index:
                        unsupported.append(
                            f"{path}:{handler.name}:unsupported_sink_identity_signature:{sink_key}"
                        )
                        continue

                    identity_node = call.args[identity_index]
                    identity_term = None
                    if profile.contract_identity_attribute_for_sink(sink_key) is None:
                        identity_term = _symbol_term(identity_node)
                        if identity_term is None:
                            unsupported.append(
                                f"{path}:{handler.name}:unsupported_sink_identity_expression:{sink_key}"
                            )
                            continue

                    scope_term: ResourceIdentityTerm | None = None
                    contract_attribute_terms: dict[str, ResourceIdentityTerm] = {}
                    expected_contract_name = profile.contract_for_sink(sink_key)
                    inferred_contract = None
                    if expected_contract_name is not None:
                        resolved_name = _resolved_call_qualified_name(
                            call,
                            constructor_aliases,
                        )
                        if resolved_name != expected_contract_name:
                            unsupported.append(
                                f"{path}:{handler.name}:sink_contract_target_unresolved:"
                                f"{sink_key}:{expected_contract_name}"
                            )
                        else:
                            inferred_contract = contracts_by_name.get(
                                expected_contract_name
                            )
                            if inferred_contract is None:
                                unsupported.append(
                                    f"{path}:{handler.name}:required_sink_contract_missing:"
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
                            non_null_parameters=non_null_parameters,
                        )

                        scope_attribute = profile.contract_scope_attribute_for_sink(
                            sink_key
                        )
                        if scope_attribute is not None:
                            scope_post = _typed_contract_projection(
                                contract=inferred_contract,
                                return_attribute=scope_attribute,
                            )
                            if scope_post is None:
                                unsupported.append(
                                    f"{path}:{handler.name}:required_scope_postcondition_missing:"
                                    f"{expected_contract_name}:{scope_attribute}"
                                )
                            elif scope_attribute in contract_attribute_terms:
                                scope_term = contract_attribute_terms[scope_attribute]
                            elif scope_attribute in omitted_contract_attributes:
                                scope_term = ResourceIdentityTerm.symbol(
                                    f"$scope:{path}:{handler.name}:{getattr(call, 'lineno', 0)}"
                                )
                            else:
                                unsupported.append(
                                    f"{path}:{handler.name}:contract_precondition_unproved:"
                                    f"{expected_contract_name}:{scope_attribute}"
                                )

                        identity_attribute = (
                            profile.contract_identity_attribute_for_sink(sink_key)
                        )
                        if identity_attribute is not None:
                            identity_post = _typed_contract_projection(
                                contract=inferred_contract,
                                return_attribute=identity_attribute,
                            )
                            if identity_post is None:
                                unsupported.append(
                                    f"{path}:{handler.name}:required_identity_postcondition_missing:"
                                    f"{expected_contract_name}:{identity_attribute}"
                                )
                            elif identity_attribute in contract_attribute_terms:
                                identity_term = contract_attribute_terms[identity_attribute]
                            else:
                                unsupported.append(
                                    f"{path}:{handler.name}:required_identity_argument_or_precondition_unproved:"
                                    f"{expected_contract_name}:{identity_attribute}"
                                )

                        # Retain every instantiated typed postcondition, including
                        # attributes not promoted to the identity/scope projections.
                        for attribute in unresolved_contract_attributes:
                            if (
                                attribute
                                in {
                                    scope_attribute,
                                    identity_attribute,
                                }
                            ):
                                continue
                            # Unused unresolved postconditions do not reduce coverage:
                            # only properties selected by the profile become proof obligations.
                    elif expected_contract_name is None:
                        scope_keyword = profile.scope_keyword(sink_key)
                        if scope_keyword is not None:
                            scope_node = _keyword_value(call, scope_keyword)
                            if scope_node is not None:
                                scope_term = _symbol_term(scope_node)
                                if scope_term is None:
                                    unsupported.append(
                                        f"{path}:{handler.name}:unsupported_sink_scope_expression:{sink_key}"
                                    )
                            elif profile.missing_scope_is_unconstrained(sink_key):
                                scope_term = ResourceIdentityTerm.symbol(
                                    f"$scope:{path}:{handler.name}:{getattr(call, 'lineno', 0)}"
                                )
                            else:
                                unsupported.append(
                                    f"{path}:{handler.name}:required_sink_scope_missing:{sink_key}"
                                )

                    effect_id = _semantic_id("effect", effect_name)
                    acted_id = _semantic_id(
                        "resource",
                        f"{path}:{handler.name}:{getattr(call, 'lineno', 0)}:{ast.unparse(identity_node)}",
                    )
                    protected_id = _semantic_id(
                        "protected",
                        f"{acted_id}:{effect_name}",
                    )
                    effects.setdefault(
                        effect_id,
                        EffectRef(effect_id=effect_id, name=effect_name, origin=_origin(path, call)),
                    )
                    resources[acted_id] = ResourceRef(
                        resource_id=acted_id,
                        symbol=ast.unparse(identity_node),
                        identity_term=identity_term,
                        scope_term=scope_term,
                        attribute_terms=contract_attribute_terms,
                        origin=_origin(path, identity_node),
                    )

                    contract_use_ids: list[str] = []
                    if inferred_contract is not None:
                        use_id = _semantic_id(
                            "contract-use",
                            (
                                f"{path}:{handler.name}:{getattr(call, 'lineno', 0)}:"
                                f"{inferred_contract.contract_id}:{acted_id}"
                            ),
                        )
                        contract_uses[use_id] = ContractUse(
                            use_id=use_id,
                            contract_id=inferred_contract.contract_id,
                            qualified_name=inferred_contract.qualified_name,
                            resource_id=acted_id,
                            established_attributes=sorted(contract_attribute_terms),
                            origin=_origin(path, call),
                        )
                        contract_use_ids.append(use_id)

                    guard_ids: list[str] = []
                    binding_ids: list[str] = []
                    for dep_name, allowed_effects in profile.dependency_guard_effects.items():
                        if effect_name not in allowed_effects:
                            continue
                        dep_record = dependency_by_name.get(dep_name)
                        resource_symbol = profile.dependency_guard_resources.get(dep_name)
                        if dep_record is None or resource_symbol is None:
                            continue
                        param_name, dep_node = dep_record
                        if param_name != profile.principal_parameter:
                            unsupported.append(
                                f"{path}:{handler.name}:dependency_principal_mismatch:{dep_name}"
                            )
                            continue

                        guard_resource_id = _semantic_id("resource", resource_symbol)
                        resources.setdefault(
                            guard_resource_id,
                            ResourceRef(
                                resource_id=guard_resource_id,
                                symbol=resource_symbol,
                                identity_term=ResourceIdentityTerm.symbol(resource_symbol),
                                origin=_origin(path, dep_node),
                            ),
                        )
                        guard_id = _semantic_id(
                            "guard",
                            f"{path}:{handler.name}:{dep_name}:{effect_name}:{resource_symbol}",
                        )
                        guards[guard_id] = AuthorizationGuard(
                            guard_id=guard_id,
                            principal_id=principal_id,
                            effect_id=effect_id,
                            resource_id=guard_resource_id,
                            origin=_origin(path, dep_node),
                        )
                        guard_ids.append(guard_id)

                        relation = profile.binding_relation_for_sink(sink_key)
                        authorized_projection = (
                            profile.binding_authorized_projection_for_sink(sink_key)
                        )
                        acted_projection = (
                            profile.binding_acted_projection_for_sink(sink_key)
                        )
                        authorized_attribute = (
                            profile.binding_authorized_attribute_for_sink(sink_key)
                        )
                        acted_attribute = (
                            profile.binding_acted_attribute_for_sink(sink_key)
                        )
                        binding_id = _semantic_id(
                            "binding",
                            (
                                f"{guard_id}:{guard_resource_id}:{acted_id}:"
                                f"{relation}:{authorized_projection}:{acted_projection}:"
                                f"{authorized_attribute}:{acted_attribute}"
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
                            origin=_origin(path, call),
                        )
                        binding_ids.append(binding_id)

                    protected[protected_id] = ProtectedEffect(
                        protected_effect_id=protected_id,
                        principal_id=principal_id,
                        effect_id=effect_id,
                        resource_id=acted_id,
                        origin=_origin(path, call),
                    )
                    path_id = _semantic_id(
                        "path",
                        f"{method}:{route_path}:{handler.name}:{protected_id}",
                    )
                    paths[path_id] = SemanticPath(
                        path_id=path_id,
                        entrypoint=f"{method} {route_path}",
                        guard_ids=sorted(guard_ids),
                        protected_effect_ids=[protected_id],
                        binding_ids=sorted(binding_ids),
                        contract_use_ids=sorted(contract_use_ids),
                        origin=_origin(path, handler),
                    )

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
            subject=subject,
            extractor=AssuranceExtractorIdentity(
                extractor_id=_SOURCE_PROFILE_ID,
                extractor_version="0.1.0",
                source_profile_id=_SOURCE_PROFILE_ID,
            ),
            coverage=AssuranceCoverage(
                status=coverage_status,
                confidence=confidence,
                supported_constructs=[
                    "static_fastapi_route_decorator",
                    "depends_or_security_default_parameter",
                    "straight_line_handler",
                    "configured_service_call_sink",
                    "configured_sink_scope_keyword",
                    "source_derived_resource_return_contract",
                    "typed_function_contract",
                    "return_attribute_projection",
                    "constructor_alias_to_service_method",
                ],
                unsupported_constructs=sorted(set(unsupported)),
                assumptions=[
                    "Configured dependency guards authorize the declared route resource for the declared effects.",
                    "Configured service-call sinks faithfully identify protected effects.",
                    "Configured sink identity argument denotes the acted resource identity only when no source-derived identity contract is required.",
                    "Configured sink scope keyword denotes the acted resource scope when no source contract is required.",
                    "Source-derived function contracts are consumed only after resolving the configured service method.",
                    "Only profile-selected contract attributes become required identity/scope/binding proof obligations.",
                    "Conditional return contracts require the caller's non-null argument precondition to be established.",
                    "Missing scope under a resolved source contract is modeled as unconstrained.",
                    "Missing manually declared scope marked unconstrained is an explicit conservative over-approximation.",
                ],
            ),
            principals=sorted(principals.values(), key=lambda item: item.principal_id),
            resources=sorted(resources.values(), key=lambda item: item.resource_id),
            effects=sorted(effects.values(), key=lambda item: item.effect_id),
            guards=sorted(guards.values(), key=lambda item: item.guard_id),
            protected_effects=sorted(protected.values(), key=lambda item: item.protected_effect_id),
            resource_bindings=sorted(bindings.values(), key=lambda item: item.binding_id),
            resource_return_contracts=resource_return_contracts,
            function_contracts=function_contracts,
            contract_uses=sorted(contract_uses.values(), key=lambda item: item.use_id),
            paths=sorted(paths.values(), key=lambda item: item.path_id),
        )
