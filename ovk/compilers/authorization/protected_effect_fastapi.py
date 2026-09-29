"""Experimental FastAPI Protected-Effect extractor.

This source profile emits Assurance IR for a deliberately narrow FastAPI subset.
It does not replace authorization.fastapi.ast_v1 and does not participate in
existing strict decisions.

Supported v1 pattern:
- static FastAPI/APIRouter route decorators;
- a configured principal parameter name;
- configured authorization calls with positional
  (principal, effect_name, resource) arguments;
- configured protected sink calls whose resource is a positional argument;
- straight-line handler bodies;
- repository-declared resource loader identity and scope semantics.

Control-flow constructs, dynamic routes, non-literal guard effects, unresolved
call signatures, and syntax errors are recorded as unsupported semantics.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field

from ovk.compilers.authorization.base import normalize_path
from ovk.compilers.authorization.material_loader import AuthMaterials
from ovk.core.assurance_ir import (
    AssuranceCoverage,
    AssuranceExtractorIdentity,
    AssuranceIR,
    AuthorizationGuard,
    BindingProjection,
    BindingRelation,
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


_SOURCE_PROFILE_ID = "assurance.fastapi.protected_effects.ast_v1"
_HTTP_METHODS = frozenset({"get", "post", "put", "patch", "delete", "options", "head"})
_CONTROL_FLOW = (ast.If, ast.For, ast.AsyncFor, ast.While, ast.Try, ast.Match, ast.With, ast.AsyncWith)


@dataclass(frozen=True)
class ResourceAlias:
    """Modeled identity and scope for one local resource variable."""

    identity_term: ResourceIdentityTerm | None = None
    scope_term: ResourceIdentityTerm | None = None


@dataclass(frozen=True)
class ProtectedEffectProfile:
    """Repository-local extraction policy for the narrow FastAPI profile."""

    sink_effects: dict[str, str]
    principal_parameter: str = "user"
    guard_functions: frozenset[str] = frozenset({"authorize"})
    guard_principal_arg: int = 0
    guard_effect_arg: int = 1
    guard_resource_arg: int = 2
    sink_resource_args: dict[str, int] = field(default_factory=dict)

    # Loader semantics are explicit profile assumptions. A loader absent from
    # these maps receives no modeled identity/scope semantics.
    resource_loader_identity_args: dict[str, int] = field(default_factory=dict)
    resource_loader_scope_args: dict[str, int] = field(default_factory=dict)
    resource_loader_unconstrained_scopes: frozenset[str] = frozenset()

    # Per-sink binding semantics. Default is resource identity equality.
    sink_binding_relations: dict[str, BindingRelation] = field(default_factory=dict)
    sink_authorized_projections: dict[str, BindingProjection] = field(default_factory=dict)
    sink_acted_projections: dict[str, BindingProjection] = field(default_factory=dict)

    def resource_arg_for_sink(self, sink_name: str) -> int:
        return int(self.sink_resource_args.get(sink_name, 0))

    def identity_arg_for_loader(self, loader_name: str) -> int | None:
        value = self.resource_loader_identity_args.get(loader_name)
        return None if value is None else int(value)

    def scope_arg_for_loader(self, loader_name: str) -> int | None:
        value = self.resource_loader_scope_args.get(loader_name)
        return None if value is None else int(value)

    def unconstrained_scope_for_loader(self, loader_name: str) -> bool:
        return loader_name in self.resource_loader_unconstrained_scopes

    def binding_relation_for_sink(self, sink_name: str) -> BindingRelation:
        return self.sink_binding_relations.get(sink_name, "equal")

    def authorized_projection_for_sink(self, sink_name: str) -> BindingProjection:
        return self.sink_authorized_projections.get(sink_name, "identity")

    def acted_projection_for_sink(self, sink_name: str) -> BindingProjection:
        return self.sink_acted_projections.get(sink_name, "identity")


def _name_of(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _expr(node: ast.AST) -> str:
    return ast.unparse(node)


def _const_str(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _origin(path: str, node: ast.AST) -> SemanticOrigin:
    return SemanticOrigin(
        path=path,
        extractor_id=_SOURCE_PROFILE_ID,
        extractor_version="0.2.0",
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


def _top_level_calls(handler: ast.FunctionDef | ast.AsyncFunctionDef) -> list[ast.Call]:
    calls: list[ast.Call] = []
    for statement in handler.body:
        for child in ast.walk(statement):
            if isinstance(child, ast.Call):
                calls.append(child)
    return sorted(calls, key=lambda item: (getattr(item, "lineno", 0), getattr(item, "col_offset", 0)))


def _has_control_flow(handler: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    return any(isinstance(node, _CONTROL_FLOW) for statement in handler.body for node in ast.walk(statement))


def _term_for_expr(
    node: ast.AST,
    aliases: dict[str, ResourceAlias],
    *,
    projection: BindingProjection,
) -> ResourceIdentityTerm | None:
    if isinstance(node, ast.Name) and node.id in aliases:
        alias = aliases[node.id]
        return alias.identity_term if projection == "identity" else alias.scope_term
    if isinstance(node, ast.Constant) and isinstance(node.value, (str, int, bool)):
        return ResourceIdentityTerm.literal(str(node.value))
    if isinstance(node, (ast.Name, ast.Attribute, ast.Subscript)):
        return ResourceIdentityTerm.symbol(_expr(node))
    return None


def _resource_aliases(
    handler: ast.FunctionDef | ast.AsyncFunctionDef,
    profile: ProtectedEffectProfile,
    *,
    path: str,
    unsupported: list[str],
) -> dict[str, ResourceAlias]:
    aliases: dict[str, ResourceAlias] = {}

    for statement in handler.body:
        target: ast.AST | None = None
        value: ast.AST | None = None
        if isinstance(statement, ast.Assign) and len(statement.targets) == 1:
            target = statement.targets[0]
            value = statement.value
        elif isinstance(statement, ast.AnnAssign):
            target = statement.target
            value = statement.value

        if not isinstance(target, ast.Name) or value is None:
            continue

        if isinstance(value, ast.Call):
            loader_name = _name_of(value.func)
            if loader_name is None:
                continue

            identity_arg = profile.identity_arg_for_loader(loader_name)
            scope_arg = profile.scope_arg_for_loader(loader_name)
            unconstrained_scope = profile.unconstrained_scope_for_loader(loader_name)
            if identity_arg is None and scope_arg is None and not unconstrained_scope:
                continue

            identity_term: ResourceIdentityTerm | None = None
            scope_term: ResourceIdentityTerm | None = None

            if identity_arg is not None:
                if len(value.args) <= identity_arg:
                    unsupported.append(
                        f"{path}:{handler.name}:unsupported_resource_loader_identity_signature:{loader_name}"
                    )
                else:
                    identity_term = _term_for_expr(
                        value.args[identity_arg],
                        aliases,
                        projection="identity",
                    )
                    if identity_term is None:
                        unsupported.append(
                            f"{path}:{handler.name}:unsupported_resource_identity_expression:{loader_name}"
                        )

            if scope_arg is not None:
                if len(value.args) <= scope_arg:
                    unsupported.append(
                        f"{path}:{handler.name}:unsupported_resource_loader_scope_signature:{loader_name}"
                    )
                else:
                    scope_term = _term_for_expr(
                        value.args[scope_arg],
                        aliases,
                        projection="identity",
                    )
                    if scope_term is None:
                        unsupported.append(
                            f"{path}:{handler.name}:unsupported_resource_scope_expression:{loader_name}"
                        )
            elif unconstrained_scope:
                # This is an explicit over-approximation: the loader is declared
                # capable of returning a resource from any scope.
                scope_term = ResourceIdentityTerm.symbol(f"$scope:{target.id}")

            aliases[target.id] = ResourceAlias(
                identity_term=identity_term,
                scope_term=scope_term,
            )
            continue

        if isinstance(value, ast.Name) and value.id in aliases:
            aliases[target.id] = aliases[value.id]
            continue

        identity_term = _term_for_expr(value, aliases, projection="identity")
        if identity_term is not None:
            aliases[target.id] = ResourceAlias(identity_term=identity_term)

    return aliases


class FastApiProtectedEffectExtractor:
    """Extract source-grounded protected effects from the supported FastAPI subset."""

    source_profile_id = _SOURCE_PROFILE_ID

    def compile(self, materials: AuthMaterials, profile: ProtectedEffectProfile) -> AssuranceIR:
        repo = materials.repo or "unknown/repo"
        subject = VerificationSubject(
            repo=repo,
            base_sha=materials.base_revision,
            head_sha=materials.head_revision or "unknown",
        )

        principals: dict[str, PrincipalRef] = {}
        resources: dict[str, ResourceRef] = {}
        effects: dict[str, EffectRef] = {}
        guards: dict[str, AuthorizationGuard] = {}
        protected_effects: dict[str, ProtectedEffect] = {}
        bindings: dict[str, ResourceBinding] = {}
        paths: dict[str, SemanticPath] = {}
        unsupported: list[str] = []

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
                    unsupported.append(f"{path}:{handler.name}:control_flow_outside_v1_subset")

                principal_expr = profile.principal_parameter
                principal_id = _semantic_id("principal", principal_expr)
                principals.setdefault(
                    principal_id,
                    PrincipalRef(
                        principal_id=principal_id,
                        symbol=principal_expr,
                        principal_type="fastapi_parameter",
                        origin=_origin(path, handler),
                    ),
                )

                resource_aliases = _resource_aliases(
                    handler,
                    profile,
                    path=path,
                    unsupported=unsupported,
                )
                calls = _top_level_calls(handler)
                guard_records: list[tuple[int, str, str, str]] = []
                # (line, guard_id, effect_name, resource_id)
                for call in calls:
                    call_name = _name_of(call.func)
                    if call_name not in profile.guard_functions:
                        continue
                    required_index = max(
                        profile.guard_principal_arg,
                        profile.guard_effect_arg,
                        profile.guard_resource_arg,
                    )
                    if len(call.args) <= required_index:
                        unsupported.append(f"{path}:{handler.name}:unsupported_guard_signature:{call_name}")
                        continue
                    effect_name = _const_str(call.args[profile.guard_effect_arg])
                    if effect_name is None:
                        unsupported.append(f"{path}:{handler.name}:dynamic_guard_effect:{call_name}")
                        continue
                    principal_symbol = _expr(call.args[profile.guard_principal_arg])
                    resource_symbol = _expr(call.args[profile.guard_resource_arg])
                    guard_principal_id = _semantic_id("principal", principal_symbol)
                    guard_resource_id = _semantic_id("resource", resource_symbol)
                    effect_id = _semantic_id("effect", effect_name)
                    guard_id = _semantic_id(
                        "guard",
                        (
                            f"{path}:{handler.name}:{getattr(call, 'lineno', 0)}:"
                            f"{principal_symbol}:{effect_name}:{resource_symbol}"
                        ),
                    )

                    principals.setdefault(
                        guard_principal_id,
                        PrincipalRef(
                            principal_id=guard_principal_id,
                            symbol=principal_symbol,
                            principal_type="expression",
                            origin=_origin(path, call.args[profile.guard_principal_arg]),
                        ),
                    )
                    guard_identity = _term_for_expr(
                        call.args[profile.guard_resource_arg],
                        resource_aliases,
                        projection="identity",
                    )
                    guard_scope = _term_for_expr(
                        call.args[profile.guard_resource_arg],
                        resource_aliases,
                        projection="scope",
                    )
                    resources.setdefault(
                        guard_resource_id,
                        ResourceRef(
                            resource_id=guard_resource_id,
                            symbol=resource_symbol,
                            identity_term=guard_identity,
                            scope_term=guard_scope,
                            origin=_origin(path, call.args[profile.guard_resource_arg]),
                        ),
                    )
                    effects.setdefault(
                        effect_id,
                        EffectRef(effect_id=effect_id, name=effect_name, origin=_origin(path, call)),
                    )
                    guards[guard_id] = AuthorizationGuard(
                        guard_id=guard_id,
                        principal_id=guard_principal_id,
                        effect_id=effect_id,
                        resource_id=guard_resource_id,
                        origin=_origin(path, call),
                    )
                    guard_records.append((getattr(call, "lineno", 0), guard_id, effect_name, guard_resource_id))

                for call in calls:
                    sink_name = _name_of(call.func)
                    if sink_name not in profile.sink_effects:
                        continue
                    resource_index = profile.resource_arg_for_sink(sink_name)
                    if len(call.args) <= resource_index:
                        unsupported.append(f"{path}:{handler.name}:unsupported_sink_signature:{sink_name}")
                        continue

                    effect_name = profile.sink_effects[sink_name]
                    effect_id = _semantic_id("effect", effect_name)
                    resource_symbol = _expr(call.args[resource_index])
                    acted_resource_id = _semantic_id("resource", resource_symbol)
                    sink_line = getattr(call, "lineno", 0)
                    protected_id = _semantic_id(
                        "protected",
                        f"{path}:{handler.name}:{sink_line}:{effect_name}:{resource_symbol}",
                    )

                    acted_identity = _term_for_expr(
                        call.args[resource_index],
                        resource_aliases,
                        projection="identity",
                    )
                    acted_scope = _term_for_expr(
                        call.args[resource_index],
                        resource_aliases,
                        projection="scope",
                    )
                    resources.setdefault(
                        acted_resource_id,
                        ResourceRef(
                            resource_id=acted_resource_id,
                            symbol=resource_symbol,
                            identity_term=acted_identity,
                            scope_term=acted_scope,
                            origin=_origin(path, call.args[resource_index]),
                        ),
                    )
                    effects.setdefault(
                        effect_id,
                        EffectRef(effect_id=effect_id, name=effect_name, origin=_origin(path, call)),
                    )

                    matching_guards = [
                        record for record in guard_records if record[0] < sink_line and record[2] == effect_name
                    ]
                    matching_guard_ids = [record[1] for record in matching_guards]

                    effect_principal_id = principal_id
                    if matching_guards:
                        latest_guard = guards[matching_guards[-1][1]]
                        effect_principal_id = latest_guard.principal_id

                    protected_effects[protected_id] = ProtectedEffect(
                        protected_effect_id=protected_id,
                        principal_id=effect_principal_id,
                        effect_id=effect_id,
                        resource_id=acted_resource_id,
                        origin=_origin(path, call),
                    )

                    relation = profile.binding_relation_for_sink(sink_name)
                    authorized_projection = profile.authorized_projection_for_sink(sink_name)
                    acted_projection = profile.acted_projection_for_sink(sink_name)

                    binding_ids: list[str] = []
                    for _, guard_id, _, authorized_resource_id in matching_guards:
                        trivial_identity = (
                            relation == "equal"
                            and authorized_projection == "identity"
                            and acted_projection == "identity"
                            and authorized_resource_id == acted_resource_id
                        )
                        if trivial_identity:
                            continue
                        binding_id = _semantic_id(
                            "binding",
                            (
                                f"{guard_id}:{authorized_resource_id}:{acted_resource_id}:"
                                f"{relation}:{authorized_projection}:{acted_projection}"
                            ),
                        )
                        bindings[binding_id] = ResourceBinding(
                            binding_id=binding_id,
                            authorized_resource_id=authorized_resource_id,
                            acted_resource_id=acted_resource_id,
                            relation=relation,
                            authorized_projection=authorized_projection,
                            acted_projection=acted_projection,
                            origin=_origin(path, call),
                        )
                        binding_ids.append(binding_id)

                    path_id = _semantic_id(
                        "path",
                        f"{method}:{route_path}:{handler.name}:{protected_id}",
                    )
                    paths[path_id] = SemanticPath(
                        path_id=path_id,
                        entrypoint=f"{method} {route_path}",
                        guard_ids=matching_guard_ids,
                        protected_effect_ids=[protected_id],
                        binding_ids=sorted(binding_ids),
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
                extractor_version="0.2.0",
                source_profile_id=_SOURCE_PROFILE_ID,
            ),
            coverage=AssuranceCoverage(
                status=coverage_status,
                confidence=confidence,
                supported_constructs=[
                    "static_fastapi_route_decorator",
                    "straight_line_handler",
                    "configured_positional_authorization_call",
                    "configured_positional_protected_sink",
                    "declared_identity_preserving_resource_loader",
                    "declared_scope_preserving_resource_loader",
                    "declared_unconstrained_resource_scope",
                ],
                unsupported_constructs=sorted(set(unsupported)),
                assumptions=[
                    "Configured guard functions are authorization decisions.",
                    "Configured sink functions faithfully identify protected effects.",
                    "Configured loader identity/scope semantics are trusted profile assumptions.",
                    "Unconstrained loader scope is an explicit conservative over-approximation.",
                    "Lexical ordering is used only inside the straight-line v1 handler subset.",
                ],
            ),
            principals=sorted(principals.values(), key=lambda item: item.principal_id),
            resources=sorted(resources.values(), key=lambda item: item.resource_id),
            effects=sorted(effects.values(), key=lambda item: item.effect_id),
            guards=sorted(guards.values(), key=lambda item: item.guard_id),
            protected_effects=sorted(protected_effects.values(), key=lambda item: item.protected_effect_id),
            resource_bindings=sorted(bindings.values(), key=lambda item: item.binding_id),
            paths=sorted(paths.values(), key=lambda item: item.path_id),
        )
