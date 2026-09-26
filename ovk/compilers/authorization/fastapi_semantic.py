"""FastAPI source-to-Assurance-IR compiler.

The compiler intentionally trusts only repository-declared semantic anchors:
principal dependencies, authorization-call signatures, and protected sinks.
It does not infer security policy from names or LLM output.

The initial profile is deliberately narrow. Unsupported control flow and dynamic
framework behavior remain explicit IR unknowns and downgrade provenance coverage.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator

from ovk.compilers.authorization.base import normalize_path
from ovk.compilers.authorization.material_loader import AuthMaterials
from ovk.core.assurance_ir import (
    AssuranceIR,
    AuthorizationGuard,
    BindingConstraint,
    EffectRef,
    PrincipalRef,
    ProtectedEffect,
    ResourceRef,
    SemanticPath,
    SourceProvenance,
)
from ovk.core.bundle import content_digest
from ovk.core.models import SourceRange, VerificationSubject


SOURCE_PROFILE_ID = "authorization.fastapi.semantic_v2"
EXTRACTOR_VERSION = "0.1.0"
_HTTP_METHODS = frozenset({"get", "post", "put", "patch", "delete", "options", "head"})
_EFFECT_RE = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)+$")


class PrincipalDependencySpec(BaseModel):
    """Trusted mapping from a FastAPI dependency to an application principal."""

    dependency: str
    kind: Literal["human", "service", "agent"] = "human"


class AuthorizationCallSpec(BaseModel):
    """Trusted signature for an application authorization function."""

    function: str
    principal_arg: int = 0
    effect_arg: int = 1
    resource_arg: int = 2
    resource_type: str = "resource"

    @model_validator(mode="after")
    def argument_positions_are_distinct(self) -> "AuthorizationCallSpec":
        positions = [self.principal_arg, self.effect_arg, self.resource_arg]
        if min(positions) < 0 or len(set(positions)) != len(positions):
            raise ValueError("authorization argument positions must be distinct non-negative integers")
        return self


class ProtectedSinkSpec(BaseModel):
    """Trusted declaration of a security-sensitive application effect."""

    function: str
    effect_name: str
    resource_arg: int = 0
    resource_type: str
    severity: Literal["low", "medium", "high", "critical"] = "high"

    @field_validator("effect_name")
    @classmethod
    def effect_is_namespaced(cls, value: str) -> str:
        value = value.strip()
        if not _EFFECT_RE.fullmatch(value):
            raise ValueError("effect_name must be namespaced, for example billing.invoice.refund")
        return value

    @field_validator("resource_arg")
    @classmethod
    def resource_arg_is_non_negative(cls, value: int) -> int:
        if value < 0:
            raise ValueError("resource_arg must be non-negative")
        return value


class FastApiSemanticConfig(BaseModel):
    """Repository-approved semantic anchors for the v2 source profile."""

    principal_dependencies: list[PrincipalDependencySpec] = Field(default_factory=list)
    authorization_calls: list[AuthorizationCallSpec] = Field(default_factory=list)
    protected_sinks: list[ProtectedSinkSpec] = Field(default_factory=list)

    @model_validator(mode="after")
    def identities_are_unambiguous(self) -> "FastApiSemanticConfig":
        for name, values in (
            ("principal dependency", [item.dependency for item in self.principal_dependencies]),
            ("authorization function", [item.function for item in self.authorization_calls]),
            ("protected sink", [item.function for item in self.protected_sinks]),
        ):
            duplicates = sorted({value for value in values if values.count(value) > 1})
            if duplicates:
                raise ValueError(f"duplicate {name} declarations: {', '.join(duplicates)}")
        return self


@dataclass(frozen=True)
class _CallSite:
    call: ast.Call
    name: str
    line: int
    end_line: int


def _qualified_name(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _qualified_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return None


def _const_str(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _expression(node: ast.AST | None) -> str | None:
    if node is None:
        return None
    try:
        return ast.unparse(node).strip()
    except Exception:
        return None


def _source_range(path: str, node: ast.AST) -> SourceRange:
    return SourceRange(
        path=path,
        start_line=getattr(node, "lineno", None),
        end_line=getattr(node, "end_lineno", getattr(node, "lineno", None)),
        start_column=getattr(node, "col_offset", None),
        end_column=getattr(node, "end_col_offset", None),
    )


def _dependency_name(node: ast.AST | None) -> str | None:
    if node is None:
        return None
    for child in ast.walk(node):
        if isinstance(child, ast.Call) and _qualified_name(child.func) in {"Depends", "Security"} and child.args:
            return _qualified_name(child.args[0])
    return None


def _positional_parameter_defaults(handler: ast.FunctionDef | ast.AsyncFunctionDef) -> dict[str, ast.AST | None]:
    params = list(handler.args.posonlyargs) + list(handler.args.args)
    defaults: list[ast.AST | None] = [None] * (len(params) - len(handler.args.defaults)) + list(handler.args.defaults)
    result = {param.arg: default for param, default in zip(params, defaults)}
    for param, default in zip(handler.args.kwonlyargs, handler.args.kw_defaults):
        result[param.arg] = default
    return result


def _http_route(
    handler: ast.FunctionDef | ast.AsyncFunctionDef,
    *,
    router_prefixes: dict[str, str],
) -> tuple[str, str] | None:
    for decorator in handler.decorator_list:
        if not isinstance(decorator, ast.Call) or not isinstance(decorator.func, ast.Attribute):
            continue
        method = decorator.func.attr.lower()
        if method not in _HTTP_METHODS:
            continue
        if not decorator.args:
            return None
        route_path = _const_str(decorator.args[0])
        if route_path is None:
            return None
        router = _qualified_name(decorator.func.value) or "app"
        prefix = router_prefixes.get(router, "")
        return method.upper(), normalize_path(prefix, route_path)
    return None


def _has_http_decorator(handler: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    return any(
        isinstance(decorator, ast.Call)
        and isinstance(decorator.func, ast.Attribute)
        and decorator.func.attr.lower() in _HTTP_METHODS
        for decorator in handler.decorator_list
    )


def _router_prefixes(tree: ast.Module, *, path: str, unknowns: list[str]) -> dict[str, str]:
    prefixes: dict[str, str] = {}
    for node in tree.body:
        if not isinstance(node, ast.Assign) or not isinstance(node.value, ast.Call):
            continue
        if _qualified_name(node.value.func) not in {"APIRouter", "fastapi.APIRouter"}:
            continue
        prefix_node = next((kw.value for kw in node.value.keywords if kw.arg == "prefix"), None)
        prefix = "" if prefix_node is None else _const_str(prefix_node)
        for target in node.targets:
            if not isinstance(target, ast.Name):
                continue
            if prefix is None:
                unknowns.append(f"{path}:dynamic_router_prefix:{target.id}")
            else:
                prefixes[target.id] = prefix
    return prefixes


class _HandlerVisitor(ast.NodeVisitor):
    """Collect direct handler call sites while flagging unsupported flow."""

    def __init__(self, handler: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        self.handler = handler
        self.calls: list[_CallSite] = []
        self.unsupported: list[str] = []

    def collect(self) -> tuple[list[_CallSite], list[str]]:
        for statement in self.handler.body:
            self.visit(statement)
        self.calls.sort(key=lambda item: (item.line, item.end_line, item.name))
        return self.calls, sorted(set(self.unsupported))

    def visit_Call(self, node: ast.Call) -> None:
        name = _qualified_name(node.func)
        if name:
            self.calls.append(
                _CallSite(
                    call=node,
                    name=name,
                    line=getattr(node, "lineno", 0),
                    end_line=getattr(node, "end_lineno", getattr(node, "lineno", 0)),
                )
            )
        self.generic_visit(node)

    def visit_If(self, node: ast.If) -> None:
        self.unsupported.append("unsupported_control_flow:if")
        self.generic_visit(node)

    def visit_For(self, node: ast.For) -> None:
        self.unsupported.append("unsupported_control_flow:for")
        self.generic_visit(node)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
        self.unsupported.append("unsupported_control_flow:async_for")
        self.generic_visit(node)

    def visit_While(self, node: ast.While) -> None:
        self.unsupported.append("unsupported_control_flow:while")
        self.generic_visit(node)

    def visit_Try(self, node: ast.Try) -> None:
        self.unsupported.append("unsupported_control_flow:try")
        self.generic_visit(node)

    def visit_With(self, node: ast.With) -> None:
        self.unsupported.append("unsupported_control_flow:with")
        self.generic_visit(node)

    def visit_AsyncWith(self, node: ast.AsyncWith) -> None:
        self.unsupported.append("unsupported_control_flow:async_with")
        self.generic_visit(node)

    def visit_Match(self, node: ast.Match) -> None:
        self.unsupported.append("unsupported_control_flow:match")
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.unsupported.append(f"nested_callable_not_modeled:{node.name}")

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.unsupported.append(f"nested_callable_not_modeled:{node.name}")

    def visit_Lambda(self, node: ast.Lambda) -> None:
        self.unsupported.append("nested_callable_not_modeled:lambda")


class FastApiSemanticAssuranceCompiler:
    """Compile supported FastAPI handler semantics into Assurance IR."""

    source_profile_id = SOURCE_PROFILE_ID
    framework = "fastapi"

    def __init__(self, config: FastApiSemanticConfig) -> None:
        self.config = config
        self._principal_specs = {item.dependency: item for item in config.principal_dependencies}
        self._auth_specs = {item.function: item for item in config.authorization_calls}
        self._sink_specs = {item.function: item for item in config.protected_sinks}

    def compile(self, materials: AuthMaterials) -> AssuranceIR:
        subject = VerificationSubject(
            repo=materials.repo or "unknown/repo",
            head_sha=materials.head_revision or "unknown",
            base_sha=materials.base_revision,
        )
        principals: dict[str, PrincipalRef] = {}
        resources: dict[str, ResourceRef] = {}
        effects: dict[str, EffectRef] = {}
        guards: list[AuthorizationGuard] = []
        protected_effects: list[ProtectedEffect] = []
        bindings: list[BindingConstraint] = []
        paths: list[SemanticPath] = []
        unknowns: list[str] = []

        if not materials.has_head():
            unknowns.append("head_materials_missing")

        for path, source in sorted(materials.head_files.items()):
            try:
                tree = ast.parse(source, filename=path)
            except SyntaxError as exc:
                unknowns.append(f"{path}:syntax_error:{exc.msg}")
                continue

            prefixes = _router_prefixes(tree, path=path, unknowns=unknowns)
            if any(
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "include_router"
                for node in ast.walk(tree)
            ):
                unknowns.append(f"{path}:include_router_mount_not_modeled")

            for handler in tree.body:
                if not isinstance(handler, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                if not _has_http_decorator(handler):
                    continue
                route = _http_route(handler, router_prefixes=prefixes)
                if route is None:
                    unknowns.append(f"{path}:{handler.name}:dynamic_route_path")
                    continue
                method, route_path = route
                handler_unknowns: list[str] = []

                route_principals = self._principals_from_handler(
                    handler,
                    path=path,
                    subject=subject,
                    principals=principals,
                    unknowns=handler_unknowns,
                )
                route_principal = self._route_principal(
                    route_principals,
                    path=path,
                    handler=handler,
                    subject=subject,
                    principals=principals,
                    unknowns=handler_unknowns,
                )

                calls, unsupported = _HandlerVisitor(handler).collect()
                handler_unknowns.extend(f"{path}:{handler.name}:{item}" for item in unsupported)

                handler_guards: list[tuple[AuthorizationGuard, str, int]] = []
                for site in calls:
                    spec = self._auth_specs.get(site.name)
                    if spec is None:
                        continue
                    guard_tuple = self._guard_from_call(
                        site,
                        spec=spec,
                        path=path,
                        handler=handler,
                        subject=subject,
                        principals=principals,
                        resources=resources,
                        effects=effects,
                        unknowns=handler_unknowns,
                    )
                    if guard_tuple is not None:
                        handler_guards.append(guard_tuple)
                        guards.append(guard_tuple[0])

                for site in calls:
                    sink_spec = self._sink_specs.get(site.name)
                    if sink_spec is None:
                        continue
                    sink_resource = self._resource_from_argument(
                        site.call,
                        position=sink_spec.resource_arg,
                        resource_type=sink_spec.resource_type,
                        path=path,
                        handler=handler,
                        subject=subject,
                        resources=resources,
                        unknowns=handler_unknowns,
                        role="sink",
                    )
                    if sink_resource is None:
                        continue
                    effect = self._effect(
                        sink_spec.effect_name,
                        path=path,
                        node=site.call,
                        subject=subject,
                        effects=effects,
                        coverage="partial" if handler_unknowns else "complete",
                    )
                    sink_id = f"protected.{content_digest({'path': path, 'handler': handler.name, 'line': site.line, 'sink': site.name})[:16]}"
                    sink_provenance = self._provenance(
                        subject,
                        path,
                        site.call,
                        coverage="partial" if handler_unknowns else "complete",
                        notes=handler_unknowns,
                    )
                    protected = ProtectedEffect(
                        protected_effect_id=sink_id,
                        principal_ref=route_principal.principal_id,
                        effect_ref=effect.effect_id,
                        resource_ref=sink_resource.resource_id,
                        sink=site.name,
                        severity=sink_spec.severity,
                        provenance=sink_provenance,
                    )
                    protected_effects.append(protected)

                    matching = [
                        item
                        for item in handler_guards
                        if item[1] == sink_spec.effect_name and item[2] <= site.line
                    ]
                    guard_refs = [item[0].guard_id for item in matching]
                    for guard, _effect_name, _line in matching:
                        bindings.extend(
                            self._binding_constraints(
                                guard,
                                protected,
                                path=path,
                                handler=handler,
                                subject=subject,
                                node=site.call,
                                partial=bool(handler_unknowns),
                            )
                        )

                    paths.append(
                        SemanticPath(
                            path_id=f"path.{content_digest({'path': path, 'handler': handler.name, 'sink': sink_id})[:16]}",
                            entrypoint=f"{method} {route_path}",
                            protected_effect_ref=protected.protected_effect_id,
                            guard_refs=guard_refs,
                            call_chain=[
                                handler.name,
                                *[item[0].decision_expression or item[0].guard_id for item in matching],
                                site.name,
                            ],
                            provenance=sink_provenance,
                        )
                    )

                unknowns.extend(handler_unknowns)

        return AssuranceIR(
            subject=subject,
            principals=sorted(principals.values(), key=lambda item: item.principal_id),
            resources=sorted(resources.values(), key=lambda item: item.resource_id),
            effects=sorted(effects.values(), key=lambda item: item.effect_id),
            guards=sorted(guards, key=lambda item: item.guard_id),
            protected_effects=sorted(protected_effects, key=lambda item: item.protected_effect_id),
            bindings=sorted(bindings, key=lambda item: item.binding_id),
            semantic_paths=sorted(paths, key=lambda item: item.path_id),
            assumptions=[
                "Only repository-declared principal dependencies, authorization calls, and protected sinks are trusted.",
                "The v2 profile models supported direct FastAPI handlers; unsupported framework/control-flow semantics are explicit unknowns.",
            ],
            unknowns=sorted(set(unknowns)),
        )

    def _principals_from_handler(
        self,
        handler: ast.FunctionDef | ast.AsyncFunctionDef,
        *,
        path: str,
        subject: VerificationSubject,
        principals: dict[str, PrincipalRef],
        unknowns: list[str],
    ) -> list[PrincipalRef]:
        defaults = _positional_parameter_defaults(handler)
        params = list(handler.args.posonlyargs) + list(handler.args.args) + list(handler.args.kwonlyargs)
        found: list[PrincipalRef] = []
        for param in params:
            dependency = _dependency_name(defaults.get(param.arg)) or _dependency_name(param.annotation)
            if dependency is None:
                continue
            spec = self._principal_specs.get(dependency)
            if spec is None:
                continue
            principal = self._principal(
                expression=param.arg,
                kind=spec.kind,
                path=path,
                handler=handler,
                node=param,
                subject=subject,
                principals=principals,
                coverage="complete",
            )
            principal.attributes["dependency"] = dependency
            found.append(principal)
        return found

    def _route_principal(
        self,
        candidates: list[PrincipalRef],
        *,
        path: str,
        handler: ast.FunctionDef | ast.AsyncFunctionDef,
        subject: VerificationSubject,
        principals: dict[str, PrincipalRef],
        unknowns: list[str],
    ) -> PrincipalRef:
        if len(candidates) == 1:
            return candidates[0]
        reason = "principal_dependency_missing" if not candidates else "multiple_principal_dependencies"
        unknowns.append(f"{path}:{handler.name}:{reason}")
        return self._principal(
            expression=f"<{reason}>",
            kind="unknown",
            path=path,
            handler=handler,
            node=handler,
            subject=subject,
            principals=principals,
            coverage="partial",
        )

    def _guard_from_call(
        self,
        site: _CallSite,
        *,
        spec: AuthorizationCallSpec,
        path: str,
        handler: ast.FunctionDef | ast.AsyncFunctionDef,
        subject: VerificationSubject,
        principals: dict[str, PrincipalRef],
        resources: dict[str, ResourceRef],
        effects: dict[str, EffectRef],
        unknowns: list[str],
    ) -> tuple[AuthorizationGuard, str, int] | None:
        required_index = max(spec.principal_arg, spec.effect_arg, spec.resource_arg)
        if len(site.call.args) <= required_index:
            unknowns.append(f"{path}:{handler.name}:authorization_call_arity:{site.name}:{site.line}")
            return None

        principal_expr = _expression(site.call.args[spec.principal_arg])
        effect_name = _const_str(site.call.args[spec.effect_arg])
        if principal_expr is None:
            unknowns.append(f"{path}:{handler.name}:authorization_principal_unresolved:{site.name}:{site.line}")
            return None
        if effect_name is None or not _EFFECT_RE.fullmatch(effect_name):
            unknowns.append(f"{path}:{handler.name}:authorization_effect_unresolved:{site.name}:{site.line}")
            return None

        principal = self._principal(
            expression=principal_expr,
            kind="unknown",
            path=path,
            handler=handler,
            node=site.call.args[spec.principal_arg],
            subject=subject,
            principals=principals,
            coverage="complete",
        )
        resource = self._resource_from_argument(
            site.call,
            position=spec.resource_arg,
            resource_type=spec.resource_type,
            path=path,
            handler=handler,
            subject=subject,
            resources=resources,
            unknowns=unknowns,
            role="authorization",
        )
        if resource is None:
            return None
        effect = self._effect(
            effect_name,
            path=path,
            node=site.call.args[spec.effect_arg],
            subject=subject,
            effects=effects,
            coverage="complete",
        )
        guard = AuthorizationGuard(
            guard_id=f"guard.{content_digest({'path': path, 'handler': handler.name, 'line': site.line, 'call': site.name})[:16]}",
            principal_ref=principal.principal_id,
            effect_ref=effect.effect_id,
            resource_ref=resource.resource_id,
            decision_expression=_expression(site.call),
            policy_ref=site.name,
            provenance=self._provenance(subject, path, site.call, coverage="complete"),
        )
        return guard, effect_name, site.line

    def _principal(
        self,
        *,
        expression: str,
        kind: Literal["human", "service", "agent", "anonymous", "unknown"],
        path: str,
        handler: ast.FunctionDef | ast.AsyncFunctionDef,
        node: ast.AST,
        subject: VerificationSubject,
        principals: dict[str, PrincipalRef],
        coverage: Literal["complete", "partial"],
    ) -> PrincipalRef:
        key = f"{path}:{handler.name}:{expression}"
        principal_id = f"principal.{content_digest({'scope': key})[:16]}"
        current = principals.get(principal_id)
        if current is not None:
            if current.kind == "unknown" and kind != "unknown":
                current = current.model_copy(update={"kind": kind})
                principals[principal_id] = current
            return current
        principal = PrincipalRef(
            principal_id=principal_id,
            kind=kind,
            expression=expression,
            provenance=self._provenance(subject, path, node, coverage=coverage),
        )
        principals[principal_id] = principal
        return principal

    def _resource_from_argument(
        self,
        call: ast.Call,
        *,
        position: int,
        resource_type: str,
        path: str,
        handler: ast.FunctionDef | ast.AsyncFunctionDef,
        subject: VerificationSubject,
        resources: dict[str, ResourceRef],
        unknowns: list[str],
        role: str,
    ) -> ResourceRef | None:
        if len(call.args) <= position:
            unknowns.append(
                f"{path}:{handler.name}:{role}_resource_arity:{_qualified_name(call.func) or 'call'}:{getattr(call, 'lineno', 0)}"
            )
            return None
        node = call.args[position]
        expression = _expression(node)
        if expression is None:
            unknowns.append(
                f"{path}:{handler.name}:{role}_resource_unresolved:{_qualified_name(call.func) or 'call'}:{getattr(call, 'lineno', 0)}"
            )
            return None
        key = {"path": path, "handler": handler.name, "type": resource_type, "expression": expression}
        resource_id = f"resource.{content_digest(key)[:16]}"
        current = resources.get(resource_id)
        if current is not None:
            return current
        resource = ResourceRef(
            resource_id=resource_id,
            resource_type=resource_type,
            expression=expression,
            provenance=self._provenance(subject, path, node, coverage="complete"),
        )
        resources[resource_id] = resource
        return resource

    def _effect(
        self,
        name: str,
        *,
        path: str,
        node: ast.AST,
        subject: VerificationSubject,
        effects: dict[str, EffectRef],
        coverage: Literal["complete", "partial"],
    ) -> EffectRef:
        effect_id = f"effect.{name}"
        current = effects.get(effect_id)
        if current is not None:
            return current
        effect = EffectRef(
            effect_id=effect_id,
            name=name,
            operation=name.rsplit(".", 1)[-1],
            provenance=self._provenance(subject, path, node, coverage=coverage),
        )
        effects[effect_id] = effect
        return effect

    def _binding_constraints(
        self,
        guard: AuthorizationGuard,
        protected: ProtectedEffect,
        *,
        path: str,
        handler: ast.FunctionDef | ast.AsyncFunctionDef,
        subject: VerificationSubject,
        node: ast.AST,
        partial: bool,
    ) -> list[BindingConstraint]:
        pairs = [
            ("principal", guard.principal_ref, protected.principal_ref),
            ("effect", guard.effect_ref, protected.effect_ref),
            ("resource", guard.resource_ref, protected.resource_ref),
        ]
        result: list[BindingConstraint] = []
        for kind, left, right in pairs:
            relation = "equal" if left == right else "unknown"
            result.append(
                BindingConstraint(
                    binding_id=f"binding.{content_digest({'path': path, 'handler': handler.name, 'guard': guard.guard_id, 'sink': protected.protected_effect_id, 'kind': kind})[:16]}",
                    kind=kind,
                    left_ref=left,
                    right_ref=right,
                    relation=relation,
                    provenance=self._provenance(
                        subject,
                        path,
                        node,
                        coverage="partial" if partial else "complete",
                    ),
                )
            )
        return result

    @staticmethod
    def _provenance(
        subject: VerificationSubject,
        path: str,
        node: ast.AST,
        *,
        coverage: Literal["complete", "partial"],
        notes: list[str] | None = None,
    ) -> SourceProvenance:
        return SourceProvenance(
            extractor_id=SOURCE_PROFILE_ID,
            extractor_version=EXTRACTOR_VERSION,
            subject=subject,
            source_ranges=[_source_range(path, node)],
            coverage=coverage,
            notes=sorted(set(notes or [])),
        )
