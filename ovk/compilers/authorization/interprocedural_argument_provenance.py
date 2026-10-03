"""Bounded interprocedural argument provenance.

For a callee parameter ``p``, provenance is the conservative lattice join of
every statically accounted callsite actual that binds to ``p``.

Supported callsites: direct ``Name`` calls and uniquely resolved imported /
module-attribute function calls with ordinary positional/keyword arguments
over a finite acyclic call graph, under caller-relative module-qualified
callee identity (#160). Request-time callable identity (#167) is applied
when the callsite sits inside a function body: mutations of module exports /
callable behavior before the callsite invalidate authorizing identity.

Deferred forms (*args, **kwargs, getattr, ambiguous imports, external
imports, cycles, etc.) yield UNKNOWN. Absence of an observed external
callsite is not a closure proof — an explicit scope proof is required for
established results.
"""

from __future__ import annotations

import ast
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Literal

from ovk.compilers.authorization.bypass_authority import ClosedWorldScopeProof
from ovk.compilers.authorization.python_callee_resolution import (
    CalleeResolver,
    CalleeResolveResult,
    begin_request_time_identity_session,
    build_callee_resolver_from_sources,
    index_unique_module_functions,
    normalize_path,
)
from ovk.compilers.authorization.value_origin import (
    AliasState,
    classify_expression_origin,
)
from ovk.core.assurance_ir import SemanticOrigin
from ovk.core.bundle import content_digest
from ovk.core.models import SourceRange


ArgumentProvenanceKind = Literal[
    "server_internal",
    "externally_bound_http",
    "unknown",
]

_IMPLEMENTATION_VERSION = "0.17.0"


@dataclass(frozen=True)
class CallsiteBinding:
    callsite_id: str
    path: str
    actual_expression: str
    origin_kind: str
    evidence_id: str | None
    unresolved_reason: str | None = None


@dataclass(frozen=True)
class InterproceduralArgumentProvenanceResult:
    callee_qualified_name: str
    parameter: str
    provenance: ArgumentProvenanceKind
    callsites: tuple[CallsiteBinding, ...]
    scope_digest: str | None
    reason: str


def _origin(path: str, node: ast.AST) -> SemanticOrigin:
    return SemanticOrigin(
        path=path,
        extractor_id="assurance.fastapi.interprocedural_arg.ast_v1",
        extractor_version=_IMPLEMENTATION_VERSION,
        source_range=SourceRange(
            path=path,
            start_line=getattr(node, "lineno", None),
            end_line=getattr(node, "end_lineno", getattr(node, "lineno", None)),
        ),
    )


def _scope_digest(scope_proof: ClosedWorldScopeProof) -> str:
    return content_digest(
        {
            "accounted_paths": list(scope_proof.accounted_paths),
            "source_roots": list(scope_proof.source_roots),
            "python_import_roots": list(scope_proof.python_import_roots),
            "implementation_version": _IMPLEMENTATION_VERSION,
        }
    )


def _function_params(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> tuple[str, ...] | None:
    args = node.args
    if args.vararg is not None or args.kwarg is not None:
        return None
    if args.posonlyargs or args.kwonlyargs:
        # Keep the first theorem narrow: ordinary positional + keyword.
        names = [item.arg for item in args.posonlyargs]
        names.extend(item.arg for item in args.args)
        names.extend(item.arg for item in args.kwonlyargs)
        return tuple(names)
    return tuple(item.arg for item in args.args)


def _shadowed_names_in_function(
    caller: ast.AST | None,
) -> frozenset[str]:
    """Names bound as parameters, stores, or nested defs in the enclosing function.

    Nested ``def``/``async def``/``class`` bindings shadow global callee names the
    same way parameters and assignments do. Omitting them lets a nested
    ``def generate`` pollute interprocedural provenance for the global
    ``generate`` (Unknown > false server_internal).
    """

    if caller is None or not isinstance(
        caller, (ast.FunctionDef, ast.AsyncFunctionDef)
    ):
        return frozenset()
    names: set[str] = set()
    params = _function_params(caller)
    if params:
        names.update(params)
    for node in ast.walk(caller):
        if node is caller:
            continue
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            names.add(node.id)
        elif isinstance(node, ast.arg):
            names.add(node.arg)
        elif isinstance(
            node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
        ):
            names.add(node.name)
    return frozenset(names)


def _maybe_targets_callee(func: ast.AST, callee_name: str) -> bool:
    """True when an unresolved callee form might still name ``callee_name``.

    Attribute calls whose final attribute equals the callee are deferred
    potential callsites and must poison the lattice (Unknown > false internal)
    when they cannot be uniquely resolved. Non-Name/non-matching forms that
    cannot be proved irrelevant also poison.
    """

    if isinstance(func, ast.Name):
        return False
    if isinstance(func, ast.Attribute):
        return func.attr == callee_name
    # Call / Subscript / Lambda / etc. could evaluate to the callee.
    return True


def _map_actual(
    call: ast.Call,
    *,
    params: Sequence[str],
    parameter: str,
) -> ast.AST | None | str:
    """Return the actual AST for ``parameter``, None if missing, or reason str."""

    if call.keywords and any(item.arg is None for item in call.keywords):
        return "kwargs_expansion"
    if any(isinstance(arg, ast.Starred) for arg in call.args):
        return "args_expansion"
    try:
        index = list(params).index(parameter)
    except ValueError:
        return "parameter_absent"
    if index < len(call.args):
        return call.args[index]
    for keyword in call.keywords:
        if keyword.arg == parameter:
            return keyword.value
    return None


def _lattice_join(kinds: Sequence[str]) -> ArgumentProvenanceKind:
    if not kinds:
        return "unknown"
    if any(kind == "unknown_origin" or kind.startswith("unknown") for kind in kinds):
        return "unknown"
    if any(kind == "externally_bound_http_value" for kind in kinds):
        return "externally_bound_http"
    if all(
        kind in {"server_configuration", "literal_constant"} for kind in kinds
    ):
        return "server_internal"
    return "unknown"


def _enclosing_function(
    tree: ast.AST,
    target: ast.AST,
) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    parent: dict[ast.AST, ast.AST] = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parent[child] = node
    cursor: ast.AST | None = target
    while cursor is not None:
        if isinstance(cursor, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return cursor
        cursor = parent.get(cursor)
    return None


def _resolve_callsite_with_request_time_identity(
    resolver: CalleeResolver,
    *,
    path: str,
    caller: ast.FunctionDef | ast.AsyncFunctionDef | None,
    call: ast.Call,
    shadowed_names: frozenset[str],
) -> CalleeResolveResult:
    """Resolve ``call`` under module bindings + request-time identity (#167)."""

    if caller is None:
        return resolver.resolve_call(
            call.func,
            caller_path=path,
            shadowed_names=shadowed_names,
        )
    session = begin_request_time_identity_session(
        resolver, path=path, fn=caller
    )
    call_lineno = getattr(call, "lineno", None)
    for stmt in caller.body:
        stmt_lineno = getattr(stmt, "lineno", None)
        # Observe only statements that strictly precede the callsite so
        # mutations after the call cannot poison this resolve (phase-sensitive).
        if (
            call_lineno is not None
            and stmt_lineno is not None
            and stmt_lineno >= call_lineno
        ):
            break
        session.observe_statement(stmt)
    return session.resolve_call(call.func, shadowed_names=shadowed_names)


def analyze_interprocedural_argument_provenance(
    files: Mapping[str, str],
    *,
    callee_name: str,
    parameter: str,
    scope_proof: ClosedWorldScopeProof,
) -> InterproceduralArgumentProvenanceResult:
    """Prove or refuse provenance for one callee parameter under a scope proof."""

    normalized = {
        normalize_path(path): source for path, source in files.items()
    }
    accounted = tuple(normalize_path(path) for path in scope_proof.accounted_paths)
    scope_digest = _scope_digest(scope_proof)
    if set(accounted) != set(normalized):
        return InterproceduralArgumentProvenanceResult(
            callee_qualified_name=callee_name,
            parameter=parameter,
            provenance="unknown",
            callsites=(),
            scope_digest=scope_digest,
            reason="scope_proof_file_set_mismatch",
        )

    resolver = build_callee_resolver_from_sources(
        normalized,
        import_roots=scope_proof.python_import_roots,
    )
    functions = index_unique_module_functions(resolver.trees)
    if callee_name not in functions:
        return InterproceduralArgumentProvenanceResult(
            callee_qualified_name=callee_name,
            parameter=parameter,
            provenance="unknown",
            callsites=(),
            scope_digest=scope_digest,
            reason="callee_not_uniquely_resolved",
        )

    target = functions[callee_name]
    callee_path = target.path
    callee_node = target.node
    params = _function_params(callee_node)
    if params is None or parameter not in params:
        return InterproceduralArgumentProvenanceResult(
            callee_qualified_name=target.qualified_name,
            parameter=parameter,
            provenance="unknown",
            callsites=(),
            scope_digest=scope_digest,
            reason="callee_signature_unsupported_or_parameter_missing",
        )

    bindings: list[CallsiteBinding] = []
    unresolved = False
    for path, tree in sorted(resolver.trees.items()):
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            caller = _enclosing_function(tree, node)
            shadowed = _shadowed_names_in_function(caller)
            resolved = _resolve_callsite_with_request_time_identity(
                resolver,
                path=path,
                caller=caller,
                call=node,
                shadowed_names=shadowed,
            )
            if resolved.callee is None:
                reason = resolved.reason or "deferred_callee_form"
                # Name forms: only poison when the unresolved binding might still
                # be the analysis target (ambiguous / incomplete follow). Plain
                # unbound, shadowed, external, or rebound Names are a different
                # runtime identity and must not authorize — omit them.
                if isinstance(node.func, ast.Name):
                    if node.func.id != callee_name:
                        continue
                    if reason in {
                        "shadowed_local_binding",
                        "unbound_name",
                        "external_import",
                        "module_level_rebinding",
                        "module_alias_not_callable",
                        "unresolved_binding",
                        "caller_module_absent",
                    }:
                        continue
                    if reason in {
                        "ambiguous_manifest",
                        "import_follow_depth",
                        "callable_behavior_unknown",
                        "request_time_callable_identity_unknown",
                    }:
                        unresolved = True
                        bindings.append(
                            CallsiteBinding(
                                callsite_id=(
                                    f"callsite:{path}:{getattr(node, 'lineno', 0)}"
                                ),
                                path=path,
                                actual_expression=ast.unparse(node),
                                origin_kind="unknown_origin",
                                evidence_id=None,
                                unresolved_reason=reason,
                            )
                        )
                    continue
                # Deferred Attribute / compound forms that might target this
                # callee must poison provenance. Silent omit enables false
                # server_internal. Request-time identity unknown is the same.
                if reason == "request_time_callable_identity_unknown" or _maybe_targets_callee(
                    node.func, callee_name
                ):
                    unresolved = True
                    bindings.append(
                        CallsiteBinding(
                            callsite_id=(
                                f"callsite:{path}:{getattr(node, 'lineno', 0)}"
                            ),
                            path=path,
                            actual_expression=ast.unparse(node),
                            origin_kind="unknown_origin",
                            evidence_id=None,
                            unresolved_reason=reason
                            if reason
                            else "deferred_callee_form",
                        )
                    )
                continue

            if resolved.callee.identity != target.identity:
                continue

            if (
                caller is not None
                and path == callee_path
                and caller.name == callee_name
            ):
                unresolved = True
                bindings.append(
                    CallsiteBinding(
                        callsite_id=(
                            f"callsite:{path}:{getattr(node, 'lineno', 0)}"
                        ),
                        path=path,
                        actual_expression=ast.unparse(node),
                        origin_kind="unknown_origin",
                        evidence_id=None,
                        unresolved_reason="recursive_call_deferred",
                    )
                )
                continue
            actual = _map_actual(node, params=params, parameter=parameter)
            callsite_id = f"callsite:{path}:{getattr(node, 'lineno', 0)}"
            if isinstance(actual, str):
                unresolved = True
                bindings.append(
                    CallsiteBinding(
                        callsite_id=callsite_id,
                        path=path,
                        actual_expression=ast.unparse(node),
                        origin_kind="unknown_origin",
                        evidence_id=None,
                        unresolved_reason=actual,
                    )
                )
                continue
            if actual is None:
                unresolved = True
                bindings.append(
                    CallsiteBinding(
                        callsite_id=callsite_id,
                        path=path,
                        actual_expression=ast.unparse(node),
                        origin_kind="unknown_origin",
                        evidence_id=None,
                        unresolved_reason="argument_not_supplied",
                    )
                )
                continue
            param_names = (
                frozenset(_function_params(caller) or ())
                if caller is not None
                else frozenset()
            )
            evidence = classify_expression_origin(
                actual,
                path=path,
                handler_param_names=param_names,
                alias_state=AliasState(),
            )
            bindings.append(
                CallsiteBinding(
                    callsite_id=callsite_id,
                    path=path,
                    actual_expression=ast.unparse(actual),
                    origin_kind=evidence.origin_kind,
                    evidence_id=evidence.evidence_id,
                )
            )

    if not bindings:
        return InterproceduralArgumentProvenanceResult(
            callee_qualified_name=target.qualified_name,
            parameter=parameter,
            provenance="unknown",
            callsites=(),
            scope_digest=scope_digest,
            reason="no_accounted_callsites",
        )

    if unresolved or any(item.unresolved_reason for item in bindings):
        return InterproceduralArgumentProvenanceResult(
            callee_qualified_name=target.qualified_name,
            parameter=parameter,
            provenance="unknown",
            callsites=tuple(bindings),
            scope_digest=scope_digest,
            reason="unresolved_callsite_or_deferred_form",
        )

    provenance = _lattice_join([item.origin_kind for item in bindings])
    reason = {
        "server_internal": "all_callsites_server_or_literal_origin",
        "externally_bound_http": "callsite_externally_bound_http_origin",
        "unknown": "mixed_or_unknown_callsite_origins",
    }[provenance]
    return InterproceduralArgumentProvenanceResult(
        callee_qualified_name=target.qualified_name,
        parameter=parameter,
        provenance=provenance,
        callsites=tuple(bindings),
        scope_digest=scope_digest,
        reason=reason,
    )
