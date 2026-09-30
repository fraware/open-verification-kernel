"""Bounded interprocedural argument provenance.

For a callee parameter ``p``, provenance is the conservative lattice join of
every statically accounted callsite actual that binds to ``p``.

Supported callsites: direct ``Name`` calls and uniquely resolved imported
function calls with ordinary positional/keyword arguments over a finite
acyclic call graph.

Deferred forms (*args, **kwargs, getattr, ambiguous imports, cycles, etc.)
yield UNKNOWN. Absence of an observed external callsite is not a closure
proof — an explicit scope proof is required for established results.
"""

from __future__ import annotations

import ast
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Literal

from ovk.compilers.authorization.bypass_authority import ClosedWorldScopeProof
from ovk.compilers.authorization.value_origin import (
    AliasState,
    classify_expression_origin,
)
from ovk.core.assurance_ir import SemanticOrigin, ValueOriginEvidence
from ovk.core.bundle import content_digest
from ovk.core.models import SourceRange


ArgumentProvenanceKind = Literal[
    "server_internal",
    "externally_bound_http",
    "unknown",
]

_IMPLEMENTATION_VERSION = "0.1.0"


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


def _normalize(path: str) -> str:
    return path.replace("\\", "/")


def _scope_digest(scope_proof: ClosedWorldScopeProof) -> str:
    return content_digest(
        {
            "accounted_paths": list(scope_proof.accounted_paths),
            "source_roots": list(scope_proof.source_roots),
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


def _index_functions(
    files: Mapping[str, str],
) -> dict[str, tuple[str, ast.FunctionDef | ast.AsyncFunctionDef]]:
    """Map simple function name -> unique (path, node) when unambiguous."""

    found: dict[str, list[tuple[str, ast.FunctionDef | ast.AsyncFunctionDef]]] = {}
    for path, source in files.items():
        tree = ast.parse(source, filename=path)
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                found.setdefault(node.name, []).append((_normalize(path), node))
    unique: dict[str, tuple[str, ast.FunctionDef | ast.AsyncFunctionDef]] = {}
    for name, items in found.items():
        if len(items) == 1:
            unique[name] = items[0]
    return unique


def _resolve_callee_name(
    func: ast.AST,
    *,
    import_aliases: Mapping[str, str],
) -> str | None:
    if isinstance(func, ast.Name):
        return import_aliases.get(func.id, func.id)
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        # module.func where module is a uniquely imported module alias — deferred
        # unless the alias maps to a bare function name in this theorem.
        return None
    return None


def _collect_import_aliases(tree: ast.AST) -> dict[str, str] | None:
    """Return alias->name for unique function imports, or None if ambiguous/deferred."""

    aliases: dict[str, str] = {}
    for node in tree.body:  # type: ignore[attr-defined]
        if isinstance(node, ast.ImportFrom):
            if any(alias.name == "*" for alias in node.names):
                return None
            for alias in node.names:
                local = alias.asname or alias.name
                if local in aliases and aliases[local] != alias.name:
                    return None
                aliases[local] = alias.name
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if "." in alias.name:
                    return None
                local = alias.asname or alias.name
                if local in aliases:
                    return None
                # Module import alone does not resolve function calls.
    return aliases


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


def analyze_interprocedural_argument_provenance(
    files: Mapping[str, str],
    *,
    callee_name: str,
    parameter: str,
    scope_proof: ClosedWorldScopeProof,
) -> InterproceduralArgumentProvenanceResult:
    """Prove or refuse provenance for one callee parameter under a scope proof."""

    normalized = {
        _normalize(path): source for path, source in files.items()
    }
    accounted = tuple(_normalize(path) for path in scope_proof.accounted_paths)
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

    functions = _index_functions(normalized)
    if callee_name not in functions:
        return InterproceduralArgumentProvenanceResult(
            callee_qualified_name=callee_name,
            parameter=parameter,
            provenance="unknown",
            callsites=(),
            scope_digest=scope_digest,
            reason="callee_not_uniquely_resolved",
        )

    callee_path, callee_node = functions[callee_name]
    params = _function_params(callee_node)
    if params is None or parameter not in params:
        return InterproceduralArgumentProvenanceResult(
            callee_qualified_name=f"{callee_path}:{callee_name}",
            parameter=parameter,
            provenance="unknown",
            callsites=(),
            scope_digest=scope_digest,
            reason="callee_signature_unsupported_or_parameter_missing",
        )

    bindings: list[CallsiteBinding] = []
    unresolved = False
    for path, source in sorted(normalized.items()):
        tree = ast.parse(source, filename=path)
        aliases = _collect_import_aliases(tree)
        if aliases is None:
            unresolved = True
            bindings.append(
                CallsiteBinding(
                    callsite_id=f"callsite:{path}:imports",
                    path=path,
                    actual_expression="",
                    origin_kind="unknown_origin",
                    evidence_id=None,
                    unresolved_reason="deferred_import_form",
                )
            )
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            resolved = _resolve_callee_name(node.func, import_aliases=aliases)
            if resolved != callee_name:
                continue
            caller = _enclosing_function(tree, node)
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
            callee_qualified_name=f"{callee_path}:{callee_name}",
            parameter=parameter,
            provenance="unknown",
            callsites=(),
            scope_digest=scope_digest,
            reason="no_accounted_callsites",
        )

    if unresolved or any(item.unresolved_reason for item in bindings):
        return InterproceduralArgumentProvenanceResult(
            callee_qualified_name=f"{callee_path}:{callee_name}",
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
        callee_qualified_name=f"{callee_path}:{callee_name}",
        parameter=parameter,
        provenance=provenance,
        callsites=tuple(bindings),
        scope_digest=scope_digest,
        reason=reason,
    )
