"""Persistent content-addressed Python semantic summary cache.

This cache stores only explicit JSON semantic summaries. It never serializes AST
objects or executes cached code.

A cache hit is accepted only when:
- schema and implementation versions match;
- repository-relative path and source digest match the request;
- stored key components hash to the requested key;
- stored payload digest validates;
- typed summary reconstruction succeeds; and
- reconstructed path/source digests match the request.

Corrupt or incompatible records are cache misses.
"""

from __future__ import annotations

import ast
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ovk import __version__ as OVK_VERSION
from ovk.compilers.authorization.fastapi_route_summary import (
    CallSummary,
    DependencyParameterSummary,
    ExpressionSummary,
    IncludeRouterCallSummary,
    ModuleImportSummary,
    OwnershipAssertionSummary,
    RouteDependencySummary,
    RouteFileSummary,
    RouteHandlerSummary,
    RouteSummaryIndex,
    summarize_route_file,
)
from ovk.compilers.authorization.material_loader import AuthMaterials
from ovk.compilers.authorization.python_ast_index import ParsedPythonMaterials
from ovk.compilers.authorization.resource_return_contracts import (
    ContractFileSummary,
    ContractSummaryIndex,
    ForwardingContractCandidate,
    summarize_contract_file,
)
from ovk.core.assurance_ir import (
    ContractTerm,
    FunctionContract,
    SemanticOrigin,
)
from ovk.core.bundle import content_digest
from ovk.core.resource_identity import ResourceIdentityTerm


SEMANTIC_SUMMARY_CACHE_SCHEMA = "ovk.python_semantic_summary_cache.v1"
SEMANTIC_SUMMARY_IMPLEMENTATION_VERSION = "0.9.0"
DEFAULT_SEMANTIC_SUMMARY_CACHE_DIR = Path(
    ".verification/cache/python-semantic-summaries"
)


@dataclass(frozen=True)
class SemanticSummaryCacheStats:
    hits: int = 0
    misses: int = 0
    writes: int = 0
    parse_count: int = 0


@dataclass(frozen=True)
class PersistentSemanticSummaryLoad:
    parsed_index: ParsedPythonMaterials
    contract_summary_index: ContractSummaryIndex
    route_summary_index: RouteSummaryIndex
    stats: SemanticSummaryCacheStats


def _origin_payload(origin: SemanticOrigin) -> dict[str, Any]:
    return origin.model_dump(mode="json")


def _term_payload(term: ContractTerm | None) -> dict[str, Any] | None:
    return None if term is None else term.model_dump(mode="json")


def _resource_term_payload(
    term: ResourceIdentityTerm | None,
) -> dict[str, Any] | None:
    return None if term is None else term.canonical_payload()


def _contract_summary_payload(summary: ContractFileSummary) -> dict[str, Any]:
    return {
        "path": summary.path,
        "source_digest": summary.source_digest,
        "direct_contracts": [
            item.model_dump(mode="json")
            for item in summary.direct_contracts
        ],
        "forwarding_candidates": [
            {
                "qualified_name": item.qualified_name,
                "callee_qualified_name": item.callee_qualified_name,
                "positional_parameters": list(item.positional_parameters),
                "positional_arguments": [
                    _term_payload(term)
                    for term in item.positional_arguments
                ],
                "keyword_arguments": [
                    [name, _term_payload(term)]
                    for name, term in item.keyword_arguments
                ],
                "origin": _origin_payload(item.origin),
            }
            for item in summary.forwarding_candidates
        ],
    }


def _contract_summary_from_payload(
    payload: dict[str, Any],
) -> ContractFileSummary:
    return ContractFileSummary(
        path=str(payload["path"]),
        source_digest=str(payload["source_digest"]),
        direct_contracts=tuple(
            FunctionContract.model_validate(item)
            for item in payload.get("direct_contracts") or []
        ),
        forwarding_candidates=tuple(
            ForwardingContractCandidate(
                qualified_name=str(item["qualified_name"]),
                callee_qualified_name=str(item["callee_qualified_name"]),
                positional_parameters=tuple(
                    str(value)
                    for value in item.get("positional_parameters") or []
                ),
                positional_arguments=tuple(
                    ContractTerm.model_validate(term)
                    if term is not None
                    else None
                    for term in item.get("positional_arguments") or []
                ),
                keyword_arguments=tuple(
                    (
                        str(pair[0]),
                        (
                            ContractTerm.model_validate(pair[1])
                            if pair[1] is not None
                            else None
                        ),
                    )
                    for pair in item.get("keyword_arguments") or []
                ),
                origin=SemanticOrigin.model_validate(item["origin"]),
            )
            for item in payload.get("forwarding_candidates") or []
        ),
    )


def _expression_payload(item: ExpressionSummary) -> dict[str, Any]:
    return {
        "rendered": item.rendered,
        "term": _resource_term_payload(item.term),
        "provably_non_null": item.provably_non_null,
        "origin": _origin_payload(item.origin),
    }


def _expression_from_payload(payload: dict[str, Any]) -> ExpressionSummary:
    term = payload.get("term")
    return ExpressionSummary(
        rendered=str(payload["rendered"]),
        term=(
            ResourceIdentityTerm.model_validate(term)
            if term is not None
            else None
        ),
        provably_non_null=bool(payload["provably_non_null"]),
        origin=SemanticOrigin.model_validate(payload["origin"]),
    )


def _route_summary_payload(summary: RouteFileSummary) -> dict[str, Any]:
    return {
        "path": summary.path,
        "source_digest": summary.source_digest,
        "apirouter_symbols": list(summary.apirouter_symbols),
        "module_imports": [
            {
                "local_name": item.local_name,
                "module_name": item.module_name,
            }
            for item in summary.module_imports
        ],
        "include_router_calls": [
            {
                "app_symbol": item.app_symbol,
                "module_alias": item.module_alias,
                "router_symbol": item.router_symbol,
                "dependencies": (
                    [
                        {
                            "full_name": dep.full_name,
                            "leaf_name": dep.leaf_name,
                            "source_kind": dep.source_kind,
                            "factory_call": dep.factory_call,
                            "origin": _origin_payload(dep.origin),
                        }
                        for dep in item.dependencies
                    ]
                    if item.dependencies is not None
                    else None
                ),
                "origin": _origin_payload(item.origin),
            }
            for item in summary.include_router_calls
        ],
        "handlers": [
            {
                "handler_name": handler.handler_name,
                "method": handler.method,
                "route_path": handler.route_path,
                "router_symbol": handler.router_symbol,
                "has_control_flow": handler.has_control_flow,
                "unsupported_control_flow_lines": list(handler.unsupported_control_flow_lines),
                "ownership_assertions": [
                    {
                        "loader_full_name": item.loader_full_name,
                        "loader_leaf_name": item.loader_leaf_name,
                        "loaded_resource_symbol": item.loaded_resource_symbol,
                        "resource_identity_attribute": item.resource_identity_attribute,
                        "resource_key": _expression_payload(item.resource_key),
                        "owner_attribute": item.owner_attribute,
                        "principal_expression": _expression_payload(item.principal_expression),
                        "principal_attribute": item.principal_attribute,
                        "presence_test": item.presence_test,
                        "origin": _origin_payload(item.origin),
                    }
                    for item in handler.ownership_assertions
                ],
                "dependencies": [
                    {
                        "parameter_name": dep.parameter_name,
                        "dependency_name": dep.dependency_name,
                        "origin": _origin_payload(dep.origin),
                    }
                    for dep in handler.dependencies
                ],
                "route_dependencies": [
                    {
                        "full_name": dep.full_name,
                        "leaf_name": dep.leaf_name,
                        "source_kind": dep.source_kind,
                        "factory_call": dep.factory_call,
                        "origin": _origin_payload(dep.origin),
                    }
                    for dep in handler.route_dependencies
                ],
                "calls": [
                    {
                        "full_name": call.full_name,
                        "leaf_name": call.leaf_name,
                        "resolved_qualified_name": (
                            call.resolved_qualified_name
                        ),
                        "positional_arguments": [
                            _expression_payload(argument)
                            for argument in call.positional_arguments
                        ],
                        "keyword_arguments": [
                            [name, _expression_payload(argument)]
                            for name, argument in call.keyword_arguments
                        ],
                        "origin": _origin_payload(call.origin),
                    }
                    for call in handler.calls
                ],
                "origin": _origin_payload(handler.origin),
            }
            for handler in summary.handlers
        ],
    }


def _route_summary_from_payload(payload: dict[str, Any]) -> RouteFileSummary:
    handlers: list[RouteHandlerSummary] = []
    for handler in payload.get("handlers") or []:
        calls: list[CallSummary] = []
        for call in handler.get("calls") or []:
            calls.append(
                CallSummary(
                    full_name=str(call["full_name"]),
                    leaf_name=(
                        str(call["leaf_name"])
                        if call.get("leaf_name") is not None
                        else None
                    ),
                    resolved_qualified_name=(
                        str(call["resolved_qualified_name"])
                        if call.get("resolved_qualified_name") is not None
                        else None
                    ),
                    positional_arguments=tuple(
                        _expression_from_payload(argument)
                        for argument in call.get("positional_arguments") or []
                    ),
                    keyword_arguments=tuple(
                        (
                            str(pair[0]),
                            _expression_from_payload(pair[1]),
                        )
                        for pair in call.get("keyword_arguments") or []
                    ),
                    origin=SemanticOrigin.model_validate(call["origin"]),
                )
            )

        handlers.append(
            RouteHandlerSummary(
                handler_name=str(handler["handler_name"]),
                method=str(handler["method"]),
                route_path=str(handler["route_path"]),
                router_symbol=(
                    str(handler["router_symbol"])
                    if handler.get("router_symbol") is not None
                    else None
                ),
                has_control_flow=bool(handler["has_control_flow"]),
                unsupported_control_flow_lines=tuple(
                    int(value)
                    for value in handler.get("unsupported_control_flow_lines") or []
                ),
                ownership_assertions=tuple(
                    OwnershipAssertionSummary(
                        loader_full_name=str(item["loader_full_name"]),
                        loader_leaf_name=(
                            str(item["loader_leaf_name"])
                            if item.get("loader_leaf_name") is not None
                            else None
                        ),
                        loaded_resource_symbol=str(item["loaded_resource_symbol"]),
                        resource_identity_attribute=str(item["resource_identity_attribute"]),
                        resource_key=_expression_from_payload(item["resource_key"]),
                        owner_attribute=str(item["owner_attribute"]),
                        principal_expression=_expression_from_payload(item["principal_expression"]),
                        principal_attribute=str(item["principal_attribute"]),
                        presence_test=str(item["presence_test"]),
                        origin=SemanticOrigin.model_validate(item["origin"]),
                    )
                    for item in handler.get("ownership_assertions") or []
                ),
                dependencies=tuple(
                    DependencyParameterSummary(
                        parameter_name=str(dep["parameter_name"]),
                        dependency_name=str(dep["dependency_name"]),
                        origin=SemanticOrigin.model_validate(dep["origin"]),
                    )
                    for dep in handler.get("dependencies") or []
                ),
                route_dependencies=tuple(
                    RouteDependencySummary(
                        full_name=str(dep["full_name"]),
                        leaf_name=(
                            str(dep["leaf_name"])
                            if dep.get("leaf_name") is not None
                            else None
                        ),
                        source_kind=str(dep["source_kind"]),
                        origin=SemanticOrigin.model_validate(dep["origin"]),
                        factory_call=(
                            str(dep["factory_call"])
                            if dep.get("factory_call") is not None
                            else None
                        ),
                    )
                    for dep in handler.get("route_dependencies") or []
                ),
                calls=tuple(calls),
                origin=SemanticOrigin.model_validate(handler["origin"]),
            )
        )

    return RouteFileSummary(
        path=str(payload["path"]),
        source_digest=str(payload["source_digest"]),
        handlers=tuple(handlers),
        apirouter_symbols=tuple(
            str(value)
            for value in payload.get("apirouter_symbols") or []
        ),
        module_imports=tuple(
            ModuleImportSummary(
                local_name=str(item["local_name"]),
                module_name=str(item["module_name"]),
            )
            for item in payload.get("module_imports") or []
        ),
        include_router_calls=tuple(
            IncludeRouterCallSummary(
                app_symbol=str(item["app_symbol"]),
                module_alias=str(item["module_alias"]),
                router_symbol=str(item["router_symbol"]),
                dependencies=(
                    tuple(
                        RouteDependencySummary(
                            full_name=str(dep["full_name"]),
                            leaf_name=(
                                str(dep["leaf_name"])
                                if dep.get("leaf_name") is not None
                                else None
                            ),
                            source_kind=str(dep["source_kind"]),
                            origin=SemanticOrigin.model_validate(
                                dep["origin"]
                            ),
                            factory_call=(
                                str(dep["factory_call"])
                                if dep.get("factory_call") is not None
                                else None
                            ),
                        )
                        for dep in item["dependencies"]
                    )
                    if item.get("dependencies") is not None
                    else None
                ),
                origin=SemanticOrigin.model_validate(item["origin"]),
            )
            for item in payload.get("include_router_calls") or []
        ),
    )


def _key_components(*, path: str, source_digest: str) -> dict[str, Any]:
    return {
        "schema_version": SEMANTIC_SUMMARY_CACHE_SCHEMA,
        "implementation_version": SEMANTIC_SUMMARY_IMPLEMENTATION_VERSION,
        "ovk_version": OVK_VERSION,
        "path": path,
        "source_digest": source_digest,
    }


def _key_digest(*, path: str, source_digest: str) -> str:
    return content_digest(
        _key_components(path=path, source_digest=source_digest)
    )


class PersistentPythonSemanticSummaryCache:
    """Filesystem-backed semantic summaries for fresh worker processes."""

    def __init__(self, root: Path | None = None) -> None:
        self.root = root or DEFAULT_SEMANTIC_SUMMARY_CACHE_DIR

    def _path(self, *, path: str, source_digest: str) -> Path:
        key = _key_digest(path=path, source_digest=source_digest)
        return self.root / f"{key}.json"

    def get(
        self,
        *,
        path: str,
        source_digest: str,
    ) -> tuple[ContractFileSummary | None, RouteFileSummary | None, str | None] | None:
        cache_path = self._path(path=path, source_digest=source_digest)
        if not cache_path.exists():
            return None
        try:
            record = json.loads(cache_path.read_text(encoding="utf-8"))
            components = record["key_components"]
            payload = record["payload"]
        except (OSError, json.JSONDecodeError, KeyError, TypeError):
            return None

        requested = _key_components(
            path=path,
            source_digest=source_digest,
        )
        if components != requested:
            return None
        if record.get("key_digest") != content_digest(requested):
            return None
        if record.get("payload_digest") != content_digest(payload):
            return None
        if payload.get("path") != path:
            return None
        if payload.get("source_digest") != source_digest:
            return None

        syntax_error = payload.get("syntax_error")
        if syntax_error is not None:
            if not isinstance(syntax_error, str):
                return None
            return None, None, syntax_error

        try:
            contract = _contract_summary_from_payload(
                payload["contract_summary"]
            )
            route = _route_summary_from_payload(
                payload["route_summary"]
            )
        except Exception:
            return None
        if contract.path != path or route.path != path:
            return None
        if (
            contract.source_digest != source_digest
            or route.source_digest != source_digest
        ):
            return None
        return contract, route, None

    def put(
        self,
        *,
        path: str,
        source_digest: str,
        contract_summary: ContractFileSummary | None,
        route_summary: RouteFileSummary | None,
        syntax_error: str | None = None,
    ) -> str:
        if syntax_error is None and (
            contract_summary is None or route_summary is None
        ):
            raise ValueError(
                "valid source summary cache record requires both semantic summaries"
            )
        if syntax_error is not None and (
            contract_summary is not None or route_summary is not None
        ):
            raise ValueError(
                "syntax-error cache record cannot contain semantic summaries"
            )

        if contract_summary is not None:
            if (
                contract_summary.path != path
                or contract_summary.source_digest != source_digest
            ):
                raise ValueError("contract summary does not match cache identity")
        if route_summary is not None:
            if (
                route_summary.path != path
                or route_summary.source_digest != source_digest
            ):
                raise ValueError("route summary does not match cache identity")

        components = _key_components(
            path=path,
            source_digest=source_digest,
        )
        payload: dict[str, Any] = {
            "path": path,
            "source_digest": source_digest,
            "syntax_error": syntax_error,
            "contract_summary": (
                _contract_summary_payload(contract_summary)
                if contract_summary is not None
                else None
            ),
            "route_summary": (
                _route_summary_payload(route_summary)
                if route_summary is not None
                else None
            ),
        }
        record = {
            "cached_at": time.time(),
            "key_digest": content_digest(components),
            "key_components": components,
            "payload": payload,
            "payload_digest": content_digest(payload),
        }
        self.root.mkdir(parents=True, exist_ok=True)
        cache_path = self._path(
            path=path,
            source_digest=source_digest,
        )
        temp = cache_path.with_suffix(".tmp")
        temp.write_text(
            json.dumps(record, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        temp.replace(cache_path)
        return str(record["key_digest"])


def load_persistent_semantic_summaries(
    materials: AuthMaterials,
    *,
    cache: PersistentPythonSemanticSummaryCache,
) -> PersistentSemanticSummaryLoad:
    """Load cached summaries and parse/summarize only cache misses."""

    trees: dict[str, ast.Module] = {}
    syntax_errors: dict[str, str] = {}
    digests: dict[str, str] = {}
    contract_summaries: dict[str, ContractFileSummary] = {}
    route_summaries: dict[str, RouteFileSummary] = {}

    hits = 0
    misses = 0
    writes = 0
    parse_count = 0
    fresh_valid_summaries = 0
    reused_valid_summaries = 0

    for path, source in sorted(materials.head_files.items()):
        source_digest = content_digest(source)
        digests[path] = source_digest

        cached = cache.get(
            path=path,
            source_digest=source_digest,
        )
        if cached is not None:
            contract, route, syntax_error = cached
            hits += 1
            if syntax_error is not None:
                syntax_errors[path] = syntax_error
            else:
                assert contract is not None
                assert route is not None
                contract_summaries[path] = contract
                route_summaries[path] = route
                reused_valid_summaries += 1
            continue

        misses += 1
        parse_count += 1
        try:
            tree = ast.parse(source, filename=path)
        except SyntaxError as exc:
            syntax_errors[path] = exc.msg
            cache.put(
                path=path,
                source_digest=source_digest,
                contract_summary=None,
                route_summary=None,
                syntax_error=exc.msg,
            )
            writes += 1
            continue

        trees[path] = tree
        contract = summarize_contract_file(
            path=path,
            tree=tree,
            source_digest=source_digest,
        )
        route = summarize_route_file(
            path=path,
            tree=tree,
            source_digest=source_digest,
        )
        contract_summaries[path] = contract
        route_summaries[path] = route
        fresh_valid_summaries += 1
        cache.put(
            path=path,
            source_digest=source_digest,
            contract_summary=contract,
            route_summary=route,
        )
        writes += 1

    parsed_index = ParsedPythonMaterials(
        trees=trees,
        syntax_errors=syntax_errors,
        source_digests=digests,
        parse_count=parse_count,
        reused_count=hits,
    )
    contract_index = ContractSummaryIndex(
        summaries=contract_summaries,
        source_digests=digests,
        fresh_summary_count=fresh_valid_summaries,
        reused_summary_count=reused_valid_summaries,
    )
    route_index = RouteSummaryIndex(
        summaries=route_summaries,
        source_digests=digests,
        fresh_summary_count=contract_index.fresh_summary_count,
        reused_summary_count=contract_index.reused_summary_count,
    )

    return PersistentSemanticSummaryLoad(
        parsed_index=parsed_index,
        contract_summary_index=contract_index,
        route_summary_index=route_index,
        stats=SemanticSummaryCacheStats(
            hits=hits,
            misses=misses,
            writes=writes,
            parse_count=parse_count,
        ),
    )
