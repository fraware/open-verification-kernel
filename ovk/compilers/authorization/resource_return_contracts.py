"""Restricted source inference for resource-return scope contracts.

The v1 rule recognizes a narrow rejecting-guard pattern:

    async def get(..., workspace_id: Optional[str] = None):
        ...
        if workspace_id is not None and resource.workspace_id != workspace_id:
            return None
        return resource

For a successful non-None return and a non-None supplied scope argument, the
method establishes:

    returned_resource.workspace_id == workspace_id

The inferencer deliberately ignores arbitrary functional behavior and does not
infer persistence-framework semantics such as primary-key identity.
"""

from __future__ import annotations

import ast
from collections.abc import Mapping
from dataclasses import dataclass, field

from ovk.compilers.authorization.material_loader import AuthMaterials
from ovk.core.assurance_ir import (
    ContractPredicate,
    ContractTerm,
    FunctionContract,
    ResourceReturnContract,
    SemanticOrigin,
)
from ovk.core.bundle import content_digest
from ovk.core.models import SourceRange


_EXTRACTOR_ID = "assurance.python.resource_return_contracts.ast_v1"
_UNSUPPORTED_CONTROL_FLOW = (
    ast.For,
    ast.AsyncFor,
    ast.While,
    ast.Try,
    ast.Match,
    ast.With,
    ast.AsyncWith,
)


def _origin(path: str, node: ast.AST) -> SemanticOrigin:
    return SemanticOrigin(
        path=path,
        extractor_id=_EXTRACTOR_ID,
        extractor_version="0.1.0",
        source_range=SourceRange(
            path=path,
            start_line=getattr(node, "lineno", None),
            end_line=getattr(node, "end_lineno", getattr(node, "lineno", None)),
        ),
    )


def _function_parameters(node: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    return {
        arg.arg
        for arg in (
            list(node.args.posonlyargs)
            + list(node.args.args)
            + list(node.args.kwonlyargs)
        )
    }


def _returns_none(statements: list[ast.stmt]) -> bool:
    returns = [
        item
        for statement in statements
        for item in ast.walk(statement)
        if isinstance(item, ast.Return)
    ]
    return bool(returns) and all(item.value is None or _is_none(item.value) for item in returns)


def _is_none(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and node.value is None


def _contains_non_null_guard(test: ast.AST, parameter: str) -> bool:
    for item in ast.walk(test):
        if not isinstance(item, ast.Compare) or len(item.ops) != 1 or len(item.comparators) != 1:
            continue
        left = item.left
        right = item.comparators[0]
        op = item.ops[0]
        if isinstance(op, (ast.IsNot, ast.NotEq)):
            if isinstance(left, ast.Name) and left.id == parameter and _is_none(right):
                return True
            if isinstance(right, ast.Name) and right.id == parameter and _is_none(left):
                return True
    return False


def _scope_mismatch(test: ast.AST, returned_name: str) -> tuple[str, str] | None:
    """Return (scope_attribute, parameter) for resource.attr != parameter."""

    for item in ast.walk(test):
        if not isinstance(item, ast.Compare) or len(item.ops) != 1 or len(item.comparators) != 1:
            continue
        if not isinstance(item.ops[0], ast.NotEq):
            continue

        pairs = ((item.left, item.comparators[0]), (item.comparators[0], item.left))
        for attribute_node, parameter_node in pairs:
            if (
                isinstance(attribute_node, ast.Attribute)
                and isinstance(attribute_node.value, ast.Name)
                and attribute_node.value.id == returned_name
                and isinstance(parameter_node, ast.Name)
            ):
                return attribute_node.attr, parameter_node.id
    return None


def _top_level_success_return(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> tuple[int, str] | None:
    successes: list[tuple[int, str]] = []
    for index, statement in enumerate(node.body):
        if isinstance(statement, ast.Return) and isinstance(statement.value, ast.Name):
            successes.append((index, statement.value.id))
    if len(successes) != 1:
        return None

    non_none_returns = [
        item
        for statement in node.body
        for item in ast.walk(statement)
        if isinstance(item, ast.Return)
        and item.value is not None
        and not _is_none(item.value)
    ]
    if len(non_none_returns) != 1:
        return None
    return successes[0]


def _infer_method_contract(
    *,
    path: str,
    class_name: str,
    method: ast.FunctionDef | ast.AsyncFunctionDef,
) -> FunctionContract | None:
    if any(
        isinstance(item, _UNSUPPORTED_CONTROL_FLOW)
        for statement in method.body
        for item in ast.walk(statement)
    ):
        return None

    success = _top_level_success_return(method)
    if success is None:
        return None
    success_index, returned_name = success
    parameters = _function_parameters(method)

    candidates: list[tuple[str, str, bool, ast.If]] = []
    for index, statement in enumerate(method.body):
        if index >= success_index or not isinstance(statement, ast.If):
            continue
        if not _returns_none(statement.body):
            continue
        mismatch = _scope_mismatch(statement.test, returned_name)
        if mismatch is None:
            continue
        scope_attribute, parameter = mismatch
        if parameter not in parameters:
            continue
        requires_non_null = _contains_non_null_guard(statement.test, parameter)
        candidates.append((scope_attribute, parameter, requires_non_null, statement))

    if not candidates:
        return None

    # One method may establish several return relations, such as
    # return.id == agent_id and return.workspace_id == workspace_id.
    unique_pairs = {(attribute, parameter) for attribute, parameter, _, _ in candidates}
    if len(unique_pairs) != len(candidates):
        return None

    qualified_name = f"{class_name}.{method.name}"
    positional_parameters = [
        arg.arg
        for arg in (list(method.args.posonlyargs) + list(method.args.args))
        if arg.arg not in {"self", "cls"}
    ]

    preconditions = []
    postconditions = []
    for attribute, parameter, requires_non_null, _guard in candidates:
        if requires_non_null:
            predicate = ContractPredicate(
                relation="non_null",
                left=ContractTerm.parameter(parameter),
            )
            if predicate not in preconditions:
                preconditions.append(predicate)
        postconditions.append(
            ContractPredicate(
                relation="eq",
                left=ContractTerm.return_attribute(attribute),
                right=ContractTerm.parameter(parameter),
            )
        )

    contract_id = (
        "contract:"
        + content_digest(
            {
                "qualified_name": qualified_name,
                "positional_parameters": positional_parameters,
                "preconditions": [
                    predicate.model_dump(mode="json") for predicate in preconditions
                ],
                "postconditions": [
                    predicate.model_dump(mode="json") for predicate in postconditions
                ],
                "path": path,
            }
        )[:16]
    )
    origin_node = min(candidates, key=lambda item: getattr(item[3], "lineno", 0))[3]
    return FunctionContract(
        contract_id=contract_id,
        qualified_name=qualified_name,
        positional_parameters=positional_parameters,
        preconditions=preconditions,
        postconditions=postconditions,
        origin=_origin(path, origin_node),
    )


def _unwrap_call(node: ast.AST | None) -> ast.Call | None:
    if isinstance(node, ast.Await):
        node = node.value
    return node if isinstance(node, ast.Call) else None


def _class_member_aliases(class_node: ast.ClassDef) -> dict[str, str]:
    """Map self.<field> to constructor class for simple __init__ assignments."""

    aliases: dict[str, str] = {}
    for statement in class_node.body:
        if not isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if statement.name != "__init__":
            continue
        for body_statement in statement.body:
            if not isinstance(body_statement, (ast.Assign, ast.AnnAssign)):
                continue
            if isinstance(body_statement, ast.Assign):
                if len(body_statement.targets) != 1:
                    continue
                target = body_statement.targets[0]
                value = body_statement.value
            else:
                target = body_statement.target
                value = body_statement.value
            if (
                not isinstance(target, ast.Attribute)
                or not isinstance(target.value, ast.Name)
                or target.value.id != "self"
                or value is None
            ):
                continue
            call = _unwrap_call(value)
            if call is None:
                continue
            constructor = call.func
            if isinstance(constructor, ast.Name):
                aliases[target.attr] = constructor.id
            elif isinstance(constructor, ast.Attribute):
                aliases[target.attr] = constructor.attr
    return aliases


def _local_constructor_aliases(
    method: ast.FunctionDef | ast.AsyncFunctionDef,
) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for statement in method.body:
        if not isinstance(statement, (ast.Assign, ast.AnnAssign)):
            continue
        if isinstance(statement, ast.Assign):
            if len(statement.targets) != 1:
                continue
            target = statement.targets[0]
            value = statement.value
        else:
            target = statement.target
            value = statement.value
        if not isinstance(target, ast.Name) or value is None:
            continue
        call = _unwrap_call(value)
        if call is None:
            continue
        if isinstance(call.func, ast.Name):
            aliases[target.id] = call.func.id
        elif isinstance(call.func, ast.Attribute):
            aliases[target.id] = call.func.attr
    return aliases


def _resolve_forwarded_qualified_name(
    call: ast.Call,
    *,
    local_aliases: dict[str, str],
    member_aliases: dict[str, str],
) -> str | None:
    if not isinstance(call.func, ast.Attribute):
        return None

    receiver = call.func.value
    if isinstance(receiver, ast.Name):
        constructor = local_aliases.get(receiver.id)
        if constructor is not None:
            return f"{constructor}.{call.func.attr}"

    if (
        isinstance(receiver, ast.Attribute)
        and isinstance(receiver.value, ast.Name)
        and receiver.value.id == "self"
    ):
        constructor = member_aliases.get(receiver.attr)
        if constructor is not None:
            return f"{constructor}.{call.func.attr}"

    direct_constructor = _unwrap_call(receiver)
    if direct_constructor is not None:
        if isinstance(direct_constructor.func, ast.Name):
            return f"{direct_constructor.func.id}.{call.func.attr}"
        if isinstance(direct_constructor.func, ast.Attribute):
            return f"{direct_constructor.func.attr}.{call.func.attr}"
    return None


def _forwarded_return_call(
    method: ast.FunctionDef | ast.AsyncFunctionDef,
) -> ast.Call | None:
    """Return the unique forwarded call for a narrow wrapper method."""

    if any(
        isinstance(item, _UNSUPPORTED_CONTROL_FLOW)
        for statement in method.body
        for item in ast.walk(statement)
    ):
        return None

    top_returns = [
        (index, statement)
        for index, statement in enumerate(method.body)
        if isinstance(statement, ast.Return)
    ]
    if len(top_returns) != 1:
        return None
    return_index, return_statement = top_returns[0]
    if return_statement.value is None or _is_none(return_statement.value):
        return None

    direct = _unwrap_call(return_statement.value)
    if direct is not None:
        return direct

    if not isinstance(return_statement.value, ast.Name) or return_index == 0:
        return None
    result_name = return_statement.value.id
    previous = method.body[return_index - 1]
    if isinstance(previous, ast.Assign):
        if (
            len(previous.targets) != 1
            or not isinstance(previous.targets[0], ast.Name)
            or previous.targets[0].id != result_name
        ):
            return None
        return _unwrap_call(previous.value)
    if isinstance(previous, ast.AnnAssign):
        if not isinstance(previous.target, ast.Name) or previous.target.id != result_name:
            return None
        return _unwrap_call(previous.value)
    return None


def _method_positional_parameters(
    method: ast.FunctionDef | ast.AsyncFunctionDef,
) -> list[str]:
    return [
        arg.arg
        for arg in (list(method.args.posonlyargs) + list(method.args.args))
        if arg.arg not in {"self", "cls"}
    ]


def _call_argument_for_parameter(
    call: ast.Call,
    *,
    parameter_name: str,
    callee_positional_parameters: list[str],
) -> ast.AST | None:
    for keyword in call.keywords:
        if keyword.arg == parameter_name:
            return keyword.value
    if parameter_name not in callee_positional_parameters:
        return None
    index = callee_positional_parameters.index(parameter_name)
    if len(call.args) <= index:
        return None
    return call.args[index]


def _substitute_term_into_wrapper(
    term: ContractTerm,
    *,
    call: ast.Call,
    callee: FunctionContract,
    wrapper_parameters: set[str],
) -> ContractTerm | None:
    if term.kind == "return_attribute":
        return term.model_copy(deep=True)
    if term.kind == "literal":
        return term.model_copy(deep=True)
    if term.kind != "parameter" or term.name is None:
        return None

    argument = _call_argument_for_parameter(
        call,
        parameter_name=term.name,
        callee_positional_parameters=callee.positional_parameters,
    )
    if argument is None:
        return None
    if isinstance(argument, ast.Name) and argument.id in wrapper_parameters:
        return ContractTerm.parameter(argument.id)
    if isinstance(argument, ast.Constant) and argument.value is not None:
        return ContractTerm.literal(str(argument.value))
    return None


def _compose_forwarded_contract(
    *,
    path: str,
    class_node: ast.ClassDef,
    method: ast.FunctionDef | ast.AsyncFunctionDef,
    known_contracts: dict[str, FunctionContract],
) -> FunctionContract | None:
    call = _forwarded_return_call(method)
    if call is None:
        return None

    qualified_callee = _resolve_forwarded_qualified_name(
        call,
        local_aliases=_local_constructor_aliases(method),
        member_aliases=_class_member_aliases(class_node),
    )
    if qualified_callee is None:
        return None
    callee = known_contracts.get(qualified_callee)
    if callee is None:
        return None

    wrapper_parameters = _function_parameters(method)
    preconditions: list[ContractPredicate] = []
    postconditions: list[ContractPredicate] = []

    for predicate in callee.preconditions:
        left = _substitute_term_into_wrapper(
            predicate.left,
            call=call,
            callee=callee,
            wrapper_parameters=wrapper_parameters,
        )
        right = (
            _substitute_term_into_wrapper(
                predicate.right,
                call=call,
                callee=callee,
                wrapper_parameters=wrapper_parameters,
            )
            if predicate.right is not None
            else None
        )
        if left is None or (predicate.right is not None and right is None):
            return None
        # A non-null literal discharges a callee non_null precondition.
        if predicate.relation == "non_null" and left.kind == "literal":
            continue
        preconditions.append(
            ContractPredicate(
                relation=predicate.relation,
                left=left,
                right=right,
            )
        )

    for predicate in callee.postconditions:
        left = _substitute_term_into_wrapper(
            predicate.left,
            call=call,
            callee=callee,
            wrapper_parameters=wrapper_parameters,
        )
        right = (
            _substitute_term_into_wrapper(
                predicate.right,
                call=call,
                callee=callee,
                wrapper_parameters=wrapper_parameters,
            )
            if predicate.right is not None
            else None
        )
        if left is None or (predicate.right is not None and right is None):
            return None
        postconditions.append(
            ContractPredicate(
                relation=predicate.relation,
                left=left,
                right=right,
            )
        )

    if not postconditions:
        return None

    qualified_name = f"{class_node.name}.{method.name}"
    positional_parameters = _method_positional_parameters(method)
    contract_id = (
        "contract:"
        + content_digest(
            {
                "qualified_name": qualified_name,
                "composed_from": callee.contract_id,
                "positional_parameters": positional_parameters,
                "preconditions": [
                    predicate.model_dump(mode="json") for predicate in preconditions
                ],
                "postconditions": [
                    predicate.model_dump(mode="json") for predicate in postconditions
                ],
                "path": path,
            }
        )[:16]
    )
    return FunctionContract(
        contract_id=contract_id,
        qualified_name=qualified_name,
        derivation="composed",
        depends_on=[callee.qualified_name],
        positional_parameters=positional_parameters,
        preconditions=preconditions,
        postconditions=postconditions,
        origin=_origin(path, call),
    )


@dataclass(frozen=True)
class ForwardingContractCandidate:
    """Serializable semantic summary of one transparent forwarding wrapper."""

    qualified_name: str
    callee_qualified_name: str
    positional_parameters: tuple[str, ...]
    positional_arguments: tuple[ContractTerm | None, ...]
    keyword_arguments: tuple[tuple[str, ContractTerm | None], ...]
    origin: SemanticOrigin


@dataclass(frozen=True)
class ContractFileSummary:
    """Content-bound contract semantics extracted from one Python source file."""

    path: str
    source_digest: str
    direct_contracts: tuple[FunctionContract, ...] = ()
    forwarding_candidates: tuple[ForwardingContractCandidate, ...] = ()


@dataclass(frozen=True)
class ContractSummaryIndex:
    """Per-file contract summaries reusable across source revisions."""

    summaries: dict[str, ContractFileSummary] = field(default_factory=dict)
    source_digests: dict[str, str] = field(default_factory=dict)
    fresh_summary_count: int = 0
    reused_summary_count: int = 0


def _wrapper_argument_term(
    node: ast.AST,
    *,
    wrapper_parameters: set[str],
) -> ContractTerm | None:
    if isinstance(node, ast.Name) and node.id in wrapper_parameters:
        return ContractTerm.parameter(node.id)
    if isinstance(node, ast.Constant) and node.value is not None:
        return ContractTerm.literal(str(node.value))
    return None


def _summarize_forwarding_candidate(
    *,
    path: str,
    class_node: ast.ClassDef,
    method: ast.FunctionDef | ast.AsyncFunctionDef,
) -> ForwardingContractCandidate | None:
    call = _forwarded_return_call(method)
    if call is None:
        return None

    qualified_callee = _resolve_forwarded_qualified_name(
        call,
        local_aliases=_local_constructor_aliases(method),
        member_aliases=_class_member_aliases(class_node),
    )
    if qualified_callee is None:
        return None

    wrapper_parameters = _function_parameters(method)
    keyword_arguments: list[tuple[str, ContractTerm | None]] = []
    for keyword in call.keywords:
        if keyword.arg is None:
            return None
        keyword_arguments.append(
            (
                keyword.arg,
                _wrapper_argument_term(
                    keyword.value,
                    wrapper_parameters=wrapper_parameters,
                ),
            )
        )

    return ForwardingContractCandidate(
        qualified_name=f"{class_node.name}.{method.name}",
        callee_qualified_name=qualified_callee,
        positional_parameters=tuple(_method_positional_parameters(method)),
        positional_arguments=tuple(
            _wrapper_argument_term(
                argument,
                wrapper_parameters=wrapper_parameters,
            )
            for argument in call.args
        ),
        keyword_arguments=tuple(keyword_arguments),
        origin=_origin(path, call),
    )


def summarize_contract_file(
    *,
    path: str,
    tree: ast.Module,
    source_digest: str,
) -> ContractFileSummary:
    """Extract reusable direct-contract and forwarding facts from one AST."""

    direct: list[FunctionContract] = []
    forwarding: list[ForwardingContractCandidate] = []

    for node in tree.body:
        if not isinstance(node, ast.ClassDef):
            continue
        for statement in node.body:
            if not isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue

            contract = _infer_method_contract(
                path=path,
                class_name=node.name,
                method=statement,
            )
            if contract is not None:
                direct.append(contract)

            candidate = _summarize_forwarding_candidate(
                path=path,
                class_node=node,
                method=statement,
            )
            if candidate is not None:
                forwarding.append(candidate)

    return ContractFileSummary(
        path=path,
        source_digest=source_digest,
        direct_contracts=tuple(
            sorted(direct, key=lambda item: item.contract_id)
        ),
        forwarding_candidates=tuple(
            sorted(
                forwarding,
                key=lambda item: (
                    item.qualified_name,
                    item.callee_qualified_name,
                ),
            )
        ),
    )


def build_contract_summary_index(
    materials: AuthMaterials,
    *,
    parsed_trees: Mapping[str, ast.Module],
    source_digests: Mapping[str, str] | None = None,
    reuse_from: ContractSummaryIndex | None = None,
) -> ContractSummaryIndex:
    """Build or incrementally reuse per-file contract semantic summaries."""

    digests = (
        dict(source_digests)
        if source_digests is not None
        else {
            path: content_digest(source)
            for path, source in sorted(materials.head_files.items())
        }
    )
    current_expected = {
        path: content_digest(source)
        for path, source in sorted(materials.head_files.items())
    }
    if digests != current_expected:
        raise ValueError(
            "contract summary source digests do not match supplied head materials"
        )

    summaries: dict[str, ContractFileSummary] = {}
    fresh = 0
    reused = 0

    for path, tree in sorted(parsed_trees.items()):
        digest = digests.get(path)
        if digest is None:
            raise ValueError(f"missing source digest for parsed tree: {path}")

        prior = reuse_from.summaries.get(path) if reuse_from is not None else None
        if prior is not None and prior.source_digest == digest:
            summaries[path] = prior
            reused += 1
            continue

        summaries[path] = summarize_contract_file(
            path=path,
            tree=tree,
            source_digest=digest,
        )
        fresh += 1

    return ContractSummaryIndex(
        summaries=summaries,
        source_digests=digests,
        fresh_summary_count=fresh,
        reused_summary_count=reused,
    )


def contract_summary_index_matches_materials(
    summary_index: ContractSummaryIndex,
    materials: AuthMaterials,
) -> bool:
    current = {
        path: content_digest(source)
        for path, source in sorted(materials.head_files.items())
    }
    return current == summary_index.source_digests


def _candidate_argument_for_parameter(
    candidate: ForwardingContractCandidate,
    *,
    parameter_name: str,
    callee_positional_parameters: list[str],
) -> ContractTerm | None:
    keywords = dict(candidate.keyword_arguments)
    if parameter_name in keywords:
        return keywords[parameter_name]
    if parameter_name not in callee_positional_parameters:
        return None
    index = callee_positional_parameters.index(parameter_name)
    if len(candidate.positional_arguments) <= index:
        return None
    return candidate.positional_arguments[index]


def _substitute_summary_term(
    term: ContractTerm,
    *,
    candidate: ForwardingContractCandidate,
    callee: FunctionContract,
) -> ContractTerm | None:
    if term.kind in {"return_attribute", "literal"}:
        return term.model_copy(deep=True)
    if term.kind != "parameter" or term.name is None:
        return None
    argument = _candidate_argument_for_parameter(
        candidate,
        parameter_name=term.name,
        callee_positional_parameters=callee.positional_parameters,
    )
    return argument.model_copy(deep=True) if argument is not None else None


def _compose_summary_candidate(
    candidate: ForwardingContractCandidate,
    *,
    known_contracts: dict[str, FunctionContract],
) -> FunctionContract | None:
    callee = known_contracts.get(candidate.callee_qualified_name)
    if callee is None:
        return None

    preconditions: list[ContractPredicate] = []
    postconditions: list[ContractPredicate] = []

    for predicate in callee.preconditions:
        left = _substitute_summary_term(
            predicate.left,
            candidate=candidate,
            callee=callee,
        )
        right = (
            _substitute_summary_term(
                predicate.right,
                candidate=candidate,
                callee=callee,
            )
            if predicate.right is not None
            else None
        )
        if left is None or (predicate.right is not None and right is None):
            return None
        if predicate.relation == "non_null" and left.kind == "literal":
            continue
        preconditions.append(
            ContractPredicate(
                relation=predicate.relation,
                left=left,
                right=right,
            )
        )

    for predicate in callee.postconditions:
        left = _substitute_summary_term(
            predicate.left,
            candidate=candidate,
            callee=callee,
        )
        right = (
            _substitute_summary_term(
                predicate.right,
                candidate=candidate,
                callee=callee,
            )
            if predicate.right is not None
            else None
        )
        if left is None or (predicate.right is not None and right is None):
            return None
        postconditions.append(
            ContractPredicate(
                relation=predicate.relation,
                left=left,
                right=right,
            )
        )

    if not postconditions:
        return None

    path = candidate.origin.path
    contract_id = (
        "contract:"
        + content_digest(
            {
                "qualified_name": candidate.qualified_name,
                "composed_from": callee.contract_id,
                "positional_parameters": list(candidate.positional_parameters),
                "preconditions": [
                    predicate.model_dump(mode="json")
                    for predicate in preconditions
                ],
                "postconditions": [
                    predicate.model_dump(mode="json")
                    for predicate in postconditions
                ],
                "path": path,
            }
        )[:16]
    )
    return FunctionContract(
        contract_id=contract_id,
        qualified_name=candidate.qualified_name,
        derivation="composed",
        depends_on=[callee.qualified_name],
        positional_parameters=list(candidate.positional_parameters),
        preconditions=preconditions,
        postconditions=postconditions,
        origin=candidate.origin,
    )


def compose_function_contracts(
    summary_index: ContractSummaryIndex,
) -> list[FunctionContract]:
    """Compose a global contract set from reusable per-file summaries."""

    contracts_by_name: dict[str, FunctionContract] = {}
    candidates: list[ForwardingContractCandidate] = []

    for path, summary in sorted(summary_index.summaries.items()):
        for contract in summary.direct_contracts:
            contracts_by_name[contract.qualified_name] = contract
        candidates.extend(summary.forwarding_candidates)

    candidates.sort(
        key=lambda item: (
            item.qualified_name,
            item.callee_qualified_name,
            item.origin.path,
        )
    )

    for _round in range(len(candidates)):
        added = False
        for candidate in candidates:
            if candidate.qualified_name in contracts_by_name:
                continue
            composed = _compose_summary_candidate(
                candidate,
                known_contracts=contracts_by_name,
            )
            if composed is not None:
                contracts_by_name[candidate.qualified_name] = composed
                added = True
        if not added:
            break

    return sorted(
        contracts_by_name.values(),
        key=lambda item: item.contract_id,
    )


def infer_function_contracts(
    materials: AuthMaterials,
    *,
    parsed_trees: Mapping[str, ast.Module] | None = None,
    summary_index: ContractSummaryIndex | None = None,
) -> list[FunctionContract]:
    """Infer direct and forwarding-composed typed contracts to a fixed point.

    Callers may provide a content-validated ContractSummaryIndex to avoid AST
    walking for unchanged files. Otherwise summaries are built from parsed trees.
    """

    if summary_index is not None:
        if not contract_summary_index_matches_materials(summary_index, materials):
            raise ValueError(
                "contract summary index does not match supplied head materials"
            )
        return compose_function_contracts(summary_index)

    if parsed_trees is None:
        trees: dict[str, ast.Module] = {}
        for path, source in sorted(materials.head_files.items()):
            try:
                trees[path] = ast.parse(source, filename=path)
            except SyntaxError:
                continue
    else:
        trees = dict(parsed_trees)

    summaries = build_contract_summary_index(
        materials,
        parsed_trees=trees,
    )
    return compose_function_contracts(summaries)


def _legacy_resource_return_contract(
    contract: FunctionContract,
) -> ResourceReturnContract | None:
    """Project a v1 typed contract into the compatibility scope contract."""

    if len(contract.postconditions) != 1:
        return None
    post = contract.postconditions[0]
    if (
        post.relation != "eq"
        or post.right is None
        or post.left.kind != "return_attribute"
        or post.right.kind != "parameter"
        or post.left.name is None
        or post.right.name is None
    ):
        return None

    # Compatibility is intentionally limited to the original semantic scope.
    # Generic parent/ownership attributes remain typed FunctionContract data and
    # are never relabeled as a tenant/workspace return-scope contract.
    if post.left.name not in {"workspace_id", "tenant_id"}:
        return None

    requires_non_null = any(
        predicate.relation == "non_null"
        and predicate.left.kind == "parameter"
        and predicate.left.name == post.right.name
        for predicate in contract.preconditions
    )
    unsupported_preconditions = [
        predicate
        for predicate in contract.preconditions
        if not (
            predicate.relation == "non_null"
            and predicate.left.kind == "parameter"
            and predicate.left.name == post.right.name
        )
    ]
    if unsupported_preconditions:
        return None

    return ResourceReturnContract(
        contract_id=contract.contract_id,
        qualified_name=contract.qualified_name,
        return_scope_parameter=post.right.name,
        return_scope_attribute=post.left.name,
        requires_non_null_argument=requires_non_null,
        origin=contract.origin,
    )


def infer_resource_return_contracts(
    materials: AuthMaterials,
    *,
    function_contracts: list[FunctionContract] | None = None,
    parsed_trees: Mapping[str, ast.Module] | None = None,
) -> list[ResourceReturnContract]:
    """Compatibility projection of typed contracts into scope-return contracts.

    Supplying function_contracts reuses an already inferred semantic contract
    set. parsed_trees is used only when contracts still need to be inferred.
    """

    contracts = (
        function_contracts
        if function_contracts is not None
        else infer_function_contracts(materials, parsed_trees=parsed_trees)
    )
    projected = [
        legacy
        for contract in contracts
        if (legacy := _legacy_resource_return_contract(contract)) is not None
    ]
    return sorted(projected, key=lambda item: item.contract_id)
