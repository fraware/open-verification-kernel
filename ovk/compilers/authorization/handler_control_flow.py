"""Bounded Python handler control-flow calculus.

Profile-independent CFG construction for FastAPI (and similar) route handlers.
Security binding happens in later PRs; this module only constructs and queries
control-flow structure.

Simple Boolean ``and`` / ``or`` conditions receive a *bounded* short-circuit
expansion: later operands execute only on the paths required by Python
semantics and are never marked unconditional. Nested or unsupported BoolOp
forms remain opaque (partial / refused at the security layer).
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Literal, Mapping, Sequence

from ovk.core.bundle import content_digest
from ovk.core.models import SourceRange


ControlFlowNodeKind = Literal[
    "entry",
    "statement",
    "branch",
    "return",
    "raise",
    "exit",
]
CoverageStatus = Literal["complete", "partial"]

_UNSUPPORTED_STATEMENT_TYPES: dict[type[ast.AST], str] = {
    ast.For: "for",
    ast.AsyncFor: "async_for",
    ast.While: "while",
    ast.Try: "try",
    ast.Match: "match",
    ast.With: "with",
    ast.AsyncWith: "async_with",
}

_UNSUPPORTED_NESTED_TYPES: dict[type[ast.AST], str] = {
    **_UNSUPPORTED_STATEMENT_TYPES,
    ast.Break: "break",
    ast.Continue: "continue",
    ast.Yield: "yield",
    ast.YieldFrom: "yield_from",
}


@dataclass(frozen=True)
class ControlFlowNodeSummary:
    node_id: str
    kind: ControlFlowNodeKind
    source_range: SourceRange | None = None
    expression: str | None = None
    partial: bool = False
    unsupported_construct: str | None = None


@dataclass(frozen=True)
class ControlFlowEdgeSummary:
    source_id: str
    target_id: str
    branch_value: bool | None = None


@dataclass(frozen=True)
class ControlFlowEdgeRef:
    """Stable, content-addressed reference to one CFG edge.

    ``edge_id`` is derived from ``(source_node_id, target_node_id, branch_value)``
    and must never rely on process-local object identity.
    """

    edge_id: str
    source_node_id: str
    target_node_id: str
    branch_value: bool | None = None


def control_flow_edge_id(
    source_node_id: str,
    target_node_id: str,
    branch_value: bool | None = None,
) -> str:
    """Return a handler-local edge identity from semantic edge content.

    Local IDs are unique only within one CFG. Security evidence must namespace
    them with :func:`scoped_control_flow_edge_id` (CFG digest + entrypoint).
    """

    if branch_value is None:
        branch_token = "none"
    elif branch_value:
        branch_token = "true"
    else:
        branch_token = "false"
    return f"edge:{source_node_id}->{target_node_id}:{branch_token}"


def scoped_control_flow_edge_id(
    *,
    control_flow_summary_digest: str,
    entrypoint: str,
    source_node_id: str,
    target_node_id: str,
    branch_value: bool | None = None,
) -> str:
    """Namespace a CFG edge by digest, entrypoint, endpoints, and branch value."""

    local = control_flow_edge_id(source_node_id, target_node_id, branch_value)
    digest = control_flow_summary_digest.strip()
    entry = entrypoint.strip()
    if not digest or not entry:
        raise ValueError("scoped edge identity requires CFG digest and entrypoint")
    return (
        f"edge:{digest}:{content_digest({'entrypoint': entry})[:12]}:"
        f"{local.removeprefix('edge:')}"
    )


def scoped_control_flow_edge_id_from_local(
    *,
    control_flow_summary_digest: str,
    entrypoint: str,
    local_edge_id: str,
) -> str:
    """Lift a handler-local edge id into a globally scoped security identity."""

    digest = control_flow_summary_digest.strip()
    entry = entrypoint.strip()
    local = local_edge_id.strip()
    if not digest or not entry or not local:
        raise ValueError("scoped edge identity requires digest, entrypoint, and edge")
    if not local.startswith("edge:"):
        raise ValueError("local edge id must use the edge: prefix")
    return (
        f"edge:{digest}:{content_digest({'entrypoint': entry})[:12]}:"
        f"{local.removeprefix('edge:')}"
    )


def control_flow_edge_ref(
    source_node_id: str,
    target_node_id: str,
    branch_value: bool | None = None,
) -> ControlFlowEdgeRef:
    """Build a stable edge reference from semantic endpoints and branch value."""

    return ControlFlowEdgeRef(
        edge_id=control_flow_edge_id(source_node_id, target_node_id, branch_value),
        source_node_id=source_node_id,
        target_node_id=target_node_id,
        branch_value=branch_value,
    )


def control_flow_edge_ref_from_summary(
    edge: ControlFlowEdgeSummary,
) -> ControlFlowEdgeRef:
    """Lift a CFG edge summary into a stable edge reference."""

    return control_flow_edge_ref(
        edge.source_id,
        edge.target_id,
        edge.branch_value,
    )


@dataclass(frozen=True)
class HandlerControlFlowSummary:
    entry_id: str
    exit_ids: tuple[str, ...]
    nodes: tuple[ControlFlowNodeSummary, ...]
    edges: tuple[ControlFlowEdgeSummary, ...]
    coverage_status: CoverageStatus
    unsupported_constructs: tuple[str, ...]

    def node_map(self) -> dict[str, ControlFlowNodeSummary]:
        return {node.node_id: node for node in self.nodes}

    def predecessors(self) -> dict[str, tuple[str, ...]]:
        preds: dict[str, list[str]] = {node.node_id: [] for node in self.nodes}
        for edge in self.edges:
            preds.setdefault(edge.target_id, []).append(edge.source_id)
        return {node_id: tuple(sources) for node_id, sources in preds.items()}

    def successors(self) -> dict[str, tuple[ControlFlowEdgeSummary, ...]]:
        succs: dict[str, list[ControlFlowEdgeSummary]] = {
            node.node_id: [] for node in self.nodes
        }
        for edge in self.edges:
            succs.setdefault(edge.source_id, []).append(edge)
        return {
            node_id: tuple(edges) for node_id, edges in succs.items()
        }

    def digest(self) -> str:
        return content_digest(self.canonical_payload())

    def canonical_payload(self) -> dict:
        return {
            "entry_id": self.entry_id,
            "exit_ids": list(self.exit_ids),
            "nodes": [
                {
                    "node_id": node.node_id,
                    "kind": node.kind,
                    "source_range": (
                        None
                        if node.source_range is None
                        else node.source_range.model_dump(mode="json")
                    ),
                    "expression": node.expression,
                    "partial": node.partial,
                    "unsupported_construct": node.unsupported_construct,
                }
                for node in self.nodes
            ],
            "edges": [
                {
                    "source_id": edge.source_id,
                    "target_id": edge.target_id,
                    "branch_value": edge.branch_value,
                }
                for edge in self.edges
            ],
            "coverage_status": self.coverage_status,
            "unsupported_constructs": list(self.unsupported_constructs),
        }


def control_flow_from_payload(payload: Mapping[str, object]) -> HandlerControlFlowSummary:
    nodes = tuple(
        ControlFlowNodeSummary(
            node_id=str(item["node_id"]),
            kind=str(item["kind"]),  # type: ignore[arg-type]
            source_range=(
                SourceRange.model_validate(item["source_range"])
                if item.get("source_range") is not None
                else None
            ),
            expression=(
                str(item["expression"])
                if item.get("expression") is not None
                else None
            ),
            partial=bool(item.get("partial", False)),
            unsupported_construct=(
                str(item["unsupported_construct"])
                if item.get("unsupported_construct") is not None
                else None
            ),
        )
        for item in (payload.get("nodes") or [])  # type: ignore[union-attr]
    )
    edges = tuple(
        ControlFlowEdgeSummary(
            source_id=str(item["source_id"]),
            target_id=str(item["target_id"]),
            branch_value=(
                None
                if item.get("branch_value") is None
                else bool(item["branch_value"])
            ),
        )
        for item in (payload.get("edges") or [])  # type: ignore[union-attr]
    )
    return HandlerControlFlowSummary(
        entry_id=str(payload["entry_id"]),
        exit_ids=tuple(str(value) for value in payload.get("exit_ids") or []),  # type: ignore[union-attr]
        nodes=nodes,
        edges=edges,
        coverage_status=str(payload["coverage_status"]),  # type: ignore[arg-type]
        unsupported_constructs=tuple(
            str(value) for value in payload.get("unsupported_constructs") or []  # type: ignore[union-attr]
        ),
    )


class _CfgBuilder:
    def __init__(self, *, path: str) -> None:
        self.path = path
        self._counter = 0
        self.nodes: list[ControlFlowNodeSummary] = []
        self.edges: list[ControlFlowEdgeSummary] = []
        self.unsupported: list[str] = []
        self.exit_id = self._alloc("exit", kind="exit")

    def _alloc(
        self,
        prefix: str,
        *,
        kind: ControlFlowNodeKind,
        source_range: SourceRange | None = None,
        expression: str | None = None,
        partial: bool = False,
        unsupported_construct: str | None = None,
    ) -> str:
        self._counter += 1
        node_id = f"{prefix}:{self._counter}"
        self.nodes.append(
            ControlFlowNodeSummary(
                node_id=node_id,
                kind=kind,
                source_range=source_range,
                expression=expression,
                partial=partial,
                unsupported_construct=unsupported_construct,
            )
        )
        return node_id

    def _range_of(self, node: ast.AST) -> SourceRange:
        return SourceRange(
            path=self.path,
            start_line=getattr(node, "lineno", None),
            end_line=getattr(node, "end_lineno", getattr(node, "lineno", None)),
            start_column=getattr(node, "col_offset", None),
            end_column=getattr(node, "end_col_offset", None),
        )

    def _edge(
        self,
        source_id: str,
        target_id: str,
        *,
        branch_value: bool | None = None,
    ) -> None:
        self.edges.append(
            ControlFlowEdgeSummary(
                source_id=source_id,
                target_id=target_id,
                branch_value=branch_value,
            )
        )

    def _record_unsupported(self, construct: str) -> None:
        if construct not in self.unsupported:
            self.unsupported.append(construct)

    def _nested_unsupported(self, node: ast.AST) -> tuple[str, ...]:
        found: list[str] = []
        for child in ast.walk(node):
            for node_type, name in _UNSUPPORTED_NESTED_TYPES.items():
                if isinstance(child, node_type) and name not in found:
                    found.append(name)
        return tuple(found)

    def build(self, handler: ast.FunctionDef | ast.AsyncFunctionDef) -> HandlerControlFlowSummary:
        entry_id = self._alloc("entry", kind="entry")
        fallthrough = self._link_block(handler.body, entry_id)
        if fallthrough is not None:
            self._edge(fallthrough, self.exit_id)

        coverage: CoverageStatus = "partial" if self.unsupported else "complete"
        return HandlerControlFlowSummary(
            entry_id=entry_id,
            exit_ids=(self.exit_id,),
            nodes=tuple(self.nodes),
            edges=tuple(self.edges),
            coverage_status=coverage,
            unsupported_constructs=tuple(self.unsupported),
        )

    def _link_block(
        self,
        statements: Sequence[ast.stmt],
        predecessor: str,
        *,
        first_branch_value: bool | None = None,
    ) -> str | None:
        """Link a statement list after ``predecessor``.

        Returns the last fallthrough node id, or None if the block always exits.
        Unreachable statements after a terminal are not wired into the CFG, so
        unsupported constructs there cannot contaminate sink-reaching paths.
        """

        if not statements:
            return predecessor

        current: str | None = predecessor
        pending_branch_value = first_branch_value
        for statement in statements:
            if current is None:
                break
            current = self._link_statement(
                statement,
                current,
                branch_value=pending_branch_value,
            )
            pending_branch_value = None
        return current

    def _link_statement(
        self,
        statement: ast.stmt,
        predecessor: str,
        *,
        branch_value: bool | None = None,
    ) -> str | None:
        if isinstance(statement, ast.If):
            return self._link_if(statement, predecessor, branch_value=branch_value)

        if isinstance(statement, ast.Return):
            node_id = self._alloc(
                "return",
                kind="return",
                source_range=self._range_of(statement),
                expression=ast.unparse(statement),
            )
            self._edge(predecessor, node_id, branch_value=branch_value)
            self._edge(node_id, self.exit_id)
            return None

        if isinstance(statement, ast.Raise):
            node_id = self._alloc(
                "raise",
                kind="raise",
                source_range=self._range_of(statement),
                expression=ast.unparse(statement),
            )
            self._edge(predecessor, node_id, branch_value=branch_value)
            self._edge(node_id, self.exit_id)
            return None

        for node_type, construct in _UNSUPPORTED_STATEMENT_TYPES.items():
            if isinstance(statement, node_type):
                self._record_unsupported(construct)
                node_id = self._alloc(
                    "partial",
                    kind="statement",
                    source_range=self._range_of(statement),
                    expression=ast.unparse(statement),
                    partial=True,
                    unsupported_construct=construct,
                )
                self._edge(predecessor, node_id, branch_value=branch_value)
                return node_id

        nested = self._nested_unsupported(statement)
        if nested:
            for construct in nested:
                self._record_unsupported(construct)
            node_id = self._alloc(
                "stmt",
                kind="statement",
                source_range=self._range_of(statement),
                expression=ast.unparse(statement),
                partial=True,
                unsupported_construct=nested[0],
            )
            self._edge(predecessor, node_id, branch_value=branch_value)
            return node_id

        node_id = self._alloc(
            "stmt",
            kind="statement",
            source_range=self._range_of(statement),
            expression=ast.unparse(statement),
        )
        self._edge(predecessor, node_id, branch_value=branch_value)
        return node_id

    def _link_if(
        self,
        statement: ast.If,
        predecessor: str,
        *,
        branch_value: bool | None = None,
    ) -> str | None:
        simple = _as_simple_boolop(statement.test)
        if simple is not None:
            return self._link_short_circuit_if(
                statement,
                predecessor,
                simple,
                incoming_branch_value=branch_value,
            )

        branch_id = self._alloc(
            "branch",
            kind="branch",
            source_range=self._range_of(statement.test),
            expression=ast.unparse(statement.test),
        )
        self._edge(predecessor, branch_id, branch_value=branch_value)

        if statement.body:
            true_fall = self._link_block(
                statement.body,
                branch_id,
                first_branch_value=True,
            )
        else:
            true_fall = "__empty_true__"

        if not statement.orelse:
            false_fall: str | None = "__empty_false__"
        else:
            false_fall = self._link_orelse(statement.orelse, branch_id)

        arms_to_join: list[tuple[str | None, bool | None]] = []
        if true_fall == "__empty_true__":
            arms_to_join.append((branch_id, True))
        elif true_fall is not None:
            arms_to_join.append((true_fall, None))

        if false_fall == "__empty_false__":
            arms_to_join.append((branch_id, False))
        elif false_fall is not None:
            # Nested elif returns a join/fallthrough already reached via a
            # False-labeled edge from this branch.
            arms_to_join.append((false_fall, None))

        if not arms_to_join:
            return None

        join_id = self._alloc("join", kind="statement", expression="__cfg_join__")
        for source_id, label in arms_to_join:
            assert source_id is not None
            self._edge(source_id, join_id, branch_value=label)
        return join_id

    def _link_short_circuit_if(
        self,
        statement: ast.If,
        predecessor: str,
        boolop: ast.BoolOp,
        *,
        incoming_branch_value: bool | None,
    ) -> str | None:
        """Expand a flat ``and``/``or`` into short-circuit-aware CFG nodes.

        ``A or B``: B executes only on A-false paths.
        ``A and B``: B executes only on A-true paths.
        Operand branch nodes carry the atom expression (including calls) so
        dominance binds to the short-circuit-aware execution condition — never
        as an unconditional pre-if statement.
        """

        is_or = isinstance(boolop.op, ast.Or)
        true_sources: list[tuple[str, bool | None]] = []
        false_sources: list[tuple[str, bool | None]] = []

        current_pred = predecessor
        current_label = incoming_branch_value
        values = list(boolop.values)
        for index, atom in enumerate(values):
            branch_id = self._alloc(
                "sc_branch",
                kind="branch",
                source_range=self._range_of(atom),
                expression=ast.unparse(atom),
            )
            self._edge(current_pred, branch_id, branch_value=current_label)
            is_last = index == len(values) - 1
            if is_or:
                # True short-circuits the remaining operands.
                true_sources.append((branch_id, True))
                if is_last:
                    false_sources.append((branch_id, False))
                else:
                    current_pred = branch_id
                    current_label = False
            else:
                # False short-circuits the remaining operands.
                false_sources.append((branch_id, False))
                if is_last:
                    true_sources.append((branch_id, True))
                else:
                    current_pred = branch_id
                    current_label = True

        cond_true = self._alloc(
            "sc_true",
            kind="statement",
            expression="__cfg_boolop_true__",
        )
        cond_false = self._alloc(
            "sc_false",
            kind="statement",
            expression="__cfg_boolop_false__",
        )
        for source_id, label in true_sources:
            self._edge(source_id, cond_true, branch_value=label)
        for source_id, label in false_sources:
            self._edge(source_id, cond_false, branch_value=label)

        if statement.body:
            true_fall = self._link_block(statement.body, cond_true)
        else:
            true_fall = cond_true

        if not statement.orelse:
            false_fall: str | None = cond_false
        else:
            false_fall = self._link_orelse_from(statement.orelse, cond_false)

        arms_to_join: list[tuple[str | None, bool | None]] = []
        if true_fall is not None:
            arms_to_join.append((true_fall, None))
        if false_fall is not None:
            arms_to_join.append((false_fall, None))
        if not arms_to_join:
            return None
        join_id = self._alloc("join", kind="statement", expression="__cfg_join__")
        for source_id, label in arms_to_join:
            assert source_id is not None
            self._edge(source_id, join_id, branch_value=label)
        return join_id

    def _link_orelse_from(
        self,
        orelse: Sequence[ast.stmt],
        predecessor: str,
    ) -> str | None:
        """Link orelse after an already-materialized false-condition node."""

        if len(orelse) == 1 and isinstance(orelse[0], ast.If):
            return self._link_if(orelse[0], predecessor)
        return self._link_block(orelse, predecessor)

    def _link_orelse(
        self,
        orelse: Sequence[ast.stmt],
        branch_id: str,
    ) -> str | None:
        if len(orelse) == 1 and isinstance(orelse[0], ast.If):
            return self._link_if(
                orelse[0],
                branch_id,
                branch_value=False,
            )
        return self._link_block(
            orelse,
            branch_id,
            first_branch_value=False,
        )


def _is_supported_boolop_atom(node: ast.AST) -> bool:
    """Atoms admitted by the bounded short-circuit theorem."""

    if isinstance(node, (ast.Name, ast.Constant)):
        return True
    if isinstance(node, ast.Attribute):
        return _is_supported_boolop_atom(node.value)
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        return _is_supported_boolop_atom(node.operand)
    if isinstance(node, ast.Call):
        if not isinstance(node.func, (ast.Name, ast.Attribute)):
            return False
        if isinstance(node.func, ast.Attribute) and not _is_supported_boolop_atom(
            node.func.value
        ):
            return False
        for arg in node.args:
            if not _is_supported_boolop_atom(arg):
                return False
        for keyword in node.keywords:
            if keyword.arg is None:
                return False
            if not _is_supported_boolop_atom(keyword.value):
                return False
        return True
    return False


def _as_simple_boolop(test: ast.AST) -> ast.BoolOp | None:
    """Return a flat And/Or of supported atoms, else None (keep opaque)."""

    if not isinstance(test, ast.BoolOp):
        return None
    if not isinstance(test.op, (ast.And, ast.Or)):
        return None
    if len(test.values) < 2:
        return None
    if any(isinstance(value, ast.BoolOp) for value in test.values):
        # Nested BoolOp stays opaque / may be partial at security binding.
        return None
    if not all(_is_supported_boolop_atom(value) for value in test.values):
        return None
    return test


def is_unconditionally_executed(
    cfg: "HandlerControlFlowSummary",
    node_id: str,
) -> bool:
    """True iff every exit-reaching path from entry executes ``node_id``.

    Short-circuit operands after the first BoolOp atom are not unconditional:
    there exist exit-reaching paths that skip them.
    """

    if node_id not in {node.node_id for node in cfg.nodes}:
        return False
    if not cfg.exit_ids:
        return False
    return all(dominates(cfg, node_id, exit_id) for exit_id in cfg.exit_ids)


def build_handler_control_flow(
    handler: ast.FunctionDef | ast.AsyncFunctionDef,
    *,
    path: str = "<handler>",
) -> HandlerControlFlowSummary:
    """Construct a bounded CFG for one function/handler body."""

    return _CfgBuilder(path=path).build(handler)


def build_handler_control_flow_from_source(
    source: str,
    *,
    path: str = "<handler>",
    function_name: str | None = None,
) -> HandlerControlFlowSummary:
    """Parse source and build CFG for the first / named function."""

    tree = ast.parse(source)
    functions = [
        node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]
    if function_name is not None:
        functions = [node for node in functions if node.name == function_name]
    if not functions:
        raise ValueError("no function found for control-flow extraction")
    return build_handler_control_flow(functions[0], path=path)


def compute_dominators(
    cfg: HandlerControlFlowSummary,
) -> dict[str, frozenset[str]]:
    """Standard iterative dominator calculation over reachable nodes."""

    node_ids = [node.node_id for node in cfg.nodes]
    preds = cfg.predecessors()
    reachable = _reachable_from(cfg, cfg.entry_id)
    dom: dict[str, frozenset[str]] = {
        node_id: (frozenset({node_id}) if node_id == cfg.entry_id else frozenset(reachable))
        for node_id in node_ids
        if node_id in reachable
    }

    changed = True
    while changed:
        changed = False
        for node_id in node_ids:
            if node_id == cfg.entry_id or node_id not in reachable:
                continue
            predecessors = [p for p in preds.get(node_id, ()) if p in dom]
            if not predecessors:
                new_dom = frozenset({node_id})
            else:
                intersection = frozenset.intersection(*(dom[p] for p in predecessors))
                new_dom = frozenset({node_id}) | intersection
            if new_dom != dom[node_id]:
                dom[node_id] = new_dom
                changed = True
    return dom


def dominates(cfg: HandlerControlFlowSummary, dominator: str, node: str) -> bool:
    """Return True iff ``dominator`` dominates ``node``."""

    dom = compute_dominators(cfg)
    return dominator in dom.get(node, frozenset())


def _reachable_from(cfg: HandlerControlFlowSummary, start: str) -> frozenset[str]:
    succs = cfg.successors()
    seen: set[str] = set()
    stack = [start]
    while stack:
        current = stack.pop()
        if current in seen:
            continue
        seen.add(current)
        for edge in succs.get(current, ()):
            stack.append(edge.target_id)
    return frozenset(seen)


def _nodes_reaching(cfg: HandlerControlFlowSummary, sink: str) -> frozenset[str]:
    """Nodes that can reach ``sink`` (including sink)."""

    preds = cfg.predecessors()
    seen: set[str] = set()
    stack = [sink]
    while stack:
        current = stack.pop()
        if current in seen:
            continue
        seen.add(current)
        for predecessor in preds.get(current, ()):
            stack.append(predecessor)
    return frozenset(seen)


def paths_avoiding(
    cfg: HandlerControlFlowSummary,
    entry: str,
    sink: str,
    avoided: str,
) -> tuple[tuple[str, ...], ...]:
    """Enumerate simple paths from entry to sink that do not visit ``avoided``."""

    succs = cfg.successors()
    found: list[tuple[str, ...]] = []

    def walk(current: str, path: tuple[str, ...]) -> None:
        if current == avoided:
            return
        if current == sink:
            found.append(path + (current,))
            return
        if current in path:
            return
        next_path = path + (current,)
        for edge in succs.get(current, ()):
            walk(edge.target_id, next_path)

    walk(entry, ())
    return tuple(found)


def coverage_authoritative_for(
    cfg: HandlerControlFlowSummary,
    sink: str,
) -> bool:
    """True when sink-reaching region has no partial/unsupported nodes."""

    if sink not in {node.node_id for node in cfg.nodes}:
        return False
    reaching = _nodes_reaching(cfg, sink) & _reachable_from(cfg, cfg.entry_id)
    if sink not in reaching:
        return False
    node_map = cfg.node_map()
    for node_id in reaching:
        node = node_map[node_id]
        if node.partial or node.unsupported_construct is not None:
            return False
    return True


def find_control_flow_edge_ref(
    cfg: HandlerControlFlowSummary,
    *,
    source_node_id: str,
    target_node_id: str | None = None,
    branch_value: bool | None = None,
    require_branch_value: bool = False,
) -> ControlFlowEdgeRef | None:
    """Resolve exactly one CFG edge, or None when missing or ambiguous.

    When ``require_branch_value`` is True, ``branch_value`` must match exactly
    (including ``None``). When False and ``branch_value`` is provided, only
    edges with that branch value are considered; ``target_node_id`` may further
    narrow the match.
    """

    matches: list[ControlFlowEdgeRef] = []
    for edge in cfg.edges:
        if edge.source_id != source_node_id:
            continue
        if target_node_id is not None and edge.target_id != target_node_id:
            continue
        if require_branch_value or branch_value is not None:
            if edge.branch_value != branch_value:
                continue
        matches.append(control_flow_edge_ref_from_summary(edge))
    if len(matches) != 1:
        return None
    return matches[0]


def find_nodes_by_expression_substring(
    cfg: HandlerControlFlowSummary,
    needle: str,
) -> tuple[ControlFlowNodeSummary, ...]:
    return tuple(
        node
        for node in cfg.nodes
        if node.expression is not None and needle in node.expression
    )


def find_nodes_covering_line(
    cfg: HandlerControlFlowSummary,
    line: int,
) -> tuple[ControlFlowNodeSummary, ...]:
    matches: list[ControlFlowNodeSummary] = []
    for node in cfg.nodes:
        source_range = node.source_range
        if source_range is None:
            continue
        start = source_range.start_line
        end = source_range.end_line if source_range.end_line is not None else start
        if start is None:
            continue
        if int(start) <= line <= int(end or start):
            matches.append(node)
    return tuple(matches)
