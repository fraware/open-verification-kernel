"""Caller-relative Python callee resolution (#160 / #161 / #163 / #165 / #167 / #169).

Replaces repository-global simple-name callee indexing with resolution that
honours the caller's module-level final bindings and authenticated-manifest
import identity under the shared import-root theorem (#161).

#163 adds bounded callable/module mutation closure: an imported module export
or source-grounded callable retains precise authorizing identity only when
both ModuleBindingIdentity and CallableBehaviorIdentity are established.

#165 extends mutation closure with bounded module/callable *object-alias*
provenance: assignments may alias ModuleObject / CallableObject /
ModuleNamespace identities; mutation closure operates on object identity at
the statement of mutation (not spelling of final bindings). The same
identity-flow is shared by bypass writer closure and interprocedural
argument provenance (no divergent systems).

#167 adds phase-sensitive *request-time* callable identity: handler-body
mutations of module exports / callable behavior invalidate authorizing
identity from the mutation point onward (Unknown > false PASS), reusing
the same identity environment via RequestTimeIdentitySession.

#169 forks and joins the *whole* request-time abstract state across
control-flow predecessors (may-poison / must-reestablish) so branch-local
re-establishment cannot clear poisons that remain elsewhere.

Resolution for a bare call ``write_state(...)``:
1. local function binding in the caller module
2. explicit imported binding (followed through a unique manifest module)
3. otherwise unresolved → UNKNOWN when Request/state escapes

Never searches the repository for a same-leaf function merely because the
name matches. Import follow uses :func:`python_import_space.module_candidates_in_manifest`
— the same primitive as closed-world import accounting.
"""

from __future__ import annotations

import ast
import copy
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from typing import Literal

from ovk.compilers.authorization.python_import_space import (
    module_candidates_in_manifest,
    normalize_import_roots,
    normalize_path,
)

_IMPLEMENTATION_VERSION = "0.30.0"
_MAX_IMPORT_FOLLOW_DEPTH = 8

BindingKind = Literal["function", "import_name", "import_module", "rebound"]


@dataclass(frozen=True)
class ResolvedCallee:
    """A uniquely resolved module-level function identity."""

    path: str
    node: ast.FunctionDef | ast.AsyncFunctionDef

    @property
    def identity(self) -> tuple[str, str]:
        return (self.path, self.node.name)

    @property
    def qualified_name(self) -> str:
        return f"{self.path}:{self.node.name}"


@dataclass(frozen=True)
class FinalBinding:
    """Module-scope final binding for one local name.

    ``behavior_established`` is CallableBehaviorIdentity: false when a
    represented execution can mutate the callable object (``__code__``,
    attribute/subscript writes, etc.) while ModuleBindingIdentity remains.
    Authorizing resolution requires both identities.
    """

    kind: BindingKind
    function_node: ast.FunctionDef | ast.AsyncFunctionDef | None = None
    # Absolute import module name for import_name / import_module.
    module_name: str | None = None
    # Imported attribute for ``from mod import attr`` (attr may differ from local).
    imported_name: str | None = None
    behavior_established: bool = True


@dataclass(frozen=True)
class CalleeResolveResult:
    """Outcome of resolving one call expression's callee."""

    callee: ResolvedCallee | None
    reason: str | None = None

    @property
    def resolved(self) -> bool:
        return self.callee is not None


@dataclass(frozen=True)
class _MutationEffects:
    """Collected module-export and callable-behavior mutation effects (#163/#165)."""

    # Defining module path → export names whose ModuleBindingIdentity is lost.
    export_mutations: Mapping[str, frozenset[str]]
    # (defining_path, export_name) with CallableBehaviorIdentity lost.
    behavior_mutations: frozenset[tuple[str, str]]
    # Unsupported dynamic module surfaces (e.g. sys.modules) → full poison.
    unsupported_module_mutation: bool


# ---------------------------------------------------------------------------
# #165 object-alias identity lattice (narrow, security-relevant only)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ModuleObject:
    """Identity of an imported / resolved module object."""

    path: str


@dataclass(frozen=True)
class CallableObject:
    """Identity of a source-grounded callable export."""

    defining_path: str
    export_name: str


@dataclass(frozen=True)
class ModuleNamespace:
    """``module.__dict__`` / ``vars(module)`` namespace surface."""

    module_path: str


_ObjectAtom = ModuleObject | CallableObject | ModuleNamespace


@dataclass(frozen=True)
class _IdentityPointsTo:
    """May-point-to set for one local name (Unknown > false PASS).

    Distinguishes *bottom* (definitely no tracked module/callable identity —
    used for closed-world severance) from *unknown* (may alias a tracked
    object via an unmodeled value). Mutation of an unknown receiver may
    spelling-poison matching exports; mutation of bottom does not.
    """

    known: frozenset[_ObjectAtom] = frozenset()
    unknown: bool = False

    @staticmethod
    def bottom() -> _IdentityPointsTo:
        return _IdentityPointsTo(known=frozenset(), unknown=False)

    @staticmethod
    def unknown_only() -> _IdentityPointsTo:
        return _IdentityPointsTo(known=frozenset(), unknown=True)

    @staticmethod
    def precise(atom: _ObjectAtom) -> _IdentityPointsTo:
        return _IdentityPointsTo(known=frozenset({atom}), unknown=False)

    def join(self, other: _IdentityPointsTo) -> _IdentityPointsTo:
        return _IdentityPointsTo(
            known=self.known | other.known,
            unknown=self.unknown or other.unknown,
        )

    def is_bottom(self) -> bool:
        return not self.known and not self.unknown


# Callable-object mutation surfaces (#163); unknown receivers that write these
# lose CallableBehaviorIdentity across the closed world.
_CALLABLE_BEHAVIOR_ATTRS = frozenset(
    {
        "__code__",
        "__defaults__",
        "__kwdefaults__",
        "__annotations__",
        "__dict__",
        "__globals__",
        "__closure__",
        "__module__",
        "__name__",
        "__qualname__",
    }
)

def import_module_name_from_importer(
    node: ast.ImportFrom,
    *,
    importer_path: str,
) -> str | None:
    """Resolve ImportFrom to an absolute module name from the importer path."""

    if not node.level or node.level <= 0:
        return node.module

    importer = normalize_path(importer_path)
    parts = importer.split("/")
    if not parts:
        return None
    if parts[-1].endswith(".py"):
        parts[-1] = parts[-1][:-3]
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    else:
        parts = parts[:-1]
    if node.level - 1 > len(parts):
        return None
    if node.level > 1:
        parts = parts[: -(node.level - 1)]
    if node.module:
        parts = list(parts) + node.module.split(".")
    return ".".join(parts) if parts else None


def _collect_store_names(target: ast.AST) -> list[str]:
    names: list[str] = []
    if isinstance(target, ast.Name):
        names.append(target.id)
    elif isinstance(target, ast.Starred):
        names.extend(_collect_store_names(target.value))
    elif isinstance(target, (ast.Tuple, ast.List)):
        for elt in target.elts:
            names.extend(_collect_store_names(elt))
    return names


def _collect_match_pattern_names(pattern: ast.AST) -> list[str]:
    """Names bound by a ``match`` pattern (module-scope adversary)."""

    names: list[str] = []
    if isinstance(pattern, ast.MatchAs):
        if pattern.name:
            names.append(pattern.name)
        if pattern.pattern is not None:
            names.extend(_collect_match_pattern_names(pattern.pattern))
    elif isinstance(pattern, ast.MatchStar):
        if pattern.name:
            names.append(pattern.name)
    elif isinstance(pattern, ast.MatchMapping):
        if pattern.rest:
            names.append(pattern.rest)
        for item in pattern.patterns:
            names.extend(_collect_match_pattern_names(item))
    elif isinstance(pattern, (ast.MatchSequence, ast.MatchOr)):
        for item in pattern.patterns:
            names.extend(_collect_match_pattern_names(item))
    elif isinstance(pattern, ast.MatchClass):
        for item in pattern.patterns:
            names.extend(_collect_match_pattern_names(item))
        for item in pattern.kwd_patterns:
            names.extend(_collect_match_pattern_names(item))
    return names


def _mark_rebound(bindings: dict[str, FinalBinding], names: list[str] | set[str]) -> None:
    for name in names:
        if name == "*":
            continue
        bindings[name] = FinalBinding(kind="rebound")


def _is_globals_call(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in {"globals", "locals", "vars"}
        and not node.args
        and not node.keywords
    )


def _static_str(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _static_key(node: ast.AST) -> object | None:
    """Static Constant key (str/int/…) for dict/subscript peels."""

    if isinstance(node, ast.Constant):
        return node.value
    return None


def _static_sequence_index(node: ast.AST) -> int | None:
    """Static int index for sequence ``pop`` / ``__getitem__`` peels.

    Covers bare Constants, unary minus (``-1``), and bitwise invert (``~0``)
    so negative / bitwise last-element peels share bare ``.pop()``
    (Unknown > false PASS).
    """

    if isinstance(node, ast.Constant) and isinstance(node.value, int):
        return node.value
    if isinstance(node, ast.UnaryOp) and isinstance(node.operand, ast.Constant):
        if not isinstance(node.operand.value, int):
            return None
        if isinstance(node.op, ast.USub):
            return -node.operand.value
        if isinstance(node.op, ast.Invert):
            return ~node.operand.value
    return None


# Dunder Attribute spellings of operator projection factories.
_PROJECTION_DUNDER_ALIASES: Mapping[str, str] = {
    "__ior__": "ior",
    "__or__": "or_",
    "__iadd__": "iadd",
    "__iconcat__": "iconcat",
    "__setitem__": "setitem",
    "__getitem__": "getitem",
}


# Namespace / mapping view attrs that project key→value identity the same way
# ``.get`` does (``getattr(ns, "__getitem__"|"pop")`` / ``ns.__getitem__``).
_NS_DICT_VIEW_ATTRS = frozenset({"get", "pop", "__getitem__", "setdefault"})
# Mapping / namespace constructors that pack kwargs / dict literals like ``dict``.
_MAPPING_CTOR_NAMES = frozenset(
    {
        "dict",
        "OrderedDict",
        "UserDict",
        "SimpleNamespace",
        "defaultdict",
        "ChainMap",
        "Counter",
    }
)
# Mapping merge spellings that union both operand packs (``a | b``).
_MAPPING_MERGE_METHODS = frozenset({"__or__", "__ior__", "__ror__"})
# ``operator.or_`` / ``operator.ior`` merge the same way (alias-tracked via
# ``operator_projection_aliases`` so ``from operator import or_ as o`` peels).
_MAPPING_MERGE_FUNCS = frozenset({"or_", "ior"})
# Bound / unbound dict iteration + mutation views tracked as Name products.
_DICT_ITER_VIEW_ATTRS = frozenset(
    {"keys", "values", "items", "popitem", "__iter__"}
)
_DICT_MUTATOR_ATTRS = frozenset({"update", "setdefault", "__setitem__", "pop", "clear"})
# Mapping copy / projection factories that preserve packed identities.
_MAPPING_COPY_FUNCS = frozenset({"copy", "deepcopy"})
# itertools adapters that project iterable element packs.
_ITERTOOLS_ADAPTER_NAMES = frozenset(
    {
        "chain",
        "islice",
        "chain_from_iterable",
        "from_iterable",
        "starmap",
        "compress",
        "filterfalse",
        "dropwhile",
        "takewhile",
        "tee",
        "zip_longest",
        "cycle",
        "repeat",
        "permutations",
        "combinations",
        "combinations_with_replacement",
        "product",
        "groupby",
        "accumulate",
        "pairwise",
        "batched",
    }
)
# Adapters that flatten one level (``chain.from_iterable`` / Name alias).
_ITERTOOLS_FLATTEN_ADAPTERS = frozenset({"chain_from_iterable", "from_iterable"})
# In-place merge / grow methods shared by AugAssign, operator, and dunders.
_INPLACE_MERGE_METHODS = frozenset(
    {"__iadd__", "__iconcat__", "__ior__", "iadd", "iconcat", "ior"}
)
_INPLACE_MERGE_FUNCS = frozenset({"iadd", "iconcat", "ior", "or_"})
# Shared key=/reduce applicator Names (import-as / getattr peels).
_KEY_APPLICATOR_NAMES = frozenset({"sorted", "max", "min", "reduce"})
# ChainMap internal list attrs grown via append/extend/insert/__iadd__.
_CHAINMAP_LIST_ATTRS = frozenset({"maps", "parents"})


def _is_dict_constructor(
    func: ast.AST,
    *,
    dict_ctor_aliases: frozenset[str] | None = None,
    getattr_aliases: frozenset[str] | None = None,
) -> bool:
    """True for ``dict`` / ``builtins.dict`` / Name-bound / ``dict.__call__`` forms.

    Also covers ``OrderedDict`` / ``UserDict`` / ``SimpleNamespace`` and
    ``getattr(builtins, \"dict\")`` so packing peels stay shared (Unknown >
    false PASS).
    """

    aliases = dict_ctor_aliases or frozenset()
    func = _peel_call_func(func)
    if isinstance(func, ast.Name):
        return func.id in _MAPPING_CTOR_NAMES or func.id in aliases
    if isinstance(func, ast.Attribute):
        if func.attr in _MAPPING_CTOR_NAMES:
            return True
        # ``dict.__call__(...)`` / ``D.__call__(...)`` when D is a dict ctor.
        if func.attr == "__call__":
            return _is_dict_constructor(
                func.value,
                dict_ctor_aliases=aliases,
                getattr_aliases=getattr_aliases,
            )
        return False
    if isinstance(func, ast.Subscript):
        # Namespace projections: ``vars(builtins)["dict"]`` /
        # ``builtins.__dict__["dict"]`` / ``ns["dict"]``.
        if _static_str(func.slice) in _MAPPING_CTOR_NAMES:
            return True
        # Packed ``[SimpleNamespace][0]`` / ``[SN][0]`` ctor peels.
        for cand in _shallow_packed_callee_exprs(func):
            if cand is func:
                continue
            if _is_dict_constructor(
                cand,
                dict_ctor_aliases=aliases,
                getattr_aliases=getattr_aliases,
            ):
                return True
        return False
    if isinstance(func, ast.Call):
        # ``getattr(builtins, "dict")`` / renamed getattr.
        attr = _getattr_static_name(func, getattr_aliases=getattr_aliases)
        if attr in _MAPPING_CTOR_NAMES:
            return True
        # ``vars(builtins).get("dict")`` / ``.setdefault`` / ``.pop`` /
        # ``.__getitem__`` namespace key projections.
        peeled = _peel_call_func(func.func)
        if (
            isinstance(peeled, ast.Attribute)
            and peeled.attr in _NS_DICT_VIEW_ATTRS
            and func.args
        ):
            return _static_str(func.args[0]) in _MAPPING_CTOR_NAMES
    return False


def _is_dict_fromkeys(
    func: ast.AST,
    *,
    dict_ctor_aliases: frozenset[str] | None = None,
    dict_view_products: Mapping[str, str] | None = None,
) -> bool:
    """True for ``dict.fromkeys`` / ``D.fromkeys`` / Name-bound ``fk`` forms."""

    aliases = dict_ctor_aliases or frozenset()
    views = dict_view_products or {}
    func = _peel_transparent_callee(func)
    if isinstance(func, ast.Name):
        return views.get(func.id) in {"fromkeys", "dict.fromkeys"}
    if not isinstance(func, ast.Attribute) or func.attr != "fromkeys":
        return False
    recv = _peel_call_func(func.value)
    if isinstance(recv, ast.Name):
        return recv.id == "dict" or recv.id in aliases
    if isinstance(recv, ast.Attribute):
        return recv.attr == "dict"
    return False


def _dict_call_values_for_key(
    call: ast.Call, key: object | None = None
) -> list[ast.AST]:
    """Values packed by ``dict(p=Proxy)`` / ``dict(**{…})`` / ``dict({…})``.

    Recurses through nested mapping constructors in ``**`` spreads and
    positional mapping args so ``SimpleNamespace(**dict(m=…)).m`` /
    ``dict(**dict(m=…))`` share one peel with bare kwargs (Unknown >
    false PASS).
    """

    found: list[ast.AST] = []
    for kw in call.keywords:
        if kw.arg is None:
            if isinstance(kw.value, ast.Dict):
                if key is None:
                    found.extend(v for v in kw.value.values if v is not None)
                elif isinstance(key, str):
                    found.extend(_dict_values_for_static_key(kw.value, key))
                else:
                    for map_key, map_val in zip(kw.value.keys, kw.value.values):
                        if (
                            map_val is not None
                            and isinstance(map_key, ast.Constant)
                            and map_key.value == key
                        ):
                            found.append(map_val)
            elif isinstance(kw.value, ast.Call) and _is_dict_constructor(
                kw.value.func
            ):
                found.extend(_dict_call_values_for_key(kw.value, key))
            else:
                found.append(kw.value)
        elif key is None or kw.arg == key:
            found.append(kw.value)
    for arg in call.args:
        nested = arg.value if isinstance(arg, ast.Starred) else arg
        if isinstance(nested, ast.Dict):
            if key is None:
                found.extend(v for v in nested.values if v is not None)
            elif isinstance(key, str):
                found.extend(_dict_values_for_static_key(nested, key))
            else:
                for map_key, map_val in zip(nested.keys, nested.values):
                    if (
                        map_val is not None
                        and isinstance(map_key, ast.Constant)
                        and map_key.value == key
                    ):
                        found.append(map_val)
        elif isinstance(nested, ast.Call) and _is_dict_constructor(nested.func):
            found.extend(_dict_call_values_for_key(nested, key))
        else:
            found.append(nested)
    return found


def _is_module_namespace_expr(node: ast.AST) -> bool:
    """True for module-level namespace objects we refuse to trust as identity."""

    if _is_globals_call(node):
        return True
    return isinstance(node, ast.Name) and node.id in {"__dict__", "globals", "locals", "vars"}


def _names_bound_by_statement(node: ast.AST) -> set[str]:
    """Names a module-level statement may bind, including nested suites.

    Used for conditional / compound control flow where the outcome is not
    statically established: any possible binding forces rebound.
    """

    names: set[str] = set()
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        names.add(node.name)
    elif isinstance(node, ast.ImportFrom):
        if any(alias.name == "*" for alias in node.names):
            names.add("*")
        else:
            for alias in node.names:
                names.add(alias.asname or alias.name)
    elif isinstance(node, ast.Import):
        for alias in node.names:
            if alias.asname:
                names.add(alias.asname)
            else:
                names.add(alias.name.split(".", 1)[0])
    elif isinstance(node, ast.Assign):
        for target in node.targets:
            names.update(_collect_store_names(target))
            if isinstance(target, ast.Subscript) and _is_module_namespace_expr(
                target.value
            ):
                key = _static_str(target.slice)
                if key is not None:
                    names.add(key)
                else:
                    names.add("*")
    elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
        names.add(node.target.id)
    elif isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Name):
        names.add(node.target.id)
    elif isinstance(node, ast.Delete):
        for target in node.targets:
            names.update(_collect_store_names(target))
    elif isinstance(node, (ast.For, ast.AsyncFor)):
        names.update(_collect_store_names(node.target))
        for stmt in list(node.body) + list(node.orelse):
            names.update(_names_bound_by_statement(stmt))
    elif isinstance(node, ast.While):
        for stmt in list(node.body) + list(node.orelse):
            names.update(_names_bound_by_statement(stmt))
    elif isinstance(node, (ast.With, ast.AsyncWith)):
        for item in node.items:
            if item.optional_vars is not None:
                names.update(_collect_store_names(item.optional_vars))
        for stmt in node.body:
            names.update(_names_bound_by_statement(stmt))
    elif isinstance(node, ast.Try):
        for stmt in node.body:
            names.update(_names_bound_by_statement(stmt))
        for handler in node.handlers:
            if handler.name:
                names.add(handler.name)
            for stmt in handler.body:
                names.update(_names_bound_by_statement(stmt))
        for stmt in list(node.orelse) + list(node.finalbody):
            names.update(_names_bound_by_statement(stmt))
    elif isinstance(node, ast.Match):
        for case in node.cases:
            names.update(_collect_match_pattern_names(case.pattern))
            for stmt in case.body:
                names.update(_names_bound_by_statement(stmt))
    elif isinstance(node, ast.If):
        for stmt in list(node.body) + list(node.orelse):
            names.update(_names_bound_by_statement(stmt))
    elif isinstance(node, ast.Expr):
        for child in ast.walk(node):
            if isinstance(child, ast.NamedExpr) and isinstance(child.target, ast.Name):
                names.add(child.target.id)
        if isinstance(node.value, ast.Call):
            func = node.value.func
            if isinstance(func, ast.Name) and func.id in {"exec", "eval", "compile"}:
                names.add("*")
            elif (
                isinstance(func, ast.Attribute)
                and _is_module_namespace_expr(func.value)
                and func.attr
                in {
                    "update",
                    "setdefault",
                    "pop",
                    "clear",
                    "__setitem__",
                }
            ):
                names.add("*")
    return names


def _apply_precise_binding(
    bindings: dict[str, FinalBinding],
    node: ast.AST,
    *,
    path: str,
) -> None:
    """Apply an unconditional module-level binding statement."""

    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        if node.decorator_list:
            # Decorator identity is not modeled — refuse authorizing identity.
            bindings[node.name] = FinalBinding(kind="rebound")
        else:
            bindings[node.name] = FinalBinding(
                kind="function",
                function_node=node,
            )
    elif isinstance(node, ast.ClassDef):
        bindings[node.name] = FinalBinding(kind="rebound")
    elif isinstance(node, ast.ImportFrom):
        if any(alias.name == "*" for alias in node.names):
            _mark_rebound(bindings, list(bindings))
            return
        module_name = import_module_name_from_importer(node, importer_path=path)
        for alias in node.names:
            local = alias.asname or alias.name
            if module_name is None:
                bindings[local] = FinalBinding(kind="rebound")
            else:
                bindings[local] = FinalBinding(
                    kind="import_name",
                    module_name=module_name,
                    imported_name=alias.name,
                )
    elif isinstance(node, ast.Import):
        for alias in node.names:
            if alias.asname:
                bindings[alias.asname] = FinalBinding(
                    kind="import_module",
                    module_name=alias.name,
                )
            else:
                top = alias.name.split(".", 1)[0]
                bindings[top] = FinalBinding(
                    kind="import_module",
                    module_name=top,
                )
    elif isinstance(node, ast.Assign):
        poisoned = False
        for target in node.targets:
            if isinstance(target, ast.Subscript) and _is_module_namespace_expr(
                target.value
            ):
                key = _static_str(target.slice)
                if key is None:
                    poisoned = True
                else:
                    bindings[key] = FinalBinding(kind="rebound")
            else:
                _mark_rebound(bindings, _collect_store_names(target))
        if poisoned:
            _mark_rebound(bindings, list(bindings))
    elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
        bindings[node.target.id] = FinalBinding(kind="rebound")
    elif isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Name):
        bindings[node.target.id] = FinalBinding(kind="rebound")
    elif isinstance(node, ast.Delete):
        for target in node.targets:
            _mark_rebound(bindings, _collect_store_names(target))
    elif isinstance(node, (ast.For, ast.AsyncFor)):
        _mark_rebound(bindings, _collect_store_names(node.target))
    elif isinstance(node, (ast.With, ast.AsyncWith)):
        for item in node.items:
            if item.optional_vars is not None:
                _mark_rebound(bindings, _collect_store_names(item.optional_vars))
    elif isinstance(node, ast.Try):
        for handler in node.handlers:
            if handler.name:
                bindings[handler.name] = FinalBinding(kind="rebound")
    elif isinstance(node, ast.Match):
        for case in node.cases:
            _mark_rebound(bindings, _collect_match_pattern_names(case.pattern))
    elif isinstance(node, ast.Expr):
        for child in ast.walk(node):
            if isinstance(child, ast.NamedExpr) and isinstance(child.target, ast.Name):
                bindings[child.target.id] = FinalBinding(kind="rebound")
        if isinstance(node.value, ast.Call):
            func = node.value.func
            if isinstance(func, ast.Name) and func.id in {"exec", "eval", "compile"}:
                _mark_rebound(bindings, list(bindings))
            elif (
                isinstance(func, ast.Attribute)
                and _is_module_namespace_expr(func.value)
                and func.attr
                in {
                    "update",
                    "setdefault",
                    "pop",
                    "clear",
                    "__setitem__",
                }
            ):
                _mark_rebound(bindings, list(bindings))


_COMPOUND_UNCERTAIN = (
    ast.If,
    ast.While,
    ast.For,
    ast.AsyncFor,
    ast.With,
    ast.AsyncWith,
    ast.Try,
    ast.Match,
)


def module_final_bindings(
    tree: ast.AST,
    *,
    path: str,
) -> dict[str, FinalBinding]:
    """Compute module-scope final bindings in statement order.

    Later unconditional statements win. Conditional / compound suites that may
    bind a name leave that name ``rebound`` unless a later unconditional binding
    restores precise identity (Unknown > false PASS).

    Decorated ``FunctionDef`` / ``AsyncFunctionDef`` nodes are rebound until
    decorator identity is modeled. Dynamic namespace mutations (``globals()``,
    ``locals()``, ``vars()``) likewise refuse precise identity.
    """

    bindings: dict[str, FinalBinding] = {}
    for node in getattr(tree, "body", ()):
        if isinstance(node, _COMPOUND_UNCERTAIN):
            possible = _names_bound_by_statement(node)
            if "*" in possible:
                _mark_rebound(bindings, list(bindings))
            if isinstance(
                node,
                (ast.For, ast.AsyncFor, ast.With, ast.AsyncWith, ast.Try, ast.Match),
            ):
                _apply_precise_binding(bindings, node, path=path)
            _mark_rebound(bindings, possible - {"*"})
            continue
        _apply_precise_binding(bindings, node, path=path)
    return bindings


def _final_binding_establish_index(
    tree: ast.AST,
    name: str,
) -> int | None:
    """Top-level statement index that establishes ``name``'s final binding."""

    body: Sequence[ast.stmt] = getattr(tree, "body", ())
    establish: int | None = None
    for index, node in enumerate(body):
        if isinstance(node, _COMPOUND_UNCERTAIN):
            possible = _names_bound_by_statement(node)
            if name in possible or "*" in possible:
                # Uncertain compound leaves rebound unless a later precise bind.
                establish = None
            continue
        # Mirror unconditional precise binding that can own ``name``.
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name == name:
                establish = index
        elif isinstance(node, ast.ClassDef) and node.name == name:
            establish = index
        elif isinstance(node, ast.ImportFrom):
            if any(alias.name == "*" for alias in node.names):
                establish = None
            else:
                for alias in node.names:
                    if (alias.asname or alias.name) == name:
                        establish = index
        elif isinstance(node, ast.Import):
            for alias in node.names:
                local = alias.asname or alias.name.split(".", 1)[0]
                if local == name:
                    establish = index
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Subscript) and _is_module_namespace_expr(
                    target.value
                ):
                    key = _static_str(target.slice)
                    if key is None:
                        establish = None
                    elif key == name:
                        establish = index
                elif name in _collect_store_names(target):
                    establish = index
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            if node.target.id == name:
                establish = index
        elif isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Name):
            if node.target.id == name:
                establish = index
        elif isinstance(node, ast.Delete):
            for target in node.targets:
                if name in _collect_store_names(target):
                    establish = None
        elif isinstance(node, ast.Expr):
            if isinstance(node.value, ast.Call):
                func = node.value.func
                if isinstance(func, ast.Name) and func.id in {
                    "exec",
                    "eval",
                    "compile",
                }:
                    establish = None
                elif (
                    isinstance(func, ast.Attribute)
                    and _is_module_namespace_expr(func.value)
                    and func.attr
                    in {
                        "update",
                        "setdefault",
                        "pop",
                        "clear",
                        "__setitem__",
                    }
                ):
                    establish = None
    return establish


def _is_sys_modules_expr(node: ast.AST) -> bool:
    """True for ``sys.modules`` (Name sys + Attribute modules)."""

    return (
        isinstance(node, ast.Attribute)
        and node.attr == "modules"
        and isinstance(node.value, ast.Name)
        and node.value.id == "sys"
    )


def _with_as_targets_mutated(
    body: Sequence[ast.stmt],
    bound_names: set[str],
) -> bool:
    """True when a with-as bound name is the base of an attribute/subscript store."""

    for stmt in body:
        for node in ast.walk(stmt):
            if isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Store):
                if isinstance(node.value, ast.Name) and node.value.id in bound_names:
                    return True
            if isinstance(node, ast.Subscript) and isinstance(node.ctx, ast.Store):
                if isinstance(node.value, ast.Name) and node.value.id in bound_names:
                    return True
            if isinstance(node, ast.Call):
                parts = _setattr_target_and_name(node)
                if parts is not None:
                    obj, _name = parts
                    if isinstance(obj, ast.Name) and obj.id in bound_names:
                        return True
    return False


def _module_path_for_import_name(
    module_name: str,
    *,
    available_paths: frozenset[str],
    import_roots: tuple[str, ...],
) -> str | None:
    candidates = module_candidates_in_manifest(
        module_name,
        set(available_paths),
        import_roots=import_roots,
    )
    if len(candidates) != 1:
        return None
    return candidates[0]


def _identity_from_final_binding(
    name: str,
    *,
    path: str,
    bindings_by_path: Mapping[str, Mapping[str, FinalBinding]],
    available_paths: frozenset[str],
    import_roots: tuple[str, ...],
) -> _IdentityPointsTo:
    """Fallback identity from final module bindings when env lacks ``name``.

    Unbound / non-tracked names are *bottom* (not unknown): closed-world
    severance must remain precise so ``m = other; m.write_state = ...`` does
    not spelling-poison after reassignment.
    """

    binding = bindings_by_path.get(path, {}).get(name)
    if binding is None:
        return _IdentityPointsTo.bottom()
    if binding.kind == "import_module" and binding.module_name is not None:
        module_path = _module_path_for_import_name(
            binding.module_name,
            available_paths=available_paths,
            import_roots=import_roots,
        )
        if module_path is None:
            return _IdentityPointsTo.unknown_only()
        return _IdentityPointsTo.precise(ModuleObject(module_path))
    if binding.kind == "function":
        return _IdentityPointsTo.precise(CallableObject(path, name))
    if binding.kind == "import_name":
        if binding.module_name is None or binding.imported_name is None:
            return _IdentityPointsTo.unknown_only()
        module_path = _module_path_for_import_name(
            binding.module_name,
            available_paths=available_paths,
            import_roots=import_roots,
        )
        if module_path is None:
            return _IdentityPointsTo.unknown_only()
        return _IdentityPointsTo.precise(
            CallableObject(module_path, binding.imported_name)
        )
    # rebound / unmodeled kinds: may no longer be the tracked object.
    return _IdentityPointsTo.unknown_only()


def _join_envs(
    left: dict[str, _IdentityPointsTo],
    right: dict[str, _IdentityPointsTo],
) -> dict[str, _IdentityPointsTo]:
    keys = set(left) | set(right)
    joined: dict[str, _IdentityPointsTo] = {}
    for key in keys:
        lval = left.get(key)
        rval = right.get(key)
        if lval is None:
            assert rval is not None
            joined[key] = rval.join(_IdentityPointsTo.unknown_only())
        elif rval is None:
            joined[key] = lval.join(_IdentityPointsTo.unknown_only())
        else:
            joined[key] = lval.join(rval)
    return joined


def _copy_env(env: Mapping[str, _IdentityPointsTo]) -> dict[str, _IdentityPointsTo]:
    return dict(env)


def _setattr_func_kind(
    func: ast.AST,
    *,
    setattr_aliases: frozenset[str] | None = None,
    getattr_aliases: frozenset[str] | None = None,
) -> str | None:
    """``\"setattr\"`` / ``\"__setattr__\"`` when ``func`` denotes a setattr peel."""

    aliases = setattr_aliases or frozenset({"setattr"})
    func = _peel_transparent_callee(func)
    if isinstance(func, ast.Name) and func.id in aliases:
        return "setattr"
    if isinstance(func, ast.Attribute) and func.attr in {"setattr", "__setattr__"}:
        return func.attr
    if isinstance(func, ast.Call):
        gname = _getattr_static_name(func, getattr_aliases=getattr_aliases)
        if gname == "setattr":
            return "setattr"
    return None


def _is_setattr_call(
    call: ast.Call,
    *,
    setattr_aliases: frozenset[str] | None = None,
    getattr_aliases: frozenset[str] | None = None,
) -> bool:
    """True for bare / packed / getattr / BoolOp setattr Call.func peels."""

    aliases = setattr_aliases or frozenset({"setattr"})
    func = _peel_call_func(call.func)
    if (
        _setattr_func_kind(
            func,
            setattr_aliases=aliases,
            getattr_aliases=getattr_aliases,
        )
        is not None
    ):
        return True
    # Packed ``[builtins.setattr][0]`` / ``next(iter([setattr]))`` /
    # ``(False or builtins.setattr)`` / ``{\"sa\": setattr}[\"sa\"]``.
    for cand in _shallow_packed_callee_exprs(func):
        if (
            _setattr_func_kind(
                cand,
                setattr_aliases=aliases,
                getattr_aliases=getattr_aliases,
            )
            is not None
        ):
            return True
    return False


def _shallow_packed_callee_exprs(expr: ast.AST, *, depth: int = 0) -> list[ast.AST]:
    """Lightweight packing peel for Call.func before the identity scanner exists.

    Covers NamedExpr / IfExp / BoolOp / Subscript / list|tuple|set|dict /
    BinOp ``+`` / ``*`` sequence carriers / ``.__add__`` / ``operator.concat`` /
    ``next(iter|reversed(...))`` / dict ``.values()`` so setattr / factory
    peels share one path outside the full ``_callee_candidate_exprs``
    closure (Unknown > false PASS).
    """

    expr = _peel_transparent_callee(expr)
    out: list[ast.AST] = [expr]
    if depth > 6:
        return out
    nxt = depth + 1
    if isinstance(expr, ast.IfExp):
        out.extend(_shallow_packed_callee_exprs(expr.body, depth=nxt))
        out.extend(_shallow_packed_callee_exprs(expr.orelse, depth=nxt))
    elif isinstance(expr, ast.BoolOp):
        for value in expr.values:
            out.extend(_shallow_packed_callee_exprs(value, depth=nxt))
    elif isinstance(expr, ast.BinOp) and isinstance(expr.op, (ast.Add, ast.Mult)):
        # ``([partial(...)] + [])[0]`` / ``([p] * 1)[0]`` sequence carriers.
        out.extend(_shallow_packed_callee_exprs(expr.left, depth=nxt))
        if isinstance(expr.op, ast.Add):
            out.extend(_shallow_packed_callee_exprs(expr.right, depth=nxt))
    elif isinstance(expr, (ast.List, ast.Tuple, ast.Set)):
        for elt in expr.elts:
            nested = elt.value if isinstance(elt, ast.Starred) else elt
            out.extend(_shallow_packed_callee_exprs(nested, depth=nxt))
    elif isinstance(expr, ast.Dict):
        for value in expr.values:
            if value is not None:
                out.extend(_shallow_packed_callee_exprs(value, depth=nxt))
    elif isinstance(expr, ast.Subscript):
        out.extend(_shallow_packed_callee_exprs(expr.value, depth=nxt))
    elif isinstance(expr, ast.Attribute) and expr.attr in {"__add__", "values"}:
        # ``[p].__add__([])[0]`` / ``{0: p}.values()`` carriers.
        out.extend(_shallow_packed_callee_exprs(expr.value, depth=nxt))
    elif isinstance(expr, ast.Call):
        gname = _getattr_static_name(expr)
        if gname is not None:
            out.append(expr)
            if gname in {"__call__", "__get__"} and expr.args:
                out.extend(_shallow_packed_callee_exprs(expr.args[0], depth=nxt))
            elif gname == "__add__" and expr.args:
                out.extend(_shallow_packed_callee_exprs(expr.func, depth=nxt))
                out.extend(_shallow_packed_callee_exprs(expr.args[0], depth=nxt))
        elif (
            isinstance(expr.func, ast.Name)
            and expr.func.id
            in {"next", "iter", "list", "tuple", "reversed", "concat"}
            and expr.args
        ):
            for arg in expr.args:
                nested = arg.value if isinstance(arg, ast.Starred) else arg
                out.extend(_shallow_packed_callee_exprs(nested, depth=nxt))
        elif isinstance(expr.func, ast.Attribute) and expr.func.attr in {
            "next",
            "iter",
            "list",
            "tuple",
            "reversed",
            "concat",
            "__add__",
            "values",
        } and expr.args:
            if expr.func.attr in {"__add__", "concat"}:
                out.extend(
                    _shallow_packed_callee_exprs(expr.func.value, depth=nxt)
                )
            for arg in expr.args:
                nested = arg.value if isinstance(arg, ast.Starred) else arg
                out.extend(_shallow_packed_callee_exprs(nested, depth=nxt))
        elif (
            isinstance(expr.func, ast.Attribute)
            and expr.func.attr in {"__add__", "values"}
            and not expr.args
        ):
            out.extend(_shallow_packed_callee_exprs(expr.func.value, depth=nxt))
    return out


def _is_delattr_call(call: ast.Call) -> bool:
    func = call.func
    return (isinstance(func, ast.Name) and func.id == "delattr") or (
        isinstance(func, ast.Attribute) and func.attr == "__delattr__"
    )


def _setattr_target_and_name(
    call: ast.Call,
    *,
    setattr_aliases: frozenset[str] | None = None,
    getattr_aliases: frozenset[str] | None = None,
) -> tuple[ast.AST, ast.AST] | None:
    """Return (target_obj, name_expr) for setattr-shaped calls."""

    aliases = setattr_aliases or frozenset({"setattr"})
    if (
        not _is_setattr_call(
            call,
            setattr_aliases=aliases,
            getattr_aliases=getattr_aliases,
        )
        or len(call.args) < 2
    ):
        return None
    func = _peel_call_func(call.func)
    kind = _setattr_func_kind(
        func, setattr_aliases=aliases, getattr_aliases=getattr_aliases
    )
    if kind is None:
        for cand in _shallow_packed_callee_exprs(func):
            kind = _setattr_func_kind(
                cand, setattr_aliases=aliases, getattr_aliases=getattr_aliases
            )
            if kind is not None:
                func = cand
                break
    if kind == "setattr":
        return (call.args[0], call.args[1])
    if isinstance(func, ast.Attribute) and func.attr == "__setattr__":
        if isinstance(func.value, ast.Name) and func.value.id == "object":
            if len(call.args) < 3:
                return None
            return (call.args[0], call.args[1])
        # obj.__setattr__(name, value)
        return (func.value, call.args[0])
    return None


def _delattr_target_and_name(
    call: ast.Call,
) -> tuple[ast.AST, ast.AST] | None:
    """Return (target_obj, name_expr) for delattr-shaped calls."""

    if not _is_delattr_call(call) or len(call.args) < 1:
        return None
    func = call.func
    if isinstance(func, ast.Name) and func.id == "delattr":
        if len(call.args) < 2:
            return None
        return (call.args[0], call.args[1])
    if isinstance(func, ast.Attribute) and func.attr == "__delattr__":
        if isinstance(func.value, ast.Name) and func.value.id == "object":
            if len(call.args) < 2:
                return None
            return (call.args[0], call.args[1])
        return (func.value, call.args[0])
    return None


def _unwrap_await(expr: ast.AST) -> ast.AST:
    """Peel ``Await`` wrappers so async helper calls remain visible."""

    while isinstance(expr, ast.Await):
        expr = expr.value
    return expr


def _class_method_by_name(
    class_node: ast.ClassDef,
    method_name: str,
) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    for child in class_node.body:
        if (
            isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
            and child.name == method_name
        ):
            return child
    return None


def _method_has_decorator(
    method: ast.FunctionDef | ast.AsyncFunctionDef,
    names: frozenset[str],
) -> bool:
    for deco in method.decorator_list:
        if isinstance(deco, ast.Name) and deco.id in names:
            return True
        if isinstance(deco, ast.Attribute) and deco.attr in names:
            return True
    return False


_EXEC_EVAL_COMPILE_NAMES = frozenset({"exec", "eval", "compile"})
_TYPES_NEW_CLASS_NAME = "new_class"
_TYPE_BUILTIN_NAME = "type"
_OPERATOR_PROJECTION_NAMES = frozenset(
    {
        "getitem",
        "setitem",
        "itemgetter",
        "attrgetter",
        "methodcaller",
        "attrsetter",
        "call",
        "or_",
        "ior",
        "iadd",
        "iconcat",
        "concat",
        "add",
        "copy",
        "deepcopy",
        "chain",
        "islice",
        "chain_from_iterable",
        "from_iterable",
        "starmap",
        "compress",
        "filterfalse",
        "dropwhile",
        "takewhile",
        "tee",
        "zip_longest",
        "cycle",
        "repeat",
        "permutations",
        "combinations",
        "combinations_with_replacement",
        "product",
        "groupby",
        "accumulate",
        "pairwise",
        "batched",
        # Builtin / functools applicators (``from builtins import sorted as s``,
        # ``from functools import reduce as rd``) share operator_projection peels.
        "sorted",
        "max",
        "min",
        "reduce",
    }
)
# Shared Call peels for packed/projected callees (identity + PE parity).
_CALLEE_VIEW_ATTRS = frozenset(
    {
        "get",
        "pop",
        "popitem",
        "setdefault",
        "__getitem__",
        "values",
        "keys",
        "items",
        "copy",
    }
)
# Container-mutating methods that add packed identities to a Name-bound pack.
_PACK_ADD_METHODS = frozenset(
    {"append", "extend", "insert", "add", "appendleft", "extendleft"}
)
_CALLEE_ADAPTER_NAMES = frozenset(
    {
        "list",
        "tuple",
        "set",
        "frozenset",
        "sorted",
        "reversed",
        "iter",
        "next",
        "map",
        "filter",
        "zip",
        "enumerate",
        "MappingProxyType",
        "chain",
        "islice",
        "copy",
        "deepcopy",
        "deque",
        "reduce",
        *_ITERTOOLS_ADAPTER_NAMES,
    }
)
# Container-pack slot for non-constant dict keys (``{Mut: 1}``) so ``.keys()``
# iteration and unpack seeds observe class keys without aliasing value slots.
_KEYS_SLOT: object = ("<keys>",)


def _attrsetter_static_name(
    call: ast.Call,
    *,
    projection_aliases: Mapping[str, str] | None = None,
) -> str | None:
    """Return the static attribute name for ``operator.attrsetter("x")``."""

    aliases = projection_aliases or {}
    func = _peel_call_func(call.func)
    if isinstance(func, ast.Name) and call.args:
        if func.id == "attrsetter" or aliases.get(func.id) == "attrsetter":
            return _static_str(call.args[0])
    if (
        isinstance(func, ast.Attribute)
        and func.attr == "attrsetter"
        and call.args
    ):
        return _static_str(call.args[0])
    return None


def _is_projection_factory_expr(
    expr: ast.AST,
    factory: str,
    *,
    projection_aliases: Mapping[str, str] | None = None,
    getattr_aliases: frozenset[str] | None = None,
) -> bool:
    """True when ``expr`` peels to a bare ``factory`` applicator (not yet applied).

    Shared for packed / BoolOp / IfExp / getattr products:
    ``[getattr(operator,"itemgetter")][0]`` / ``(0 or attrgetter)`` /
    ``next(iter([operator.setitem]))`` (Unknown > false PASS).
    """

    aliases = projection_aliases or {}
    for cand in _shallow_packed_callee_exprs(expr):
        cand = _peel_transparent_callee(cand)
        if isinstance(cand, ast.Name) and (
            cand.id == factory or aliases.get(cand.id) == factory
        ):
            return True
        if isinstance(cand, ast.Attribute) and (
            cand.attr == factory
            or _canonical_projection_name(cand.attr) == factory
        ):
            return True
        if isinstance(cand, ast.Call):
            gname = _getattr_static_name(cand, getattr_aliases=getattr_aliases)
            if gname == factory or _canonical_projection_name(gname) == factory:
                return True
    return False


def _methodcaller_static_name(
    call: ast.Call,
    *,
    projection_aliases: Mapping[str, str] | None = None,
    getattr_aliases: frozenset[str] | None = None,
) -> str | None:
    """Return the static method name for ``operator.methodcaller("x")``.

    Also ``getattr(operator, \"methodcaller\")(\"x\")`` and packed /
    BoolOp / IfExp factory peels so getattr packing shares the Attribute
    peel (Unknown > false PASS).
    """

    aliases = projection_aliases or {}
    func = _peel_transparent_callee(call.func)
    if isinstance(func, ast.Name) and call.args:
        if func.id == "methodcaller" or aliases.get(func.id) == "methodcaller":
            return _static_str(call.args[0])
    if (
        isinstance(func, ast.Attribute)
        and func.attr == "methodcaller"
        and call.args
    ):
        return _static_str(call.args[0])
    if isinstance(func, ast.Call) and call.args:
        gname = _getattr_static_name(func, getattr_aliases=getattr_aliases)
        if gname == "methodcaller":
            return _static_str(call.args[0])
    # Packed ``[operator.methodcaller][0]("x")`` / ``(0 or methodcaller)("x")``.
    if call.args and _is_projection_factory_expr(
        func,
        "methodcaller",
        projection_aliases=aliases,
        getattr_aliases=getattr_aliases,
    ):
        return _static_str(call.args[0])
    return None


def _itemgetter_static_key(
    call: ast.Call,
    *,
    projection_aliases: Mapping[str, str] | None = None,
    getattr_aliases: frozenset[str] | None = None,
) -> str | None:
    """Return the static key for ``operator.itemgetter("x")`` / aliases.

    Int keys are stringified so ``itemgetter(0)([oc])`` packs share the same
    peel path as string keys. Also ``getattr(operator, \"itemgetter\")(\"x\")``
    and packed / BoolOp / IfExp / ``next(iter([...]))`` factory peels
    (Unknown > false PASS).
    """

    aliases = projection_aliases or {}
    func = _peel_transparent_callee(call.func)
    key_node: ast.AST | None = None
    if isinstance(func, ast.Name) and call.args:
        if func.id == "itemgetter" or aliases.get(func.id) == "itemgetter":
            key_node = call.args[0]
    elif isinstance(func, ast.Attribute) and func.attr == "itemgetter" and call.args:
        key_node = call.args[0]
    elif isinstance(func, ast.Call) and call.args:
        gname = _getattr_static_name(func, getattr_aliases=getattr_aliases)
        if gname == "itemgetter":
            key_node = call.args[0]
    elif call.args and _is_projection_factory_expr(
        func,
        "itemgetter",
        projection_aliases=aliases,
        getattr_aliases=getattr_aliases,
    ):
        # ``[getattr(operator,"itemgetter")][0]("x")`` /
        # ``(0 or getattr(...))("x")`` / ``next(iter([getattr(...)]))("x")``.
        key_node = call.args[0]
    if key_node is None:
        return None
    key = _static_key(key_node)
    if key is None:
        return None
    if isinstance(key, str):
        return key
    if isinstance(key, (int, float, bool)):
        return str(key)
    return None


def _attrgetter_static_name(
    call: ast.Call,
    *,
    projection_aliases: Mapping[str, str] | None = None,
    getattr_aliases: frozenset[str] | None = None,
) -> str | None:
    """Return the static attribute name for ``operator.attrgetter("x")`` / aliases.

    Also ``getattr(operator, \"attrgetter\")(\"x\")`` and packed / BoolOp /
    IfExp factory peels (Unknown > false PASS).
    """

    aliases = projection_aliases or {}
    func = _peel_transparent_callee(call.func)
    if isinstance(func, ast.Name) and call.args:
        if func.id == "attrgetter" or aliases.get(func.id) == "attrgetter":
            return _static_str(call.args[0])
    if isinstance(func, ast.Attribute) and func.attr == "attrgetter" and call.args:
        return _static_str(call.args[0])
    if isinstance(func, ast.Call) and call.args:
        gname = _getattr_static_name(func, getattr_aliases=getattr_aliases)
        if gname == "attrgetter":
            return _static_str(call.args[0])
    if call.args and _is_projection_factory_expr(
        func,
        "attrgetter",
        projection_aliases=aliases,
        getattr_aliases=getattr_aliases,
    ):
        return _static_str(call.args[0])
    return None


def _projection_factory_name(
    call: ast.Call,
    *,
    projection_aliases: Mapping[str, str] | None = None,
    getattr_aliases: frozenset[str] | None = None,
) -> str | None:
    """Canonical operator projection name for a factory Call, if any.

    Also ``getattr(operator, \"setitem\")`` / ``getattr(copy, \"copy\")`` /
    ``operator.__ior__`` dunder aliases / packed ``[operator.setitem][0]``
    so getattr and packing peels share the Attribute path
    (Unknown > false PASS).
    """

    aliases = projection_aliases or {}
    func = _peel_transparent_callee(call.func)

    def _name_of(node: ast.AST) -> str | None:
        node = _peel_transparent_callee(node)
        if isinstance(node, ast.Name):
            if node.id in _OPERATOR_PROJECTION_NAMES:
                return node.id
            aliased = aliases.get(node.id)
            if aliased is not None:
                return aliased
            return _canonical_projection_name(node.id)
        if isinstance(node, ast.Attribute):
            if node.attr in _OPERATOR_PROJECTION_NAMES:
                return node.attr
            return _canonical_projection_name(node.attr)
        if isinstance(node, ast.Call):
            gname = _getattr_static_name(node, getattr_aliases=getattr_aliases)
            if gname in _OPERATOR_PROJECTION_NAMES:
                return gname
            return _canonical_projection_name(gname)
        return None

    direct = _name_of(func)
    if direct is not None and (
        direct in _OPERATOR_PROJECTION_NAMES
        or direct in _INPLACE_MERGE_METHODS
        or direct in _MAPPING_MERGE_METHODS
    ):
        return direct if direct in _OPERATOR_PROJECTION_NAMES else _canonical_projection_name(direct) or direct
    # Packed ``[operator.setitem][0]`` / ``(0 or operator.ior)`` /
    # ``[getattr(operator,"__ior__")][0]``.
    for cand in _shallow_packed_callee_exprs(func):
        name = _name_of(cand)
        if name is None:
            continue
        canon = _canonical_projection_name(name) or name
        if (
            canon in _OPERATOR_PROJECTION_NAMES
            or canon in _INPLACE_MERGE_FUNCS
            or name in _INPLACE_MERGE_METHODS
        ):
            return canon if canon in _OPERATOR_PROJECTION_NAMES | _INPLACE_MERGE_FUNCS else name
    return None


def _is_partial_factory(
    call: ast.Call,
    *,
    partial_aliases: frozenset[str] | None = None,
    getattr_aliases: frozenset[str] | None = None,
) -> bool:
    """True for ``functools.partial(...)`` / ``partial(...)`` / aliases.

    Also ``getattr(functools, \"partial\")(...)`` so getattr packing cannot
    omit partial construction observation (Unknown > false PASS). Peels
    BoolOp / IfExp / packed factories ``(0 or partial)(...)`` /
    ``[partial][0](...)`` / ``next(iter([partial]))(...)`` on the shared
    shallow packing path.
    """

    aliases = partial_aliases or frozenset({"partial"})
    for cand in _shallow_packed_callee_exprs(call.func):
        cand = _peel_call_func(cand)
        if isinstance(cand, ast.Name) and cand.id in aliases:
            return True
        if isinstance(cand, ast.Attribute) and cand.attr == "partial":
            return True
        if isinstance(cand, ast.Call):
            if _getattr_static_name(cand, getattr_aliases=getattr_aliases) == "partial":
                return True
    return False


def _nullcontext_enter_arg(
    expr: ast.AST,
    *,
    getattr_aliases: frozenset[str] | None = None,
) -> ast.AST | None:
    """Enter argument of ``nullcontext(x)`` / ``contextlib.nullcontext(x)``.

    Shared peel for With as-target seeding: ``__enter__`` returns the argument
    (Unknown > false PASS). Covers Name / Attribute / getattr factories and
    BoolOp / IfExp / packed Call.func forms on the shallow packing path.
    """

    peeled = _peel_call_func(expr)
    if not isinstance(peeled, ast.Call) or not peeled.args:
        return None
    for cand in _shallow_packed_callee_exprs(peeled.func):
        cand = _peel_call_func(cand)
        is_nc = (
            (isinstance(cand, ast.Name) and cand.id == "nullcontext")
            or (isinstance(cand, ast.Attribute) and cand.attr == "nullcontext")
            or (
                isinstance(cand, ast.Call)
                and _getattr_static_name(
                    cand, getattr_aliases=getattr_aliases
                )
                == "nullcontext"
            )
        )
        if is_nc:
            return peeled.args[0]
    return None


def _name_is_operator_call_alias(
    name: str, *, projection_aliases: Mapping[str, str]
) -> bool:
    return name == "call" or projection_aliases.get(name) == "call"


def _expr_is_operator_call_receiver(
    expr: ast.AST,
    *,
    projection_aliases: Mapping[str, str],
    getattr_aliases: frozenset[str] | None = None,
    partial_aliases: frozenset[str] | None = None,
    adapter_aliases: frozenset[str] | None = None,
    container_packs: Mapping[str, Mapping[object, tuple[str, ...]]] | None = None,
    factory_products: Mapping[str, tuple[str, str | None]] | None = None,
    dict_view_products: Mapping[str, str] | None = None,
) -> bool:
    """True when ``expr`` peels to ``operator.call`` / renamed ``call``."""

    aliases = projection_aliases
    peeled = _peel_call_func(expr)
    if isinstance(peeled, ast.Name) and _name_is_operator_call_alias(
        peeled.id, projection_aliases=aliases
    ):
        return True
    if isinstance(peeled, ast.Attribute) and peeled.attr == "call":
        return True
    if isinstance(peeled, ast.Call):
        if _getattr_static_name(peeled, getattr_aliases=getattr_aliases) == "call":
            return True
    for name in _names_packed_as_callee(
        expr,
        projection_aliases=aliases,
        getattr_aliases=getattr_aliases,
        partial_aliases=partial_aliases,
        adapter_aliases=adapter_aliases,
        container_packs=container_packs,
        factory_products=factory_products,
        dict_view_products=dict_view_products,
    ):
        if _name_is_operator_call_alias(name, projection_aliases=aliases):
            return True
    return False


def _is_operator_call_factory(
    call: ast.Call,
    *,
    projection_aliases: Mapping[str, str] | None = None,
    getattr_aliases: frozenset[str] | None = None,
    partial_aliases: frozenset[str] | None = None,
    adapter_aliases: frozenset[str] | None = None,
    container_packs: Mapping[str, Mapping[object, tuple[str, ...]]] | None = None,
    factory_products: Mapping[str, tuple[str, str | None]] | None = None,
    dict_view_products: Mapping[str, str] | None = None,
) -> bool:
    """True for ``operator.call(...)`` / renamed ``call`` / packed projections.

    Peels NamedExpr so ``(oc := operator.call)(...)`` and Name aliases of
    ``call`` (``from operator import call as oc``) are recognized before any
    bare-Name short-circuit. Also peels container / ``next(iter)`` / subscript
    packs so ``[oc][0](exec, …)`` / ``next(iter([oc]))(…)`` cannot authorize
    beside a trusted write. Covers ``oc.__call__`` / ``getattr(oc, \"__call__\")``
    / ``operator.call.__call__`` (Unknown > false PASS).
    """

    aliases = projection_aliases or {}
    func = _peel_call_func(call.func)
    if isinstance(func, ast.Name):
        if _name_is_operator_call_alias(func.id, projection_aliases=aliases):
            return True
    elif isinstance(func, ast.Attribute):
        if func.attr == "call":
            return True
        # ``oc.__call__(...)`` / ``operator.call.__call__(...)`` /
        # ``rest["o"].__call__(...)`` via Name-bound packs.
        if func.attr == "__call__" and _expr_is_operator_call_receiver(
            func.value,
            projection_aliases=aliases,
            getattr_aliases=getattr_aliases,
            partial_aliases=partial_aliases,
            adapter_aliases=adapter_aliases,
            container_packs=container_packs,
            factory_products=factory_products,
            dict_view_products=dict_view_products,
        ):
            return True
    elif isinstance(func, ast.Call):
        # ``getattr(operator, "call")`` / renamed getattr.
        gname = _getattr_static_name(func, getattr_aliases=getattr_aliases)
        if gname == "call":
            return True
        # ``getattr(oc, "__call__")(...)``.
        if gname == "__call__" and func.args and _expr_is_operator_call_receiver(
            func.args[0],
            projection_aliases=aliases,
            getattr_aliases=getattr_aliases,
            partial_aliases=partial_aliases,
            adapter_aliases=adapter_aliases,
            container_packs=container_packs,
            factory_products=factory_products,
            dict_view_products=dict_view_products,
        ):
            return True
    # Shared packing peel: ``[oc][0]`` / ``next(iter([oc]))`` / walrus packs /
    # Name-bound ``ig([oc])`` factory products.
    for name in _names_packed_as_callee(
        call.func,
        projection_aliases=aliases,
        getattr_aliases=getattr_aliases,
        partial_aliases=partial_aliases,
        adapter_aliases=adapter_aliases,
        container_packs=container_packs,
        factory_products=factory_products,
        dict_view_products=dict_view_products,
    ):
        if _name_is_operator_call_alias(name, projection_aliases=aliases):
            return True
    return False


def _methodcaller_call_bound_args(
    call: ast.Call,
    *,
    projection_aliases: Mapping[str, str] | None = None,
) -> list[ast.AST] | None:
    """Bound args of ``methodcaller("__call__", *bound)(receiver)``, if any."""

    func = _peel_call_func(call.func)
    if not isinstance(func, ast.Call):
        return None
    if _methodcaller_static_name(func, projection_aliases=projection_aliases) != "__call__":
        return None
    return list(func.args[1:])


def _receiver_looks_like_type_builtin(
    recv: ast.AST,
    *,
    type_aliases: frozenset[str] | None = None,
) -> bool:
    """True for ``type`` / ``object`` / ``object.__class__`` / ``T = type`` receivers."""

    recv = _peel_call_func(recv)
    if isinstance(recv, ast.Name) and (
        recv.id in {_TYPE_BUILTIN_NAME, "object"}
        or (type_aliases is not None and recv.id in type_aliases)
    ):
        return True
    if isinstance(recv, ast.Attribute) and recv.attr in {
        "__class__",
        _TYPE_BUILTIN_NAME,
    }:
        return True
    return False


def _type_protocol_attr_from_value(
    value: ast.AST,
    *,
    getattr_aliases: frozenset[str] | None = None,
    protocol_products: Mapping[str, str] | None = None,
    type_aliases: frozenset[str] | None = None,
) -> str | None:
    """``type.__new__`` / ``getattr(type, "__call__")`` → protocol attr name.

    ``X.__call__`` / ``getattr(X, "__call__")`` where ``X`` already is a type
    protocol product (``tc = type.__call__``; ``type.__call__.__call__``) keeps
    X's protocol: calling the wrapper's ``__call__`` is calling the wrapper
    (Unknown > false PASS).
    """

    products = protocol_products or {}
    value = _peel_call_func(value)
    if isinstance(value, ast.Name):
        return products.get(value.id)
    if isinstance(value, ast.Attribute) and value.attr in {"__new__", "__call__"}:
        if _receiver_looks_like_type_builtin(value.value, type_aliases=type_aliases):
            return value.attr
        if value.attr == "__call__":
            return _type_protocol_attr_from_value(
                value.value,
                getattr_aliases=getattr_aliases,
                protocol_products=products,
                type_aliases=type_aliases,
            )
        return None
    if isinstance(value, ast.Call):
        attr = _getattr_static_name(value, getattr_aliases=getattr_aliases)
        if attr in {"__new__", "__call__"} and value.args:
            if _receiver_looks_like_type_builtin(
                value.args[0], type_aliases=type_aliases
            ):
                return attr
            if attr == "__call__":
                return _type_protocol_attr_from_value(
                    value.args[0],
                    getattr_aliases=getattr_aliases,
                    protocol_products=products,
                    type_aliases=type_aliases,
                )
    return None


def _peel_call_func(func: ast.AST) -> ast.AST:
    """Unwrap NamedExpr / trivial Await layers from a Call.func expression."""

    func = _unwrap_await(func)
    while isinstance(func, ast.NamedExpr):
        func = _unwrap_await(func.value)
    return func


def _is_slice_factory_expr(
    expr: ast.AST,
    *,
    slice_aliases: frozenset[str] | None = None,
    getattr_aliases: frozenset[str] | None = None,
) -> bool:
    """True when ``expr`` denotes the ``slice`` constructor (not yet applied).

    Covers ``slice`` / ``builtins.slice`` / ``getattr(builtins, \"slice\")`` /
    Name aliases / packed ``[slice][0]`` / BoolOp / IfExp peels
    (Unknown > false PASS).
    """

    aliases = slice_aliases or frozenset({"slice"})
    for cand in _shallow_packed_callee_exprs(expr):
        cand = _peel_transparent_callee(cand)
        if isinstance(cand, ast.Name) and cand.id in aliases:
            return True
        if isinstance(cand, ast.Attribute) and cand.attr == "slice":
            return True
        if isinstance(cand, ast.Call):
            gname = _getattr_static_name(cand, getattr_aliases=getattr_aliases)
            if gname == "slice":
                return True
    return False


def _is_sequence_slice_key(
    key: ast.AST,
    *,
    slice_aliases: frozenset[str] | None = None,
    getattr_aliases: frozenset[str] | None = None,
) -> bool:
    """True when a subscript/getitem key is a packing-transparent sequence slice.

    Covers syntax ``ast.Slice``, ``slice(...)`` / ``builtins.slice(...)`` /
    ``getattr(builtins, \"slice\")(...)``, Name-bound slice products, and
    packed / BoolOp / IfExp factory applies (Unknown > false PASS).
    """

    aliases = slice_aliases or frozenset({"slice"})
    key = _peel_call_func(key)
    if isinstance(key, ast.Slice):
        return True
    if isinstance(key, ast.Name) and key.id in aliases:
        return True
    if isinstance(key, ast.Call):
        func = _peel_call_func(key.func)
        if _is_slice_factory_expr(
            func,
            slice_aliases=aliases,
            getattr_aliases=getattr_aliases,
        ):
            return True
        # ``getattr(builtins, "slice")(0, 1)`` — factory is the Call itself.
        if _getattr_static_name(key, getattr_aliases=getattr_aliases) == "slice":
            return False
        if isinstance(func, ast.Call) and (
            _getattr_static_name(func, getattr_aliases=getattr_aliases) == "slice"
        ):
            return True
    return False


def _peel_sequence_slice_layers(
    expr: ast.AST,
    *,
    slice_aliases: frozenset[str] | None = None,
    getattr_aliases: frozenset[str] | None = None,
) -> ast.AST:
    """Peel packing-transparent sequence slices from a carrier.

    ``xs[:]`` / ``xs[:1]`` / ``xs[0:1]`` / ``xs[::]`` / ``xs[slice(...)]`` /
    ``xs[s]`` (Name-bound slice) preserve the packed element lattice for
    later ``[0]`` / ``pop`` peels (Unknown > false PASS). Slice-then-index
    packing must share the bare-subscript path.
    """

    node = _peel_call_func(expr)
    while isinstance(node, ast.Subscript) and _is_sequence_slice_key(
        node.slice,
        slice_aliases=slice_aliases,
        getattr_aliases=getattr_aliases,
    ):
        node = _peel_call_func(node.value)
    return node


def _canonical_projection_name(name: str | None) -> str | None:
    """Normalize dunder Attribute spellings onto operator projection names."""

    if name is None:
        return None
    return _PROJECTION_DUNDER_ALIASES.get(name, name)


def _iter_boolop_ifexp_arms(expr: ast.AST) -> list[ast.AST]:
    """Flatten BoolOp / IfExp / NamedExpr wrappers into candidate arms."""

    node = _peel_call_func(expr)
    if isinstance(node, ast.IfExp):
        return [
            *_iter_boolop_ifexp_arms(node.body),
            *_iter_boolop_ifexp_arms(node.orelse),
        ]
    if isinstance(node, ast.BoolOp):
        out: list[ast.AST] = []
        for value in node.values:
            out.extend(_iter_boolop_ifexp_arms(value))
        return out
    return [node]


def _peel_transparent_callee(func: ast.AST) -> ast.AST:
    """Peel NamedExpr and trailing transparent ``__call__`` callee layers.

    ``X.__call__`` / ``getattr(X, "__call__")`` denote ``X`` itself for Call
    observation and view detection (Unknown > false PASS). Does not erase the
    ``__call__`` marker used by name-level peels / type-protocol products.
    """

    func = _peel_call_func(func)
    while True:
        if isinstance(func, ast.Attribute) and func.attr == "__call__":
            func = _peel_call_func(func.value)
            continue
        if isinstance(func, ast.Call):
            attr = _getattr_static_name(func)
            if attr == "__call__" and func.args:
                func = _peel_call_func(func.args[0])
                continue
        break
    return func


def _getattr_static_name(
    call: ast.Call,
    *,
    getattr_aliases: frozenset[str] | None = None,
) -> str | None:
    """Return the static attribute name for ``getattr(obj, "x")`` / aliases.

    Also accepts ``builtins.getattr`` / ``x.getattr`` Attribute forms and
    BoolOp / IfExp / packed getattr factories (``(0 or getattr)(obj, "x")`` /
    ``(getattr if True else None)(obj, "x")``) so renamed / conditional
    module projections cannot skip protocol peels (Unknown > false PASS).
    """

    aliases = getattr_aliases or frozenset({"getattr"})
    if len(call.args) < 2 or call.keywords:
        return None
    for cand in _shallow_packed_callee_exprs(call.func):
        cand = _peel_call_func(cand)
        is_getattr = (
            isinstance(cand, ast.Name) and cand.id in aliases
        ) or (isinstance(cand, ast.Attribute) and cand.attr == "getattr")
        if is_getattr:
            return _static_str(call.args[1])
    return None


def _peel_getattr_attr(
    expr: ast.AST,
    *,
    getattr_aliases: frozenset[str] | None = None,
) -> tuple[ast.AST, str] | None:
    """``obj.attr`` / ``getattr(obj, "attr")`` → ``(obj, attr)`` when static."""

    node = _peel_call_func(expr)
    if isinstance(node, ast.Attribute):
        return node.value, node.attr
    if isinstance(node, ast.Call):
        name = _getattr_static_name(node, getattr_aliases=getattr_aliases)
        if name is not None and node.args:
            return node.args[0], name
    return None


def _itertools_adapter_name(
    func: ast.AST,
    *,
    projection_aliases: Mapping[str, str] | None = None,
    getattr_aliases: frozenset[str] | None = None,
) -> str | None:
    """Shared peel for itertools / operator-projection adapter Call.func forms.

    Covers ``itertools.chain`` / ``chain.from_iterable`` / Name aliases /
    ``getattr(itertools, \"chain\")`` / ``from itertools import starmap as sm``.
    ``from_iterable`` normalizes to ``chain_from_iterable``.
    """

    aliases = projection_aliases or {}
    func = _peel_transparent_callee(func)
    name: str | None = None
    if isinstance(func, ast.Name):
        name = aliases.get(func.id, func.id)
    elif isinstance(func, ast.Attribute):
        # ``itertools.chain.from_iterable`` — attr is from_iterable.
        if func.attr == "from_iterable":
            recv = _peel_call_func(func.value)
            if isinstance(recv, ast.Attribute) and recv.attr == "chain":
                name = "chain_from_iterable"
            elif isinstance(recv, ast.Name) and aliases.get(recv.id, recv.id) == "chain":
                name = "chain_from_iterable"
            else:
                name = "chain_from_iterable"
        else:
            name = func.attr
    elif isinstance(func, ast.Call):
        gname = _getattr_static_name(func, getattr_aliases=getattr_aliases)
        if gname is not None:
            name = gname
    if name == "from_iterable":
        name = "chain_from_iterable"
    if name in _ITERTOOLS_ADAPTER_NAMES or name in {
        "reduce",
        "starmap",
    }:
        return name
    return None


def _dict_values_for_static_key(dict_node: ast.Dict, key: str) -> list[ast.AST]:
    """Return Dict values whose static key matches ``key``."""

    matched: list[ast.AST] = []
    for map_key, map_value in zip(dict_node.keys, dict_node.values):
        if map_value is None or map_key is None:
            continue
        if isinstance(map_key, ast.Constant) and map_key.value == key:
            matched.append(map_value)
    return matched


def _assign_target_has_attr_or_subscript(target: ast.AST) -> bool:
    """True when a for/comp/assign target stores through Attribute or Subscript."""

    if isinstance(target, (ast.Attribute, ast.Subscript)):
        return True
    if isinstance(target, ast.Starred):
        return _assign_target_has_attr_or_subscript(target.value)
    if isinstance(target, (ast.Tuple, ast.List)):
        return any(_assign_target_has_attr_or_subscript(elt) for elt in target.elts)
    return False


def _match_pattern_attribute_targets(pattern: ast.AST) -> list[ast.Attribute]:
    """Attribute MatchValue nodes that may store export identity (fail-closed)."""

    found: list[ast.Attribute] = []

    def _walk(pat: ast.AST) -> None:
        if isinstance(pat, ast.MatchValue) and isinstance(pat.value, ast.Attribute):
            found.append(pat.value)
            return
        if isinstance(pat, ast.MatchAs):
            if pat.pattern is not None:
                _walk(pat.pattern)
            return
        if isinstance(pat, ast.MatchOr):
            for alt in pat.patterns:
                _walk(alt)
            return
        if isinstance(pat, ast.MatchSequence):
            for sub in pat.patterns:
                _walk(sub)
            return
        if isinstance(pat, ast.MatchMapping):
            for sub in pat.patterns:
                _walk(sub)
            return
        if isinstance(pat, ast.MatchClass):
            for sub in pat.patterns:
                _walk(sub)
            for sub in pat.kwd_patterns:
                _walk(sub)

    _walk(pattern)
    return found


_DICT_VIEW_DEFAULTING = frozenset({"get", "setdefault", "pop"})


def _dict_view_applied_parts(
    view: str, args: Sequence[ast.AST]
) -> tuple[list[ast.AST], list[str]]:
    """Expressions / static keys packed by applying a dict view product.

    ``view`` is ``dict.get`` / ``dict.setdefault`` / ``dict.pop`` /
    ``dict.__getitem__`` (unbound: mapping first) or ``get`` / ``setdefault`` /
    ``pop`` / ``__getitem__`` (bound). Shared by name peels, class products and
    the Call.func follow so views cannot diverge (Unknown > false PASS).
    """

    exprs: list[ast.AST] = []
    keys: list[str] = []
    if view.startswith("dict."):
        base = view[len("dict.") :]
        remaining = list(args)
        if remaining:
            exprs.append(remaining.pop(0))
    else:
        base = view
        remaining = list(args)
    if remaining:
        key = _static_str(remaining[0])
        if key is not None:
            keys.append(key)
        else:
            exprs.append(remaining[0])
    if base in _DICT_VIEW_DEFAULTING and len(remaining) >= 2:
        exprs.append(remaining[1])
    return exprs, keys


def _lambdas_packed_as_callee(expr: ast.AST) -> list[ast.Lambda]:
    """Lambdas reachable as a packed/projected callee expression.

    Covers ``[lambda: poison()][0]``, ``(lambda: poison() if f else lambda: 0)``,
    BoolOp/Dict packing, and walrus-bound lambdas' RHS. Does not descend into
    Call/Lambda defaults (those execute via ``_eval_expr`` / default-to-call).
    """

    expr = _unwrap_await(expr)
    if isinstance(expr, ast.NamedExpr):
        return _lambdas_packed_as_callee(expr.value)
    if isinstance(expr, ast.Lambda):
        return [expr]
    if isinstance(expr, (ast.List, ast.Tuple, ast.Set)):
        found: list[ast.Lambda] = []
        for elt in expr.elts:
            nested = elt.value if isinstance(elt, ast.Starred) else elt
            found.extend(_lambdas_packed_as_callee(nested))
        return found
    if isinstance(expr, ast.Dict):
        found = []
        for value in expr.values:
            if value is not None:
                found.extend(_lambdas_packed_as_callee(value))
        return found
    if isinstance(expr, ast.IfExp):
        return _lambdas_packed_as_callee(expr.body) + _lambdas_packed_as_callee(
            expr.orelse
        )
    if isinstance(expr, ast.BoolOp):
        found = []
        for value in expr.values:
            found.extend(_lambdas_packed_as_callee(value))
        return found
    if isinstance(expr, ast.Subscript):
        return _lambdas_packed_as_callee(expr.value)
    return []


def _names_packed_as_callee(
    expr: ast.AST,
    *,
    projection_aliases: Mapping[str, str] | None = None,
    getattr_aliases: frozenset[str] | None = None,
    partial_aliases: frozenset[str] | None = None,
    adapter_aliases: frozenset[str] | None = None,
    container_packs: Mapping[str, Mapping[object, tuple[str, ...]]] | None = None,
    factory_products: Mapping[str, tuple[str, str | None]] | None = None,
    dict_view_products: Mapping[str, str] | None = None,
    dict_ctor_aliases: frozenset[str] | None = None,
) -> list[str]:
    """Name ids reachable as a packed/projected callee expression.

    Shared peel for Call.func forms (NamedExpr/IfExp/BoolOp/Subscript/containers)
    and Call peels (``.get``/``.pop``/``next(iter)``/``getattr``/``attrgetter``/
    ``itemgetter``/``getitem``/``methodcaller``/``operator.call``/``partial``).
    Used to observe ``(Mut if True else int)()`` / ``{\"e\": exec}.get(\"e\")(...)``
    / ``[getattr(builtins, \"exec\")][0](...)`` / Name-bound ``d[\"p\"]`` /
    ``dict(p=Proxy)[\"p\"]`` / ``D=dict; D(...)`` / ``{}|{\"e\": exec}``
    (Unknown > false PASS).
    """

    aliases = projection_aliases or {}
    g_aliases = getattr_aliases or frozenset({"getattr"})
    p_aliases = partial_aliases or frozenset({"partial"})
    a_aliases = adapter_aliases or frozenset()
    c_packs = container_packs or {}
    f_products = factory_products or {}
    d_views = dict_view_products or {}
    d_ctors = dict_ctor_aliases or frozenset()

    def _peel(node: ast.AST) -> list[str]:
        node = _unwrap_await(node)
        if isinstance(node, ast.NamedExpr):
            names = _peel(node.value)
            if isinstance(node.target, ast.Name):
                names = list(names)
                if node.target.id not in names:
                    names.append(node.target.id)
            return names
        if isinstance(node, ast.Name):
            return [node.id]
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            found: list[str] = []
            for elt in node.elts:
                nested = elt.value if isinstance(elt, ast.Starred) else elt
                found.extend(_peel(nested))
            return found
        if isinstance(node, ast.Dict):
            found = []
            for value in node.values:
                if value is not None:
                    found.extend(_peel(value))
            return found
        if isinstance(node, ast.IfExp):
            return _peel(node.body) + _peel(node.orelse)
        if isinstance(node, ast.BoolOp):
            found = []
            for value in node.values:
                found.extend(_peel(value))
            return found
        # Sequence carriers: ``([mc] + [])[0]`` / ``([p] * 1)[0]`` — share
        # BinOp peels with ``_shallow_packed_callee_exprs`` / candidate exprs
        # (Unknown > false PASS).
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mult)):
            found = list(_peel(node.left))
            if isinstance(node.op, ast.Add):
                found.extend(_peel(node.right))
            return found
        # Comprehension / generator carriers: ``[x for x in [exec]]`` /
        # ``(x for x in [exec])`` / ``{k: v for k, v in d.items()}`` — union the
        # element expression(s) with every generator iterable (Unknown > false PASS).
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)):
            found = []
            if isinstance(node, ast.DictComp):
                found.extend(_peel(node.key))
                found.extend(_peel(node.value))
            else:
                found.extend(_peel(node.elt))
            for gen in node.generators:
                found.extend(_peel_mapping(gen.iter))
            return found
        # ``{} | {"e": exec}`` / Name-bound ``d | {"e": exec}`` merge peels.
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
            return _peel_mapping(node.left) + _peel_mapping(node.right)
        if isinstance(node, ast.Subscript):
            names = list(_peel(node.value))
            key = _static_key(node.slice)
            if isinstance(key, str) and key not in names:
                names.append(key)
            # Name-bound dict/list packs: ``d = {"p": Proxy}; d["p"]``.
            if isinstance(node.value, ast.Name) and node.value.id in c_packs:
                pack = c_packs[node.value.id]
                if key in pack:
                    names.extend(pack[key])
                else:
                    for vs in pack.values():
                        names.extend(vs)
            # ``cm.maps[0]["e"]`` / ``cm.parents[0]["e"]`` — ChainMap packs.
            maps_base = _peel_call_func(node.value)
            if isinstance(maps_base, ast.Subscript):
                maps_attr = _peel_call_func(maps_base.value)
                if isinstance(maps_attr, ast.Attribute) and maps_attr.attr in {
                    "maps",
                    "parents",
                }:
                    names.extend(_peel_mapping(maps_attr.value))
            # ``dict(p=Proxy)["p"]`` / ``D(e=exec)["e"]`` / ``dict.__call__(…)`` /
            # ``ChainMap().new_child({"e": exec})["e"]`` / ``copy.copy(d)["e"]``.
            if isinstance(node.value, ast.Call):
                if _is_dict_constructor(
                    node.value.func,
                    dict_ctor_aliases=d_ctors,
                    getattr_aliases=g_aliases,
                ):
                    for val in _dict_call_values_for_key(node.value, key):
                        names.extend(_peel_mapping(val))
                if _is_dict_fromkeys(
                    node.value.func,
                    dict_ctor_aliases=d_ctors,
                    dict_view_products=d_views,
                ):
                    if len(node.value.args) >= 2:
                        names.extend(_peel(node.value.args[1]))
                    elif node.value.args:
                        names.extend(_peel(node.value.args[0]))
                # Mapping-preserving Calls: new_child / copy / deepcopy / merge.
                view_attr = None
                peeled_f = _peel_transparent_callee(node.value.func)
                if isinstance(peeled_f, ast.Attribute):
                    view_attr = peeled_f.attr
                elif isinstance(peeled_f, ast.Name):
                    view_attr = peeled_f.id
                    if view_attr in a_aliases:
                        view_attr = aliases.get(view_attr, view_attr)
                if view_attr in {"new_child", "copy", "deepcopy"} | _MAPPING_MERGE_METHODS | _MAPPING_COPY_FUNCS | _MAPPING_MERGE_FUNCS:
                    for arg in node.value.args:
                        names.extend(_peel_mapping(arg))
                    if isinstance(peeled_f, ast.Attribute):
                        names.extend(_peel_mapping(peeled_f.value))
                proj = _projection_factory_name(
                    node.value, projection_aliases=aliases
                )
                if proj in _MAPPING_COPY_FUNCS | _MAPPING_MERGE_FUNCS | {"new_child"}:
                    for arg in node.value.args:
                        names.extend(_peel_mapping(arg))
                # Packed ``[copy.deepcopy][0]([Mut])[0]`` / ``[copy.copy][0](xs)[i]``
                # — peel Call args when any packed callee is a copy applicator.
                if view_attr not in _MAPPING_COPY_FUNCS and proj not in _MAPPING_COPY_FUNCS:
                    for cand in _shallow_packed_callee_exprs(node.value.func):
                        cand = _peel_call_func(cand)
                        cand_attr: str | None = None
                        if isinstance(cand, ast.Attribute):
                            cand_attr = cand.attr
                        elif isinstance(cand, ast.Name):
                            cand_attr = aliases.get(cand.id, cand.id)
                        if cand_attr in _MAPPING_COPY_FUNCS:
                            for arg in node.value.args:
                                names.extend(_peel_mapping(arg))
                            break
            return names
        if isinstance(node, ast.Attribute):
            # ``X.__call__`` peels the receiver and keeps the ``__call__``
            # marker so ``rest["e"].__call__`` / ``oc.__call__`` surface the
            # packed identity while ``next(iter([type.__call__]))(Mut)`` still
            # observes the type-protocol product (Unknown > false PASS).
            if node.attr == "__call__":
                names = list(_peel(node.value))
                if "__call__" not in names:
                    names.append("__call__")
                return names
            # ``SimpleNamespace(e=exec).e`` — attr projects the kwarg pack.
            if isinstance(node.value, ast.Call) and _is_dict_constructor(
                node.value.func,
                dict_ctor_aliases=d_ctors,
                getattr_aliases=g_aliases,
            ):
                names = [node.attr]
                for val in _dict_call_values_for_key(node.value, node.attr):
                    names.extend(_peel(val))
                return names
            # ``ns = SimpleNamespace(e=exec); ns.e`` — Name-bound mapping pack.
            if isinstance(node.value, ast.Name) and node.value.id in c_packs:
                pack = c_packs[node.value.id]
                names = [node.attr]
                for pname in pack.get(node.attr, ()):
                    names.append(pname)
                return names
            return [node.attr]
        if isinstance(node, ast.Call):
            return _peel_call(node)
        return []

    def _peel_mapping(node: ast.AST) -> list[str]:
        """Peel a mapping/sequence operand, expanding Name-bound container packs."""

        names = list(_peel(node))
        inner = _peel_call_func(node)
        if isinstance(inner, ast.Name) and inner.id in c_packs:
            for vs in c_packs[inner.id].values():
                names.extend(vs)
        return names

    def _peel_call(call: ast.Call) -> list[str]:
        # Transparent trailing ``.__call__`` so view / merge peels share one path
        # with bare application (``getattr(ns,"get").__call__(k)``).
        # NamedExpr peels to the RHS Attribute so ``(g := D.setdefault)(...)``
        # shares the unbound/bound view path (Unknown > false PASS).
        func = _peel_transparent_callee(call.func)
        attr_func = func
        while isinstance(attr_func, ast.NamedExpr):
            attr_func = attr_func.value
        # Unbound ``dict.get(packed, key)`` / ``D.setdefault`` / walrus forms —
        # before bound-view key arity (first arg is the mapping).
        if (
            isinstance(attr_func, ast.Attribute)
            and attr_func.attr in {"get", "__getitem__", "pop", "setdefault"}
            and call.args
            and _is_dict_constructor(
                attr_func.value,
                dict_ctor_aliases=d_ctors,
                getattr_aliases=g_aliases,
            )
        ):
            exprs, keys = _dict_view_applied_parts(
                f"dict.{attr_func.attr}", call.args
            )
            names = []
            for expr in exprs:
                names.extend(_peel_mapping(expr))
            names.extend(keys)
            return names
        # Container views: ``{\"e\": exec}.get(\"e\")`` / ``[exec].pop()`` /
        # ``vars().get(\"exec\")`` / Name-bound ``d.get(\"Mut\")`` / ``.copy()``.
        if isinstance(attr_func, ast.Attribute) and attr_func.attr in _CALLEE_VIEW_ATTRS:
            recv = _peel_call_func(attr_func.value)
            names: list[str] = []
            key: str | None = None
            if (
                attr_func.attr in {"get", "__getitem__", "pop", "setdefault"}
                and call.args
            ):
                key = _static_str(call.args[0])
            if attr_func.attr == "keys":
                # Key packs (incl. non-constant ``{Mut: 1}``) — not values.
                if isinstance(recv, ast.Dict):
                    for map_key in recv.keys:
                        if map_key is not None:
                            names.extend(_peel(map_key))
                elif isinstance(recv, ast.Name) and recv.id in c_packs:
                    pack = c_packs[recv.id]
                    names.extend(pack.get(_KEYS_SLOT, ()))
                    for pk, vs in pack.items():
                        if pk is _KEYS_SLOT:
                            continue
                        if isinstance(pk, str) and pk.isidentifier():
                            names.append(pk)
                        names.extend(vs)
                else:
                    names.extend(_peel_mapping(recv))
                return names
            if attr_func.attr == "items":
                names.extend(_peel_mapping(recv))
                if isinstance(recv, ast.Dict):
                    for map_key in recv.keys:
                        if map_key is not None:
                            names.extend(_peel(map_key))
                elif isinstance(recv, ast.Name) and recv.id in c_packs:
                    names.extend(c_packs[recv.id].get(_KEYS_SLOT, ()))
                return names
            if key is not None and isinstance(recv, ast.Dict):
                matched = _dict_values_for_static_key(recv, key)
                if matched:
                    for value in matched:
                        names.extend(_peel(value))
                else:
                    names.append(key)
            elif (
                key is not None
                and isinstance(recv, ast.Name)
                and recv.id in c_packs
            ):
                pack = c_packs[recv.id]
                if key in pack:
                    names.extend(pack[key])
                else:
                    for vs in pack.values():
                        names.extend(vs)
            else:
                names.extend(_peel_mapping(recv))
                if key is not None:
                    names.append(key)
            # ``get`` / ``setdefault`` / ``pop`` default stores / yields its arg.
            if attr_func.attr in _DICT_VIEW_DEFAULTING and len(call.args) >= 2:
                names.extend(_peel(call.args[1]))
            return names
        # ``a.__or__(b)`` / ``a.__ior__(b)`` / ``operator.or_(a, b)`` /
        # ``operator.ior(a, b)`` / ``getattr(a, "__or__")(b)`` — mapping merges.
        if isinstance(attr_func, ast.Attribute) and attr_func.attr in _MAPPING_MERGE_METHODS:
            names = _peel_mapping(attr_func.value)
            for arg in call.args:
                names.extend(_peel_mapping(arg))
            return names
        if isinstance(func, ast.Call):
            g_merge = _getattr_static_name(func, getattr_aliases=g_aliases)
            if g_merge in _MAPPING_MERGE_METHODS and func.args:
                names = _peel_mapping(func.args[0])
                for arg in call.args:
                    names.extend(_peel_mapping(arg))
                return names
            # ``getattr(ns, "get"|"setdefault"|…)(key)`` view application.
            if g_merge in _CALLEE_VIEW_ATTRS and func.args:
                syn = ast.Call(
                    func=ast.Attribute(
                        value=func.args[0],
                        attr=g_merge,
                        ctx=ast.Load(),
                    ),
                    args=list(call.args),
                    keywords=list(call.keywords),
                )
                return _peel_call(syn)
        if _projection_factory_name(call, projection_aliases=aliases) in (
            _MAPPING_MERGE_FUNCS | _MAPPING_COPY_FUNCS | {"setitem"}
        ):
            names = []
            for arg in call.args:
                names.extend(_peel_mapping(arg))
            return names
        # Name-bound unbound/bound dict views: ``g = dict.get; g({}, k, Mut)``.
        peeled_func = _peel_call_func(func)
        if isinstance(peeled_func, ast.Name) and peeled_func.id in d_views:
            exprs, keys = _dict_view_applied_parts(
                d_views[peeled_func.id], call.args
            )
            names = []
            for expr in exprs:
                names.extend(_peel_mapping(expr))
            names.extend(keys)
            return names
        # Name-bound factory applied: ``ig = itemgetter(0); ig([oc])``.
        if isinstance(peeled_func, ast.Name) and peeled_func.id in f_products:
            kind, static = f_products[peeled_func.id]
            if kind == "itemgetter" and static is not None:
                names = [static]
                for arg in call.args:
                    names.extend(_peel(arg))
                return names
            if kind == "attrgetter" and static is not None:
                return [static]
            if kind == "methodcaller" and static is not None:
                names = [static]
                for arg in call.args:
                    names.extend(_peel(arg))
                return names
            # partial products peel their bound callee at Name-bind time.
        # ``getattr(obj, \"exec\")`` / ``getattr(Mut, \"__call__\", default)``.
        gname = _getattr_static_name(call, getattr_aliases=g_aliases)
        if gname is not None:
            names = [gname]
            if len(call.args) >= 3:
                names.extend(_peel(call.args[2]))
            # Transparent ``getattr(X, "__call__")`` peels X (parity with
            # ``X.__call__``) so ``getattr(tn,"__call__").__call__(…)`` observes.
            if gname == "__call__" and call.args:
                names = list(_peel(call.args[0])) + names
            # ``getattr(ns, "get")`` — surface kept for later key application.
            return names
        # Adapters: ``next(iter([exec]))`` / ``MappingProxyType(...)`` / aliases.
        adapter_name: str | None = None
        if isinstance(func, ast.Name):
            if func.id in _CALLEE_ADAPTER_NAMES or func.id in a_aliases:
                adapter_name = func.id
        elif isinstance(func, ast.Attribute) and func.attr in _CALLEE_ADAPTER_NAMES:
            adapter_name = func.attr
        if adapter_name is not None:
            names = []
            for arg in call.args:
                nested = arg.value if isinstance(arg, ast.Starred) else arg
                names.extend(_peel_mapping(nested))
            return names
        # ``dict(p=Proxy)`` / ``D(e=exec)`` / ``OrderedDict`` / ``dict.__call__``.
        if _is_dict_constructor(
            func, dict_ctor_aliases=d_ctors, getattr_aliases=g_aliases
        ):
            names = []
            for val in _dict_call_values_for_key(call):
                names.extend(_peel_mapping(val))
            return names
        # ``dict.fromkeys(["e"], exec)`` — value arg is the packed identity.
        if _is_dict_fromkeys(
            func, dict_ctor_aliases=d_ctors, dict_view_products=d_views
        ):
            names = []
            if len(call.args) >= 2:
                names.extend(_peel(call.args[1]))
            for arg in call.args[:1]:
                names.extend(_peel(arg))
            return names
        # ``operator.call(exec, ...)`` / renamed ``call``.
        if _is_operator_call_factory(
            call,
            projection_aliases=aliases,
            getattr_aliases=g_aliases,
            partial_aliases=p_aliases,
            adapter_aliases=a_aliases,
            container_packs=c_packs,
            factory_products=f_products,
            dict_view_products=d_views,
        ):
            if call.args:
                return _peel(call.args[0])
            return []
        # ``functools.partial(Mut)`` / ``partial(exec)`` / getattr partial.
        if _is_partial_factory(
            call, partial_aliases=p_aliases, getattr_aliases=g_aliases
        ):
            if call.args:
                return _peel(call.args[0])
            return []
        # ``operator.getitem(packed, \"Mut\")``.
        proj = _projection_factory_name(call, projection_aliases=aliases)
        if proj == "getitem" and call.args:
            names = list(_peel(call.args[0]))
            if len(call.args) >= 2:
                key = _static_str(call.args[1])
                if key is not None:
                    names.append(key)
                else:
                    names.extend(_peel(call.args[1]))
            return names
        # Factory applied to a receiver: ``attrgetter(\"Mut\")(Holder)`` /
        # ``itemgetter(\"exec\")(ns)`` / ``methodcaller(\"__call__\")(Mut)``.
        if isinstance(func, ast.Call):
            ag = _attrgetter_static_name(func, projection_aliases=aliases)
            if ag is not None:
                return [ag]
            ig = _itemgetter_static_key(func, projection_aliases=aliases)
            if ig is not None:
                names = [ig]
                for arg in call.args:
                    names.extend(_peel(arg))
                return names
            mc = _methodcaller_static_name(func, projection_aliases=aliases)
            if mc is not None:
                names = [mc]
                for arg in call.args:
                    names.extend(_peel(arg))
                return names
            # Name-bound factory as nested Call.func: ``ig([oc])``.
            nested_func = _peel_call_func(func.func)
            if isinstance(nested_func, ast.Name) and nested_func.id in f_products:
                return _peel(func)
            # ``partial(Mut)()`` already handled when peeling partial Call; when
            # ``func`` itself is ``partial(Mut)``, peel the factory.
            if _is_partial_factory(
                func, partial_aliases=p_aliases, getattr_aliases=g_aliases
            ):
                return _peel(func)
            if _is_operator_call_factory(
                func,
                projection_aliases=aliases,
                getattr_aliases=g_aliases,
                partial_aliases=p_aliases,
                adapter_aliases=a_aliases,
                container_packs=c_packs,
                factory_products=f_products,
                dict_view_products=d_views,
            ):
                return _peel(func)
        # Bare projection factory as callee peel: ``attrgetter(\"exec\")``.
        ag = _attrgetter_static_name(call, projection_aliases=aliases)
        if ag is not None:
            return [ag]
        ig = _itemgetter_static_key(call, projection_aliases=aliases)
        if ig is not None:
            return [ig]
        mc = _methodcaller_static_name(call, projection_aliases=aliases)
        if mc is not None:
            return [mc]
        return []

    return _peel(expr)


_BENIGN_BUILTINS = frozenset(
    {
        "print",
        "len",
        "abs",
        "min",
        "max",
        "sorted",
        "list",
        "dict",
        "set",
        "tuple",
        "str",
        "int",
        "bool",
        "float",
        "range",
        "enumerate",
        "zip",
        "map",
        "filter",
        "iter",
        "next",
        "open",
        "isinstance",
        "issubclass",
        "hasattr",
        "getattr",
        "id",
        "hash",
        "repr",
        "format",
        "sum",
        "any",
        "all",
        "round",
        "divmod",
        "pow",
        "bytearray",
        "bytes",
        "frozenset",
        "object",
        "type",
        "super",
        "property",
        "staticmethod",
        "classmethod",
    }
)



@dataclass
class _MutationAccum:
    """Mutable module-export / callable-behavior mutation accumulation."""

    export_mutations: dict[str, set[str]]
    behavior_mutations: set[tuple[str, str]]
    unsupported: bool = False

    @staticmethod
    def fresh() -> "_MutationAccum":
        return _MutationAccum(export_mutations={}, behavior_mutations=set())

    def as_effects(self) -> _MutationEffects:
        return _MutationEffects(
            export_mutations={
                path: frozenset(names)
                for path, names in self.export_mutations.items()
            },
            behavior_mutations=frozenset(self.behavior_mutations),
            unsupported_module_mutation=self.unsupported,
        )

    def export_poisoned(self, module_path: str, name: str) -> bool:
        names = self.export_mutations.get(module_path)
        if not names:
            return False
        return "*" in names or name in names

    def behavior_poisoned(self, identity: tuple[str, str]) -> bool:
        return identity in self.behavior_mutations


@dataclass
class RequestTimeIdentityState:
    """Full request-time abstract identity state for control-flow join (#169).

    Alias points-to is a may-point-to lattice. Mutation poisons are may
    (union). Re-establishments are must (same callable identity on every
    feasible predecessor). ``visited_fns`` is branch-local: forked per
    predecessor so distinct identity inputs are not memoized across branches.
    """

    env: dict[str, _IdentityPointsTo]
    export_mutations: dict[str, set[str]]
    behavior_mutations: set[tuple[str, str]]
    unsupported: bool
    reestablished_exports: dict[tuple[str, str], tuple[str, str]]
    reestablished_behaviors: set[tuple[str, str]]
    local_fns: dict[str, ast.FunctionDef | ast.AsyncFunctionDef]
    visited_fns: set[int]


def _match_pattern_irrefutable(pattern: ast.AST) -> bool:
    """True for patterns that always match (``case _`` / ``case x``)."""

    if isinstance(pattern, ast.MatchAs) and pattern.pattern is None:
        return True
    if isinstance(pattern, ast.MatchOr):
        return bool(pattern.patterns) and all(
            _match_pattern_irrefutable(item) for item in pattern.patterns
        )
    return False


def _match_exhaustive(stmt: ast.Match) -> bool:
    """Conservative exhaustiveness: final irrefutable case with no guard (#171)."""

    if not stmt.cases:
        return False
    final = stmt.cases[-1]
    return _match_pattern_irrefutable(final.pattern) and final.guard is None


def _same_local_callable(
    left: ast.AST | None,
    right: ast.AST | None,
) -> bool:
    """True when two nested callables are the same identity for must-join.

    Object identity is preferred; structurally identical defs (same source
    shape on every predecessor) also agree so uniform rebinding may
    re-establish without requiring a shared AST node object.
    """

    if left is None or right is None:
        return left is right
    if left is right:
        return True
    return ast.dump(left, include_attributes=False) == ast.dump(
        right, include_attributes=False
    )


def _local_callables_agree(
    nodes: Sequence[ast.FunctionDef | ast.AsyncFunctionDef | None],
) -> bool:
    if not nodes:
        return True
    first = nodes[0]
    return all(_same_local_callable(first, node) for node in nodes[1:])


def _join_request_time_identity_states(
    states: Sequence[RequestTimeIdentityState],
) -> RequestTimeIdentityState:
    """Join feasible predecessor states (Unknown > false PASS)."""

    if not states:
        raise ValueError("join requires at least one predecessor state")
    joined_env = _copy_env(states[0].env)
    for state in states[1:]:
        joined_env = _join_envs(joined_env, state.env)

    export_mutations: dict[str, set[str]] = {}
    behavior_mutations: set[tuple[str, str]] = set()
    unsupported = False
    for state in states:
        for path, names in state.export_mutations.items():
            export_mutations.setdefault(path, set()).update(names)
        behavior_mutations.update(state.behavior_mutations)
        unsupported = unsupported or state.unsupported

    reestablished_exports: dict[tuple[str, str], tuple[str, str]] = {}
    all_reest_keys: set[tuple[str, str]] = set()
    for state in states:
        all_reest_keys.update(state.reestablished_exports)
    for key in all_reest_keys:
        values: list[tuple[str, str]] = []
        agreed = True
        for state in states:
            restored = state.reestablished_exports.get(key)
            if restored is None:
                agreed = False
                break
            values.append(restored)
        if agreed and values and all(value == values[0] for value in values):
            restored = values[0]
            # Nested defs share (path, name) spelling; must-join also requires
            # the same local callable (object or structural identity).
            local_nodes = [state.local_fns.get(restored[1]) for state in states]
            if any(node is not None for node in local_nodes) and not (
                all(node is not None for node in local_nodes)
                and _local_callables_agree(local_nodes)
            ):
                agreed = False
        if agreed and values and all(value == values[0] for value in values):
            reestablished_exports[key] = values[0]
            # Uniform re-establishment clears the may-poison for this export.
            path, name = key
            names = export_mutations.get(path)
            if names is not None:
                names.discard(name)
                if not names:
                    del export_mutations[path]
        else:
            # Partial / disagreeing re-establishment cannot authorize.
            path, name = key
            export_mutations.setdefault(path, set()).add(name)
            for state in states:
                restored = state.reestablished_exports.get(key)
                if restored is not None:
                    behavior_mutations.add(restored)

    reestablished_behaviors = set(states[0].reestablished_behaviors)
    for state in states[1:]:
        reestablished_behaviors &= state.reestablished_behaviors
    # Drop behavior re-establishments whose local callables disagree.
    refined_behaviors: set[tuple[str, str]] = set()
    for key in reestablished_behaviors:
        _path, name = key
        local_nodes = [state.local_fns.get(name) for state in states]
        if all(node is None for node in local_nodes):
            refined_behaviors.add(key)
        elif all(node is not None for node in local_nodes) and _local_callables_agree(
            local_nodes
        ):
            refined_behaviors.add(key)
    any_reest_behaviors: set[tuple[str, str]] = set()
    for state in states:
        any_reest_behaviors.update(state.reestablished_behaviors)
    for key in any_reest_behaviors - refined_behaviors:
        behavior_mutations.add(key)
    for key in refined_behaviors:
        behavior_mutations.discard(key)
    reestablished_behaviors = refined_behaviors

    local_fns: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
    common_names = set(states[0].local_fns)
    for state in states[1:]:
        common_names &= set(state.local_fns)
    for name in common_names:
        nodes = [state.local_fns[name] for state in states]
        if _local_callables_agree(nodes):
            local_fns[name] = nodes[0]

    visited_fns = set(states[0].visited_fns)
    for state in states[1:]:
        visited_fns &= state.visited_fns

    return RequestTimeIdentityState(
        env=joined_env,
        export_mutations=export_mutations,
        behavior_mutations=behavior_mutations,
        unsupported=unsupported,
        reestablished_exports=reestablished_exports,
        reestablished_behaviors=reestablished_behaviors,
        local_fns=local_fns,
        visited_fns=visited_fns,
    )


@dataclass
class RequestTimeIdentitySession:
    """Phase-sensitive callable identity during request-time execution (#167/#169).

    Reuses the #166 object-alias identity environment. Mutations of module
    exports / callable behavior observed on the selected handler (and bounded
    direct callees) invalidate authorizing identity from that program point
    onward unless a subsequent source-grounded rebinding re-establishes it.

    Control-flow join (#169) forks and joins the whole abstract state — not
    only alias points-to — so branch-local re-establishment cannot clear
    poisons that remain on other feasible predecessors.
    """

    path: str
    accum: _MutationAccum
    env: dict[str, _IdentityPointsTo]
    local_fns: dict[str, ast.FunctionDef | ast.AsyncFunctionDef]
    visited_fns: set[int]
    _scan_stmts: object
    _observe_expr: object
    _seed_for: object
    _seed_match: object
    _resolver: "CalleeResolver"
    _reestablished_exports: dict[tuple[str, str], tuple[str, str]]
    _reestablished_behaviors: set[tuple[str, str]]

    def observe_statement(self, stmt: ast.stmt) -> None:
        """Apply identity mutations / alias updates for one statement."""

        self._scan_stmts(  # type: ignore[operator]
            [stmt],
            path=self.path,
            index=0,
            env=self.env,
            visited_fns=self.visited_fns,
            local_fns=self.local_fns,
        )
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            self.local_fns[stmt.name] = stmt
            if not stmt.decorator_list:
                key = (self.path, stmt.name)
                self._reestablished_behaviors.add(key)
                self.accum.behavior_mutations.discard(key)
        self._maybe_reestablish_from_assign(stmt)

    def observe_expression(self, expr: ast.AST) -> None:
        """Apply identity mutations for one executed expression (#173).

        Reuses ``_eval_expr`` recursive semantics so nested forms
        (``flag and poison()``, ``poison() if flag else False``,
        ``wrapper(poison())``, ``lambda x=poison(): x`` defaults,
        comprehensions, awaits) cannot diverge from statement-position
        call scanning.
        """

        self._observe_expr(  # type: ignore[operator]
            expr,
            path=self.path,
            env=self.env,
            visited_fns=self.visited_fns,
            local_fns=self.local_fns,
        )

    def observe_for_binding(self, target: ast.AST, iter_expr: ast.AST) -> None:
        """Seed a For / AsyncFor target from the iterated element union.

        For CF walkers that visit loop bodies themselves (not whole-``For``
        ``observe_statement``): dict ``keys`` / ``values`` / ``items`` views,
        comprehensions, ``zip`` / ``enumerate`` and Name-bound packs flow into
        class / protocol / container aliases exactly like Assign unpack.
        """

        self._seed_for(  # type: ignore[operator]
            target,
            iter_expr,
            path=self.path,
            env=self.env,
            visited_fns=self.visited_fns,
            local_fns=self.local_fns,
        )

    def observe_match_binding(self, pattern: ast.AST, subject: ast.AST) -> None:
        """Seed one Match case pattern's binders from the subject union."""

        self._seed_match(  # type: ignore[operator]
            pattern,
            subject,
            path=self.path,
            env=self.env,
            visited_fns=self.visited_fns,
            local_fns=self.local_fns,
        )

    def bind_name_unknown(self, name: str) -> None:
        """Sever precise identity for an unmodeled projection target (with-as)."""

        self.env[name] = _IdentityPointsTo.unknown_only()

    def mark_unsupported(self) -> None:
        """Force UNKNOWN for opaque identity mutation channels."""

        self.accum.unsupported = True

    def snapshot(self) -> RequestTimeIdentityState:
        """Deep-copy the full request-time abstract state."""

        return RequestTimeIdentityState(
            env=_copy_env(self.env),
            export_mutations={
                path: set(names)
                for path, names in self.accum.export_mutations.items()
            },
            behavior_mutations=set(self.accum.behavior_mutations),
            unsupported=self.accum.unsupported,
            reestablished_exports=dict(self._reestablished_exports),
            reestablished_behaviors=set(self._reestablished_behaviors),
            local_fns=dict(self.local_fns),
            visited_fns=set(self.visited_fns),
        )

    def fork(self) -> RequestTimeIdentityState:
        """Fork state for one feasible control-flow predecessor."""

        return self.snapshot()

    def restore(self, state: RequestTimeIdentityState) -> None:
        """Replace the live session with a previously forked/snapshotted state."""

        self.env.clear()
        self.env.update(_copy_env(state.env))
        self.accum.export_mutations = {
            path: set(names) for path, names in state.export_mutations.items()
        }
        self.accum.behavior_mutations = set(state.behavior_mutations)
        self.accum.unsupported = state.unsupported
        self._reestablished_exports = dict(state.reestablished_exports)
        self._reestablished_behaviors = set(state.reestablished_behaviors)
        self.local_fns = dict(state.local_fns)
        self.visited_fns = set(state.visited_fns)

    def join(self, states: Sequence[RequestTimeIdentityState]) -> None:
        """Install the sound join of feasible predecessor states."""

        joined = _join_request_time_identity_states(states)
        self.restore(joined)

    def copy_env(self) -> dict[str, _IdentityPointsTo]:
        return _copy_env(self.env)

    def join_env(self, other: Mapping[str, _IdentityPointsTo]) -> None:
        joined = _join_envs(self.env, other)
        self.env.clear()
        self.env.update(joined)

    def restore_env(self, saved: Mapping[str, _IdentityPointsTo]) -> None:
        self.env.clear()
        self.env.update(_copy_env(saved))

    def merge_identity_effects(self, other: RequestTimeIdentitySession) -> None:
        """Union request-time poisons from a callee/helper session into this one."""

        for path, names in other.accum.export_mutations.items():
            bucket = self.accum.export_mutations.setdefault(path, set())
            bucket.update(names)
        self.accum.behavior_mutations.update(other.accum.behavior_mutations)
        self.accum.unsupported = self.accum.unsupported or other.accum.unsupported
        for key, value in other._reestablished_exports.items():
            self._reestablished_exports[key] = value
        self._reestablished_behaviors.update(other._reestablished_behaviors)

    def _maybe_reestablish_from_assign(self, stmt: ast.stmt) -> None:
        """Re-establish export identity only from a session-fresh source def.

        Assigning an arbitrary module-level function (e.g. ``evil``) must keep
        the export poisoned. Only a nested ``def`` observed in this session
        (recorded in ``_reestablished_behaviors``) may restore a module export
        attribute binding (#167 case 9).
        """

        if isinstance(stmt, ast.Assign):
            targets = list(stmt.targets)
            value = stmt.value
        elif isinstance(stmt, ast.AnnAssign) and stmt.value is not None:
            targets = [stmt.target]
            value = stmt.value
        else:
            return
        if not isinstance(value, ast.Name) or value.id not in self.env:
            return
        rhs = self.env[value.id]
        callable_atoms = [a for a in rhs.known if isinstance(a, CallableObject)]
        if len(callable_atoms) != 1 or rhs.unknown:
            return
        atom = callable_atoms[0]
        if (atom.defining_path, atom.export_name) not in self._reestablished_behaviors:
            return
        for target in targets:
            if not isinstance(target, ast.Attribute):
                continue
            if not isinstance(target.value, ast.Name):
                continue
            base = self.env.get(target.value.id)
            if base is None:
                continue
            for mod in base.known:
                if isinstance(mod, ModuleObject):
                    module_path = mod.path
                elif isinstance(mod, ModuleNamespace):
                    module_path = mod.module_path
                else:
                    continue
                names = self.accum.export_mutations.get(module_path)
                if names and target.attr in names:
                    names.discard(target.attr)
                self.accum.behavior_mutations.discard(
                    (atom.defining_path, atom.export_name)
                )
                self._reestablished_exports[(module_path, target.attr)] = (
                    atom.defining_path,
                    atom.export_name,
                )

    def blocks_resolved_callee(self, callee: ResolvedCallee) -> bool:
        """True when request-time mutations make ``callee`` identity UNKNOWN."""

        if self.accum.unsupported:
            # exec/eval/compile / opaque class-creation protocols (#173).
            return True
        identity = callee.identity
        if (
            identity in self.accum.behavior_mutations
            and identity not in self._reestablished_behaviors
        ):
            return True
        path, name = identity
        if self.accum.export_poisoned(path, name):
            if (path, name) not in self._reestablished_exports:
                return True
            restored = self._reestablished_exports[(path, name)]
            if restored != identity:
                return True
            if restored in self.accum.behavior_mutations:
                return True
        return False

    def resolve_call(
        self,
        func: ast.AST,
        *,
        shadowed_names: frozenset[str] = frozenset(),
    ) -> CalleeResolveResult:
        """Resolve ``func`` under module bindings + request-time overlay."""

        if isinstance(func, ast.Name) and func.id in self.local_fns:
            node = self.local_fns[func.id]
            if func.id in shadowed_names or (
                self.path,
                func.id,
            ) in self._reestablished_behaviors:
                result = CalleeResolveResult(
                    callee=ResolvedCallee(path=self.path, node=node),
                )
                if result.callee is not None and self.blocks_resolved_callee(
                    result.callee
                ):
                    return CalleeResolveResult(
                        callee=None,
                        reason="request_time_callable_identity_unknown",
                    )
                return result

        result = self._resolver.resolve_call(
            func,
            caller_path=self.path,
            shadowed_names=shadowed_names,
        )
        # Nested ``helpers.write_state = evil_local`` reestablish must win over
        # the module resolver's original export (Unknown > false PASS, #173).
        if (
            result.callee is not None
            and isinstance(func, ast.Attribute)
            and isinstance(func.value, ast.Name)
        ):
            base = self.env.get(func.value.id)
            if base is not None:
                for atom in base.known:
                    if not isinstance(atom, ModuleObject):
                        continue
                    restored = self._reestablished_exports.get((atom.path, func.attr))
                    if (
                        restored is not None
                        and restored != result.callee.identity
                    ):
                        result = CalleeResolveResult(
                            callee=None,
                            reason="request_time_callable_identity_unknown",
                        )
                        break
        if result.callee is not None and self.blocks_resolved_callee(result.callee):
            return CalleeResolveResult(
                callee=None,
                reason="request_time_callable_identity_unknown",
            )
        if (
            result.callee is None
            and isinstance(func, ast.Attribute)
            and isinstance(func.value, ast.Name)
        ):
            base = self.env.get(func.value.id)
            if base is None:
                return result
            for atom in base.known:
                if not isinstance(atom, ModuleObject):
                    continue
                if self.accum.export_poisoned(atom.path, func.attr):
                    return CalleeResolveResult(
                        callee=None,
                        reason="request_time_callable_identity_unknown",
                    )
                restored = self._reestablished_exports.get((atom.path, func.attr))
                if restored is not None:
                    # Restored overlay must resolve to the rebound callable.
                    # Falling through to the original module export after a
                    # nested ``def`` assign false-PASSes client writers that
                    # rebound ``helpers.write_state`` (#173).
                    rpath, rname = restored
                    binding = self._resolver.bindings_by_path.get(rpath, {}).get(
                        rname
                    )
                    if (
                        binding is not None
                        and binding.kind == "function"
                        and binding.function_node is not None
                        and binding.behavior_established
                    ):
                        return CalleeResolveResult(
                            callee=ResolvedCallee(
                                path=rpath, node=binding.function_node
                            )
                        )
                    if rpath == self.path and rname in self.local_fns:
                        nested = ResolvedCallee(
                            path=rpath, node=self.local_fns[rname]
                        )
                        if self.blocks_resolved_callee(nested):
                            return CalleeResolveResult(
                                callee=None,
                                reason="request_time_callable_identity_unknown",
                            )
                        return CalleeResolveResult(callee=nested)
                    return CalleeResolveResult(
                        callee=None,
                        reason="request_time_callable_identity_unknown",
                    )
                binding = self._resolver.bindings_by_path.get(atom.path, {}).get(
                    func.attr
                )
                if (
                    binding is not None
                    and binding.kind == "function"
                    and binding.function_node is not None
                    and binding.behavior_established
                    and not self.accum.export_poisoned(atom.path, func.attr)
                    and (atom.path, func.attr) not in self.accum.behavior_mutations
                ):
                    return CalleeResolveResult(
                        callee=ResolvedCallee(
                            path=atom.path, node=binding.function_node
                        )
                    )
        return result


def _build_identity_scanner(
    trees: Mapping[str, ast.AST],
    bindings_by_path: Mapping[str, Mapping[str, FinalBinding]],
    *,
    available_paths: frozenset[str],
    import_roots: tuple[str, ...],
    accum: _MutationAccum,
):
    """Shared #165/#167 object-alias identity scanner closed over ``accum``."""

    lambda_bindings: dict[str, ast.Lambda] = {}
    # Name → class method FunctionDef for bound-method aliases (``p = m.poison``).
    method_bindings: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
    # Nested / module ClassDef registry for method-call following (#167 harden).
    class_registry: dict[str, ast.ClassDef] = {}
    # Local name → class name for ``m = Mut()`` instance aliases.
    instance_class_of: dict[str, str] = {}
    # Import aliases of exec/eval/compile (incl. ``from builtins import exec as run``).
    exec_eval_compile_aliases: set[str] = set()
    # Import aliases of types.new_class (``from types import new_class as nc``).
    new_class_aliases: set[str] = set()
    # Local / import aliases of builtin ``type`` (``T = type`` / ``builtins.type``).
    type_aliases: set[str] = set()
    # Local aliases of ``getattr`` (``g = getattr``) for protocol projections.
    getattr_aliases: set[str] = {"getattr"}
    # Local / import aliases of ``setattr`` (``from builtins import setattr as sa``).
    setattr_aliases: set[str] = {"setattr"}
    # Name-bound ``slice`` constructor products: ``s = slice(0, 1)``.
    slice_aliases: set[str] = {"slice"}
    # ``from operator import itemgetter as ig`` → local name → canonical projection.
    operator_projection_aliases: dict[str, str] = {}
    # ``from functools import partial as p`` / ``P = functools.partial``.
    partial_aliases: set[str] = {"partial"}
    # ``from types import MappingProxyType as MPT`` / adapter Name aliases.
    adapter_aliases: set[str] = set()
    # Name-bound factory products: ``ag = attrgetter("Mut")`` / ``p = partial(Mut)``.
    # Maps local name → (kind, static_payload) where kind is attrgetter/
    # itemgetter/methodcaller/partial and payload is the static attr/key/method
    # (None for partial — see partial_product_names).
    projection_factory_products: dict[str, tuple[str, str | None]] = {}
    partial_product_names: dict[str, list[str]] = {}
    # Bound mapping arg for ``p = partial(copy.copy, d)`` zero-arg apply.
    partial_bound_mappings: dict[str, ast.AST] = {}
    # Name-bound ``type.__new__`` / ``type.__call__`` / getattr projections.
    type_protocol_products: dict[str, str] = {}
    # Intermediate class projection products: ``m = gi({"Mut": Mut}, "Mut")``.
    class_projection_products: dict[str, list[str]] = {}
    # Bound dict views: ``g = {}.get`` / ``g = d.__getitem__``.
    # Unbound: ``g = dict.get`` / ``g = D.get`` → ``dict.get`` (arity differs).
    dict_view_products: dict[str, str] = {}
    # Bound method receivers: ``k = d.keys`` → ``k`` maps to ``d`` for ``k()``.
    bound_view_receivers: dict[str, str] = {}
    # Non-Name bound view receivers: ``g = {"c": Mut}.items`` → Dict literal.
    bound_view_expr_receivers: dict[str, ast.AST] = {}
    # Name-bound Attribute callees: ``f = n.install`` / ``for f in [n.install]``
    # / ``match [n.install]: case [f]`` — preserve Attribute for accounted peels
    # when For/Match env points-to stay unknown (Unknown > false PASS).
    bound_callee_exprs: dict[str, ast.AST] = {}
    # Sequence/view carriers that must preserve pair structure for unpack:
    # ``it = d.items()`` / ``ks = d.keys()`` / with-as items carriers.
    sequence_view_aliases: dict[str, ast.AST] = {}
    # Name-bound static string keys: ``k = "MappingProxyType"``.
    string_constant_names: dict[str, str] = {}
    # Name-bound static Constant keys (int/str/…): ``idx = 0`` / ``xk = "x"``.
    static_constant_names: dict[str, object] = {}
    # Name-bound container packs: ``d = {"p": Proxy}`` → key → packed names.
    container_packs: dict[str, dict[object, tuple[str, ...]]] = {}
    # Renamed ``vars`` / ``globals`` / ``locals`` for namespace adapter seeds.
    ns_projection_aliases: set[str] = set()
    # Name-bound namespace carriers: ``ns = types.__dict__`` / ``ns = vars(types)``.
    ns_dict_aliases: set[str] = set()
    # ``d = vars(ns)`` / ``d = ns.__dict__`` → grow packs on the owning ns Name.
    ns_dict_alias_roots: dict[str, str] = {}
    # ``m = cm.maps`` / ``m = getattr(cm, "maps")`` → ChainMap list alias.
    chainmap_list_aliases: dict[str, tuple[str, str]] = {}
    # Name-bound mapping constructors: ``D = dict`` / ``OD = OrderedDict``.
    dict_ctor_aliases: set[str] = set()
    # ``import copy`` / ``import copy as cp`` / ``m = copy`` module aliases.
    copy_module_aliases: set[str] = {"copy"}

    def _slice_key(key: ast.AST) -> bool:
        """Live ``slice``-alias peel for packing-transparent sequence slices."""

        return _is_sequence_slice_key(
            key,
            slice_aliases=frozenset(slice_aliases),
            getattr_aliases=frozenset(getattr_aliases),
        )

    def _peel_slices(expr: ast.AST) -> ast.AST:
        """Scanner-local ``_peel_sequence_slice_layers`` with slice aliases."""

        return _peel_sequence_slice_layers(
            expr,
            slice_aliases=frozenset(slice_aliases),
            getattr_aliases=frozenset(getattr_aliases),
        )

    def _is_unbound_list_recv(recv: ast.AST) -> bool:
        """True when ``recv`` peels to unbound ``list`` / import-as / builtins.list."""

        for arm in _iter_boolop_ifexp_arms(recv):
            arm = _peel_call_func(arm)
            if isinstance(arm, ast.Name) and (
                arm.id == "list"
                or operator_projection_aliases.get(arm.id) == "list"
                or arm.id in dict_ctor_aliases
            ):
                return True
            if isinstance(arm, ast.Attribute) and arm.attr == "list":
                return True
            if isinstance(arm, ast.Call) and (
                _getattr_static_name(
                    arm, getattr_aliases=frozenset(getattr_aliases)
                )
                == "list"
            ):
                return True
            if isinstance(arm, ast.Subscript) and _static_str(arm.slice) == "list":
                # ``builtins.__dict__["list"]`` / ``vars(builtins)["list"]``.
                return True
        return False

    def _packed_names(expr: ast.AST) -> list[str]:
        """Shared packing/projection peel with live protocol aliases."""

        return _names_packed_as_callee(
            expr,
            projection_aliases=operator_projection_aliases,
            getattr_aliases=frozenset(getattr_aliases),
            partial_aliases=frozenset(partial_aliases),
            adapter_aliases=frozenset(adapter_aliases),
            container_packs=container_packs,
            factory_products=projection_factory_products,
            dict_view_products=dict_view_products,
            dict_ctor_aliases=frozenset(dict_ctor_aliases),
        )

    def _note_factory_product_from_value(name: str, value: ast.AST) -> None:
        """Track Name-bound attrgetter/itemgetter/methodcaller/partial products."""

        value = _peel_call_func(value)
        if not isinstance(value, ast.Call):
            # Double alias of a product: ``ag2 = ag``.
            if isinstance(value, ast.Name) and value.id in projection_factory_products:
                projection_factory_products[name] = projection_factory_products[
                    value.id
                ]
                if value.id in partial_product_names:
                    partial_product_names[name] = list(partial_product_names[value.id])
                if value.id in partial_bound_mappings:
                    partial_bound_mappings[name] = partial_bound_mappings[value.id]
            elif isinstance(value, ast.Name):
                projection_factory_products.pop(name, None)
                partial_product_names.pop(name, None)
                partial_bound_mappings.pop(name, None)
            return
        ag = _attrgetter_static_name(
            value,
            projection_aliases=operator_projection_aliases,
            getattr_aliases=frozenset(getattr_aliases),
        )
        if ag is not None:
            projection_factory_products[name] = ("attrgetter", ag)
            partial_product_names.pop(name, None)
            partial_bound_mappings.pop(name, None)
            return
        ig = _itemgetter_static_key(
            value,
            projection_aliases=operator_projection_aliases,
            getattr_aliases=frozenset(getattr_aliases),
        )
        if ig is not None:
            projection_factory_products[name] = ("itemgetter", ig)
            partial_product_names.pop(name, None)
            partial_bound_mappings.pop(name, None)
            return
        mc = _methodcaller_static_name(
            value,
            projection_aliases=operator_projection_aliases,
            getattr_aliases=frozenset(getattr_aliases),
        )
        if mc is not None:
            projection_factory_products[name] = ("methodcaller", mc)
            partial_product_names.pop(name, None)
            partial_bound_mappings.pop(name, None)
            return
        if _is_partial_factory(
            value,
            partial_aliases=frozenset(partial_aliases),
            getattr_aliases=frozenset(getattr_aliases),
        ):
            # ``partial(copy.copy, d)`` — bound mapping may be arg1; still
            # seed the factory callable as a copy product for zero-arg apply.
            packed = _packed_names(value.args[0]) if value.args else []
            if value.args:
                bound0 = _peel_call_func(value.args[0])
                if isinstance(bound0, ast.Call):
                    gcopy = _getattr_static_name(
                        bound0, getattr_aliases=frozenset(getattr_aliases)
                    )
                    if gcopy in _MAPPING_COPY_FUNCS and gcopy not in packed:
                        packed = [gcopy, *packed]
                elif (
                    isinstance(bound0, ast.Attribute)
                    and bound0.attr in _MAPPING_COPY_FUNCS
                    and bound0.attr not in packed
                ):
                    packed = [bound0.attr, *packed]
            projection_factory_products[name] = ("partial", None)
            partial_product_names[name] = packed
            if len(value.args) >= 2:
                partial_bound_mappings[name] = value.args[1]
            else:
                partial_bound_mappings.pop(name, None)
            return
        projection_factory_products.pop(name, None)
        partial_product_names.pop(name, None)
        partial_bound_mappings.pop(name, None)

    def _pack_add(
        pack: dict[object, tuple[str, ...]],
        key: object,
        names: Sequence[str],
    ) -> None:
        """Union ``names`` into ``pack[key]`` (may-alias, order-preserving)."""

        if not names:
            return
        pack[key] = tuple(dict.fromkeys((*pack.get(key, ()), *names)))

    def _pack_union(
        *packs: Mapping[object, tuple[str, ...]] | None,
    ) -> dict[object, tuple[str, ...]]:
        merged: dict[object, tuple[str, ...]] = {}
        for pack in packs:
            for key, names in (pack or {}).items():
                _pack_add(merged, key, names)
        return merged

    def _flat_pack_names(pack: Mapping[object, tuple[str, ...]]) -> list[str]:
        return list(dict.fromkeys(n for vs in pack.values() for n in vs))

    def _packed_names_deep(expr: ast.AST) -> list[str]:
        """Packed names plus nested Name-bound container pack contents."""

        found: list[str] = []
        seen: set[str] = set()
        pending = list(_packed_names(expr))
        while pending:
            name = pending.pop(0)
            if name not in found:
                found.append(name)
            if name in seen:
                continue
            seen.add(name)
            pack = container_packs.get(name)
            if pack:
                pending.extend(_flat_pack_names(pack))
        return found

    def _resolve_static_key_value(node: ast.AST) -> object | None:
        """Constant / Name-bound static key (str/int/…) for subscript peels."""

        peeled = _peel_call_func(node)
        direct = _static_key(peeled)
        if direct is not None:
            return direct
        if isinstance(peeled, ast.Name):
            if peeled.id in static_constant_names:
                return static_constant_names[peeled.id]
            return string_constant_names.get(peeled.id)
        return None

    def _carrier_element_at(carrier: ast.AST, key: object | None) -> ast.AST | None:
        """Element/value expression at static ``key`` in a resolvable carrier."""

        carrier = _peel_slices(carrier)
        if isinstance(carrier, ast.Name) and carrier.id in sequence_view_aliases:
            return _carrier_element_at(sequence_view_aliases[carrier.id], key)
        if isinstance(
            carrier, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)
        ):
            # ``[x for x in fns.items()][0]`` — shared element peel.
            elems = _iter_elements(carrier)
            if elems is not None and isinstance(key, int) and 0 <= key < len(elems):
                return elems[key]
            return None
        if isinstance(carrier, (ast.List, ast.Tuple)):
            # Expand ``[*items()]`` / starred elts before indexing.
            elems = _iter_elements(carrier)
            if elems is not None and isinstance(key, int) and 0 <= key < len(elems):
                return elems[key]
            if isinstance(key, int) and 0 <= key < len(carrier.elts):
                elt = carrier.elts[key]
                if isinstance(elt, ast.Starred):
                    sub = _iter_elements(elt.value)
                    return sub[0] if sub else elt.value
                return elt
            return None
        if isinstance(carrier, ast.Dict) and key is not None:
            for map_key, map_val in zip(carrier.keys, carrier.values):
                if (
                    map_val is not None
                    and isinstance(map_key, ast.Constant)
                    and map_key.value == key
                ):
                    return map_val
            return None
        if isinstance(carrier, ast.Name) and carrier.id in container_packs:
            pack = container_packs[carrier.id]
            if key in pack and pack[key]:
                return ast.Name(id=pack[key][0], ctx=ast.Load())
            return None
        # Nested subscript: ``keys[0]`` when resolving ``keys[0][0]``.
        # Sequence slices already peeled above; remaining slices are opaque.
        if isinstance(carrier, ast.Subscript):
            if _slice_key(carrier.slice):
                return _carrier_element_at(carrier.value, key)
            inner = _carrier_element_at(
                carrier.value, _resolve_static_key_value(carrier.slice)
            )
            if inner is None:
                return None
            if key is None:
                return inner
            return _carrier_element_at(inner, key)
        # Nested Call carriers: ``keys.get("x").get("y")`` /
        # ``getitem(getitem(keys,"x"),"y")`` / ``itemgetter("y")(itemgetter("x")(keys))``
        # / ``copy.copy({'outer': […]})['outer']``.
        if isinstance(carrier, ast.Call):
            inner = _call_projected_carrier_value(carrier)
            if inner is not None:
                if key is None:
                    return inner
                return _carrier_element_at(inner, key)
            # Mapping-/sequence-preserving Calls (copy/deepcopy/list/…).
            items = _mapping_items(carrier)
            if items is not None and key is not None:
                for map_key, map_val in items:
                    if (
                        map_val is not None
                        and isinstance(map_key, ast.Constant)
                        and map_key.value == key
                    ):
                        return map_val
            elems = _iter_elements(carrier)
            if elems is not None:
                if isinstance(key, int) and 0 <= key < len(elems):
                    return elems[key]
                # ``next(iter(items()))[1]`` — project into the yielded pair.
                if len(elems) == 1:
                    if key is None:
                        return elems[0]
                    return _carrier_element_at(elems[0], key)
            return None
        return None

    def _call_projected_carrier_value(call: ast.Call) -> ast.AST | None:
        """Concrete element AST projected by get/getitem/itemgetter Calls."""

        func = _peel_call_func(call.func)
        if isinstance(func, ast.Call):
            ig = _itemgetter_static_key(
                func, projection_aliases=operator_projection_aliases
            )
            if ig is not None and call.args:
                return _carrier_element_at(call.args[0], ig)
        if isinstance(func, ast.Name) and call.args:
            product = projection_factory_products.get(func.id)
            if product is not None and product[0] == "itemgetter":
                return _carrier_element_at(call.args[0], product[1])
        proj = _projection_factory_name(
            call,
            projection_aliases=operator_projection_aliases,
            getattr_aliases=frozenset(getattr_aliases),
        )
        if proj == "getitem" and len(call.args) >= 2:
            return _carrier_element_at(
                call.args[0], _resolve_static_key_value(call.args[1])
            )
        view = _view_call_parts(call)
        if view is not None and view[0] in {
            "get",
            "pop",
            "__getitem__",
            "setdefault",
        }:
            _attr, recv = view
            key = (
                _resolve_static_key_value(call.args[0]) if call.args else None
            )
            return _carrier_element_at(recv, key)
        return None

    def _project_static_str_from_carrier(
        carrier: ast.AST, key: object | None
    ) -> str | None:
        """Project a static str from a list/dict/Name-bound carrier at ``key``."""

        elem = _carrier_element_at(carrier, key)
        if elem is None:
            return None
        return _resolve_static_str(elem)

    def _resolve_static_str(node: ast.AST) -> str | None:
        """Constant str, walrus, Name-bound, or static container projection key.

        Shared peel for bare ``keys[0]`` / ``keys["x"]``, Name-bound index,
        ``.get`` / ``.__getitem__`` / ``.pop``, ``operator.getitem`` /
        ``itemgetter``, ``getattr(keys, …)``, and nested ``keys[0][0]``.
        """

        peeled = _peel_call_func(node)
        direct = _static_str(peeled)
        if direct is not None:
            return direct
        if isinstance(peeled, ast.Name):
            bound = string_constant_names.get(peeled.id)
            if bound is not None:
                return bound
            const = static_constant_names.get(peeled.id)
            return const if isinstance(const, str) else None
        # ``keys[0]`` / ``keys[idx]`` / ``keys[xk]`` / nested ``keys[0][0]``.
        if isinstance(peeled, ast.Subscript):
            key = _resolve_static_key_value(peeled.slice)
            projected = _project_static_str_from_carrier(peeled.value, key)
            if projected is not None:
                return projected

        # Call projections: ``keys.get("x")`` / ``keys.__getitem__(0)`` /
        # ``operator.getitem(keys, 0)`` / ``itemgetter("x")(keys)`` /
        # ``keys.pop("x")`` / ``getattr(keys, "get")("x")``.
        if isinstance(peeled, ast.Call):
            ig = _itemgetter_static_key(
                peeled, projection_aliases=operator_projection_aliases
            )
            # ``itemgetter("k")(keys)`` — project from the applied carrier.
            if (
                isinstance(peeled.func, ast.Call)
                and _itemgetter_static_key(
                    peeled.func, projection_aliases=operator_projection_aliases
                )
                is not None
                and peeled.args
            ):
                key = _itemgetter_static_key(
                    peeled.func, projection_aliases=operator_projection_aliases
                )
                return _project_static_str_from_carrier(peeled.args[0], key)
            # Name-bound ``ig = itemgetter("x"); ig(keys)``.
            if isinstance(peeled.func, ast.Name) and peeled.args:
                product = projection_factory_products.get(peeled.func.id)
                if product is not None and product[0] == "itemgetter":
                    return _project_static_str_from_carrier(
                        peeled.args[0], product[1]
                    )
            view = _view_call_parts(peeled)
            if view is not None and view[0] in {
                "get",
                "pop",
                "__getitem__",
                "setdefault",
            }:
                _attr, recv = view
                key = (
                    _resolve_static_key_value(peeled.args[0])
                    if peeled.args
                    else None
                )
                return _project_static_str_from_carrier(recv, key)
            # ``operator.getitem(keys, 0|"x")`` / renamed getitem.
            proj = _projection_factory_name(
                peeled,
                projection_aliases=operator_projection_aliases,
                getattr_aliases=frozenset(getattr_aliases),
            )
            if proj == "getitem" and len(peeled.args) >= 2:
                return _project_static_str_from_carrier(
                    peeled.args[0], _resolve_static_key_value(peeled.args[1])
                )
            # ``operator.itemgetter("MappingProxyType")`` key-only / applied.
            if ig is not None and isinstance(ig, str):
                if peeled.args:
                    projected = _project_static_str_from_carrier(peeled.args[0], ig)
                    if projected is not None:
                        return projected
                return ig
        return None

    def _view_call_parts(call: ast.Call) -> tuple[str, ast.AST] | None:
        """``recv.attr(...)`` / ``getattr(recv, "attr")(...)`` → ``(attr, recv)``.

        Also peels trailing ``.__call__`` and Name-bound bound views
        (``k = d.keys; k()`` / ``getattr(ns,"get").__call__(key)`` /
        ``g = {"c": Mut}.items; g()`` / ``views[0]()`` packed Attributes).
        """

        func = _peel_transparent_callee(call.func)

        def _parts_from_attr(attr_node: ast.Attribute) -> tuple[str, ast.AST] | None:
            attr = attr_node.attr
            recv = attr_node.value
            # Unbound ``dict.popitem(d)`` / ``dict.keys(d)`` / ``dict.copy(d)``
            # — mapping is arg0.
            if (
                attr
                in _DICT_ITER_VIEW_ATTRS
                | _NS_DICT_VIEW_ATTRS
                | _MAPPING_COPY_FUNCS
                | {"fromkeys"}
                and _is_dict_constructor(
                    recv,
                    dict_ctor_aliases=frozenset(dict_ctor_aliases),
                    getattr_aliases=frozenset(getattr_aliases),
                )
                and call.args
            ):
                return attr, call.args[0]
            # Module ``copy.copy(d)`` / ``cp.copy(d)`` / ``m.copy(d)``.
            if (
                attr in _MAPPING_COPY_FUNCS
                and call.args
                and isinstance(_peel_call_func(recv), ast.Name)
                and _peel_call_func(recv).id in copy_module_aliases  # type: ignore[union-attr]
            ):
                return attr, call.args[0]
            return attr, recv

        if isinstance(func, ast.Attribute):
            return _parts_from_attr(func)
        # BoolOp / IfExp / packed bound views: ``(0 or views.pop)(-1)`` /
        # ``(views.pop if True else None)(-1)`` / ``[views.pop][0](-1)``.
        if isinstance(func, (ast.BoolOp, ast.IfExp, ast.Subscript)):
            for cand in _callee_candidate_exprs(func):
                cand = _peel_transparent_callee(cand)
                if isinstance(cand, ast.Attribute):
                    parts = _parts_from_attr(cand)
                    if parts is not None:
                        return parts
                if isinstance(cand, ast.Name) and cand.id in dict_view_products:
                    view = dict_view_products[cand.id]
                    base = view.split(".")[-1]
                    recv_name = bound_view_receivers.get(cand.id)
                    if recv_name is not None:
                        return base, ast.Name(id=recv_name, ctx=ast.Load())
                    expr_recv = bound_view_expr_receivers.get(cand.id)
                    if expr_recv is not None:
                        return base, expr_recv
                    if view.startswith("dict.") and call.args:
                        return base, call.args[0]
                if isinstance(cand, ast.Call):
                    gname = _getattr_static_name(
                        cand, getattr_aliases=frozenset(getattr_aliases)
                    )
                    if gname is not None and cand.args:
                        grecv = cand.args[0]
                        # Module ``(0 or getattr(copy,"deepcopy"))(xs)`` /
                        # ``[getattr(copy,"copy")][0](xs)`` — applied arg is
                        # the carrier (same as bare getattr Call branch).
                        if (
                            gname in _MAPPING_COPY_FUNCS
                            and call.args
                            and (
                                (
                                    isinstance(_peel_call_func(grecv), ast.Name)
                                    and _peel_call_func(grecv).id  # type: ignore[union-attr]
                                    in copy_module_aliases
                                )
                                or _is_dict_constructor(
                                    grecv,
                                    dict_ctor_aliases=frozenset(dict_ctor_aliases),
                                    getattr_aliases=frozenset(getattr_aliases),
                                )
                            )
                        ):
                            return gname, call.args[0]
                        if (
                            gname
                            in _DICT_ITER_VIEW_ATTRS
                            | _NS_DICT_VIEW_ATTRS
                            | _MAPPING_COPY_FUNCS
                            | {"fromkeys"}
                            and _is_dict_constructor(
                                grecv,
                                dict_ctor_aliases=frozenset(dict_ctor_aliases),
                                getattr_aliases=frozenset(getattr_aliases),
                            )
                            and call.args
                        ):
                            return gname, call.args[0]
                        return gname, grecv
        if isinstance(func, ast.Call):
            attr = _getattr_static_name(
                func, getattr_aliases=frozenset(getattr_aliases)
            )
            if attr is not None and func.args:
                recv = func.args[0]
                if (
                    attr
                    in _DICT_ITER_VIEW_ATTRS
                    | _NS_DICT_VIEW_ATTRS
                    | _MAPPING_COPY_FUNCS
                    | {"fromkeys"}
                    and _is_dict_constructor(
                        recv,
                        dict_ctor_aliases=frozenset(dict_ctor_aliases),
                        getattr_aliases=frozenset(getattr_aliases),
                    )
                    and call.args
                ):
                    return attr, call.args[0]
                # ``getattr(copy, "copy")(d)`` / ``getattr(dict, "copy")(d)``.
                if (
                    attr in _MAPPING_COPY_FUNCS
                    and call.args
                    and (
                        (
                            isinstance(_peel_call_func(recv), ast.Name)
                            and _peel_call_func(recv).id  # type: ignore[union-attr]
                            in copy_module_aliases
                        )
                        or _is_dict_constructor(
                            recv,
                            dict_ctor_aliases=frozenset(dict_ctor_aliases),
                            getattr_aliases=frozenset(getattr_aliases),
                        )
                    )
                ):
                    return attr, call.args[0]
                return attr, recv
        if isinstance(func, ast.Name):
            view = dict_view_products.get(func.id)
            if view is not None:
                base = view.split(".")[-1]
                recv_name = bound_view_receivers.get(func.id)
                if recv_name is not None:
                    return base, ast.Name(id=recv_name, ctx=ast.Load())
                expr_recv = bound_view_expr_receivers.get(func.id)
                if expr_recv is not None:
                    return base, expr_recv
                if view.startswith("dict.") and call.args:
                    # Unbound ``g = dict.keys; g(d)`` — receiver is first arg.
                    return base, call.args[0]
        # Packed bound views: ``views=[d.keys]; views[0]()`` /
        # ``views={'v': d.keys}; views['v']()`` /
        # nested ``views={'outer':{'v':d.keys}}; views['outer']['v']()``.
        if isinstance(func, ast.Subscript):
            candidates: list[ast.AST] = []
            for cand in _callee_candidate_exprs(func):
                candidates.append(cand)
            if not candidates:
                base = _peel_call_func(func.value)
                carrier = base
                if isinstance(base, ast.Name) and base.id in sequence_view_aliases:
                    carrier = sequence_view_aliases[base.id]
                mapped = _mapping_items(carrier)
                if isinstance(carrier, (ast.Dict, ast.DictComp)) or (
                    mapped is not None
                    and not isinstance(carrier, (ast.List, ast.Tuple, ast.Set))
                ):
                    key = _resolve_static_key_value(func.slice)
                    if key is None:
                        key = _static_key(func.slice)
                    if key is None:
                        key = _resolve_static_str(func.slice)
                    for map_key, val in mapped or []:
                        if val is None:
                            continue
                        if key is not None and isinstance(map_key, ast.Constant):
                            if map_key.value != key:
                                continue
                        candidates.append(val)
                else:
                    candidates.extend(_iter_elements(carrier) or ())
            for elt in candidates:
                elt = _peel_transparent_callee(elt)
                if isinstance(elt, ast.Attribute):
                    parts = _parts_from_attr(elt)
                    if parts is not None and parts[0] in _DICT_ITER_VIEW_ATTRS | {
                        "fromkeys"
                    }:
                        return parts
                if isinstance(elt, ast.Name) and elt.id in dict_view_products:
                    view = dict_view_products[elt.id]
                    base_attr = view.split(".")[-1]
                    recv_name = bound_view_receivers.get(elt.id)
                    if recv_name is not None:
                        return base_attr, ast.Name(id=recv_name, ctx=ast.Load())
                    expr_recv = bound_view_expr_receivers.get(elt.id)
                    if expr_recv is not None:
                        return base_attr, expr_recv
                    if view.startswith("dict.") and call.args:
                        # Unbound packed ``views=[fk]; views[0]([Mut])``.
                        return base_attr, call.args[0]
        return None

    def _subst_names(node: ast.AST, bind: Mapping[str, ast.AST]) -> ast.AST:
        """Replace Load Names in ``node`` by bound element expressions."""

        if not bind:
            return node

        class _Subst(ast.NodeTransformer):
            def visit_Name(self, name_node: ast.Name) -> ast.AST:
                repl = bind.get(name_node.id)
                if repl is not None and isinstance(name_node.ctx, ast.Load):
                    return repl
                return name_node

        return _Subst().visit(copy.deepcopy(node))

    def _observe_subst_body(
        body: ast.AST,
        bind: Mapping[str, ast.AST],
        *,
        path: str,
        index: int,
        env: dict[str, _IdentityPointsTo],
        visited_fns: set[int],
        local_fns: Mapping[str, ast.FunctionDef | ast.AsyncFunctionDef] | None,
        local_classes: Mapping[str, ast.ClassDef] | None,
    ) -> None:
        """Observe a substituted apply body (map/filter/comp/key=/reduce)."""

        subst = _subst_names(body, bind)
        # Seed protocol aliases for formals so ``f(Mut)`` sees type.__call__.
        for formal, actual in bind.items():
            _note_protocol_alias_from_value(formal, actual)
        if isinstance(subst, ast.Call):
            _scan_call(
                subst,
                path=path,
                index=index,
                env=env,
                visited_fns=visited_fns,
                local_fns=local_fns,
                local_classes=local_classes,
            )
            return
        # ``f(Mut) or True`` / BoolOp / IfExp / Compare wrappers around Call.
        for child in ast.walk(subst):
            if isinstance(child, ast.Call):
                _scan_call(
                    child,
                    path=path,
                    index=index,
                    env=env,
                    visited_fns=visited_fns,
                    local_fns=local_fns,
                    local_classes=local_classes,
                )
        _eval_expr(subst, env, path=path)

    def _observe_lambda_apply(
        fn: ast.AST,
        elements: Sequence[ast.AST],
        *,
        path: str,
        index: int,
        env: dict[str, _IdentityPointsTo],
        visited_fns: set[int],
        local_fns: Mapping[str, ast.FunctionDef | ast.AsyncFunctionDef] | None,
        local_classes: Mapping[str, ast.ClassDef] | None,
        starmap: bool = False,
        skip_first_formal: bool = False,
    ) -> bool:
        """Apply lambda / type-protocol / Name-bound key callables per element.

        Shared peel for ``key=lambda`` / ``key=type.__call__`` / Name /
        ``getattr(type, \"__call__\")`` / ``starmap(type.__call__, …)``.
        """

        head = _peel_transparent_callee(fn)
        if isinstance(head, ast.Name) and head.id in lambda_bindings:
            head = lambda_bindings[head.id]

        def _type_protocol_from_fn(node: ast.AST) -> str | None:
            peeled = _peel_transparent_callee(node)
            tproto = _type_protocol_attr_from_value(
                peeled,
                getattr_aliases=frozenset(getattr_aliases),
                protocol_products=type_protocol_products,
                type_aliases=frozenset(type_aliases),
            )
            if tproto is not None:
                return tproto
            if isinstance(peeled, ast.Name):
                return type_protocol_products.get(peeled.id)
            return None

        tproto = _type_protocol_from_fn(head)
        if tproto in {"__call__", "__new__"} or not isinstance(head, ast.Lambda):
            # ``key=type.__call__`` / Name / getattr / non-lambda applicators —
            # observe as ``fn(elem)`` via shared Call peel (``_scan_call`` is
            # resolved at call time from the enclosing scanner).
            observed_call = False
            for elem in elements:
                actuals = (
                    list(elem.elts)
                    if starmap and isinstance(elem, (ast.Tuple, ast.List))
                    else [elem]
                )
                synthetic = ast.Call(
                    func=fn,
                    args=list(actuals),
                    keywords=[],
                )
                _scan_call(
                    synthetic,
                    path=path,
                    index=index,
                    env=env,
                    visited_fns=visited_fns,
                    local_fns=local_fns,
                    local_classes=local_classes,
                )
                observed_call = True
            return observed_call

        formals = [a.arg for a in head.args.posonlyargs] + [
            a.arg for a in head.args.args
        ]
        if skip_first_formal and formals:
            # ``reduce(lambda a, f: …, iterable, init)`` — bind iterable to rest.
            formals = formals[1:]
        observed = False
        for elem in elements:
            bind: dict[str, ast.AST] = {}
            if starmap and isinstance(elem, (ast.Tuple, ast.List)):
                for formal, actual in zip(formals, elem.elts):
                    bind[formal] = actual
            elif formals:
                bind[formals[0]] = elem
            if not bind:
                continue
            observed = True
            _observe_subst_body(
                head.body,
                bind,
                path=path,
                index=index,
                env=env,
                visited_fns=visited_fns,
                local_fns=local_fns,
                local_classes=local_classes,
            )
        return observed

    def _observe_comprehension_applies(
        expr: ast.ListComp | ast.SetComp | ast.GeneratorExp | ast.DictComp,
        *,
        path: str,
        index: int,
        env: dict[str, _IdentityPointsTo],
        visited_fns: set[int],
        local_fns: Mapping[str, ast.FunctionDef | ast.AsyncFunctionDef] | None,
        local_classes: Mapping[str, ast.ClassDef] | None,
    ) -> None:
        """Apply comprehension / genexp element bodies with bound generators."""

        if len(expr.generators) != 1:
            return
        gen = expr.generators[0]
        elems = _iter_elements(gen.iter)
        if elems is None:
            return
        tail: ast.AST
        if isinstance(expr, ast.DictComp):
            # Observe both key and value positions.
            for elem in elems:
                bind = _destructure_target(gen.target, elem)
                if not bind:
                    continue
                for part in (expr.key, expr.value):
                    _observe_subst_body(
                        part,
                        bind,
                        path=path,
                        index=index,
                        env=env,
                        visited_fns=visited_fns,
                        local_fns=local_fns,
                        local_classes=local_classes,
                    )
                for if_clause in gen.ifs:
                    _observe_subst_body(
                        if_clause,
                        bind,
                        path=path,
                        index=index,
                        env=env,
                        visited_fns=visited_fns,
                        local_fns=local_fns,
                        local_classes=local_classes,
                    )
            return
        tail = expr.elt
        for elem in elems:
            bind = _destructure_target(gen.target, elem)
            if not bind:
                continue
            _observe_subst_body(
                tail,
                bind,
                path=path,
                index=index,
                env=env,
                visited_fns=visited_fns,
                local_fns=local_fns,
                local_classes=local_classes,
            )
            for if_clause in gen.ifs:
                _observe_subst_body(
                    if_clause,
                    bind,
                    path=path,
                    index=index,
                    env=env,
                    visited_fns=visited_fns,
                    local_fns=local_fns,
                    local_classes=local_classes,
                )

    def _destructure_target(
        target: ast.AST, elem: ast.AST
    ) -> dict[str, ast.AST]:
        """Bind comprehension / for targets to element expressions."""

        elem = _peel_call_func(elem)
        if isinstance(target, ast.Name):
            return {target.id: elem}
        if isinstance(target, ast.Starred):
            return _destructure_target(target.value, elem)
        if (
            isinstance(target, (ast.Tuple, ast.List))
            and isinstance(elem, (ast.Tuple, ast.List))
            and len(target.elts) == len(elem.elts)
            and not any(isinstance(e, ast.Starred) for e in elem.elts)
        ):
            bound: dict[str, ast.AST] = {}
            for sub_t, sub_e in zip(target.elts, elem.elts):
                bound.update(_destructure_target(sub_t, sub_e))
            return bound
        return {}

    def _mapping_items(
        expr: ast.AST, depth: int = 0
    ) -> list[tuple[ast.AST | None, ast.AST | None]] | None:
        """``(key_expr, value_expr)`` pairs for a resolvable mapping carrier.

        Resolves Dict literals (incl. ``**`` spreads and non-constant keys),
        mapping constructors (``dict`` / ``defaultdict`` / ``ChainMap`` / …),
        ``dict.fromkeys``, ``a | b`` / ``__or__`` / ``operator.or_`` merges,
        ``.copy()``, Name-bound packs, walrus, and DictComps. ``None`` means
        unresolved (callers must not claim the mapping is empty).
        """

        if depth > 8:
            return None
        expr = _peel_call_func(expr)
        nxt = depth + 1
        # Positional ``(kw if True else {})`` / ``(kw or {})`` into
        # ``update`` / ``|=`` / ``__ior__`` — share **spread peels
        # (Unknown > false PASS).
        if isinstance(expr, (ast.IfExp, ast.BoolOp)):
            merged: list[tuple[ast.AST | None, ast.AST | None]] = []
            resolved = False
            for arm in _iter_boolop_ifexp_arms(expr):
                sub = _mapping_items(arm, nxt)
                if sub is not None:
                    merged.extend(sub)
                    resolved = True
            return merged if resolved else None
        if isinstance(expr, ast.Dict):
            items: list[tuple[ast.AST | None, ast.AST | None]] = []
            for map_key, map_val in zip(expr.keys, expr.values):
                if map_val is None:
                    continue
                if map_key is None:
                    sub = _mapping_items(map_val, nxt)
                    if sub is None:
                        items.append((None, map_val))
                    else:
                        items.extend(sub)
                else:
                    items.append((map_key, map_val))
            return items
        if isinstance(expr, ast.Name):
            # Prefer sequence_view_aliases so Attribute values survive
            # (``fns={0:n.install}; list(fns.values())`` — name packs alone
            # collapse ``n.install`` to bare ``install``; Unknown > false PASS).
            # AugAssign merge must not install empty ``{}`` aliases (see
            # AugAssign BitOr/Add); when an alias is present, trust it.
            # List/Tuple/Set aliases are sequence carriers — not mappings —
            # so ``copy.copy(carrier)`` falls through to ``_iter_elements``
            # instead of collapsing to a Dict pack (Unknown > false PASS).
            aliased = sequence_view_aliases.get(expr.id)
            if aliased is not None:
                if isinstance(aliased, (ast.List, ast.Tuple, ast.Set)):
                    return None
                sub = _mapping_items(aliased, nxt)
                if sub is not None:
                    return sub
            pack = container_packs.get(expr.id)
            if pack is None:
                return None
            # Int-keyed packs are list/tuple carriers, not mappings.
            if pack and all(isinstance(k, int) for k in pack):
                return None
            named: list[tuple[ast.AST | None, ast.AST | None]] = []
            for key, names in pack.items():
                for pname in names:
                    node = ast.Name(id=pname, ctx=ast.Load())
                    if key is _KEYS_SLOT:
                        named.append((node, None))
                    elif isinstance(key, (str, int, float, bytes)):
                        named.append((ast.Constant(value=key), node))
                    else:
                        named.append((None, node))
            return named
        if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.BitOr):
            merged: list[tuple[ast.AST | None, ast.AST | None]] = []
            for side in (expr.left, expr.right):
                sub = _mapping_items(side, nxt)
                if sub is None:
                    merged.append((None, side))
                else:
                    merged.extend(sub)
            return merged
        if isinstance(expr, ast.DictComp):
            if len(expr.generators) != 1:
                return [(expr.key, expr.value)]
            gen = expr.generators[0]
            elems = _iter_elements(gen.iter, nxt)
            if elems is None:
                return [(expr.key, expr.value)]
            comp_items: list[tuple[ast.AST | None, ast.AST | None]] = []
            for elem in elems:
                bind = _destructure_target(gen.target, elem)
                comp_items.append(
                    (_subst_names(expr.key, bind), _subst_names(expr.value, bind))
                )
            return comp_items
        if isinstance(expr, ast.Subscript):
            # ``views[0].values()`` / ``copy.copy([d])[0].keys()`` — project
            # the indexed element then read it as a mapping (shared peel with
            # list-carrier ``[:]`` / ``.pop()`` / Name applicators).
            if isinstance(expr.slice, ast.Slice):
                return None
            key = _resolve_static_key_value(expr.slice)
            if key is not None:
                elem = _carrier_element_at(expr.value, key)
                if elem is not None:
                    return _mapping_items(elem, nxt)
            return None
        if not isinstance(expr, ast.Call):
            return None
        func = _peel_call_func(expr.func)
        if _is_dict_constructor(
            func,
            dict_ctor_aliases=frozenset(dict_ctor_aliases),
            getattr_aliases=frozenset(getattr_aliases),
        ):
            ctor_items: list[tuple[ast.AST | None, ast.AST | None]] = []
            for kw in expr.keywords:
                if kw.arg is None:
                    sub = _mapping_items(kw.value, nxt)
                    if sub is None:
                        ctor_items.append((None, kw.value))
                    else:
                        ctor_items.extend(sub)
                else:
                    ctor_items.append((ast.Constant(value=kw.arg), kw.value))
            for arg in expr.args:
                nested = arg.value if isinstance(arg, ast.Starred) else arg
                if isinstance(nested, ast.Constant):
                    continue
                sub = _mapping_items(nested, nxt)
                if sub is not None:
                    ctor_items.extend(sub)
                    continue
                # ``dict([("c", Mut)])`` — iterable of key/value pairs.
                pairs = _iter_elements(nested, nxt)
                if pairs is None:
                    ctor_items.append((None, nested))
                    continue
                for pair in pairs:
                    pair = _peel_call_func(pair)
                    if isinstance(pair, (ast.Tuple, ast.List)) and len(pair.elts) == 2:
                        ctor_items.append((pair.elts[0], pair.elts[1]))
                    else:
                        ctor_items.append((None, pair))
            return ctor_items
        if _is_dict_fromkeys(
            func,
            dict_ctor_aliases=frozenset(dict_ctor_aliases),
            dict_view_products=dict_view_products,
        ):
            value = expr.args[1] if len(expr.args) >= 2 else None
            keys = _iter_elements(expr.args[0], nxt) if expr.args else None
            if keys is None:
                return [(None, value)] if value is not None else []
            return [(key, value) for key in keys]
        view = _view_call_parts(expr)
        if view is not None:
            attr, recv = view
            if attr in _MAPPING_COPY_FUNCS:
                # Bound ``d.copy()`` vs module ``copy.copy(d)`` /
                # ``cp.copy(d)`` / ``getattr(copy, "copy")(d)`` /
                # ``dict.copy(d)`` / ``getattr(dict, "copy")(d)``.
                if expr.args and (
                    (
                        isinstance(recv, ast.Name)
                        and recv.id in copy_module_aliases | _MAPPING_COPY_FUNCS
                    )
                    or (
                        isinstance(recv, ast.Attribute)
                        and recv.attr in _MAPPING_COPY_FUNCS | {"copy"}
                    )
                    or _is_dict_constructor(
                        recv,
                        dict_ctor_aliases=frozenset(dict_ctor_aliases),
                        getattr_aliases=frozenset(getattr_aliases),
                    )
                ):
                    return _mapping_items(expr.args[0], nxt)
                return _mapping_items(recv, nxt)
            if attr == "new_child":
                # ``ChainMap().new_child({"e": exec})`` — child mapping first.
                out_nc: list[tuple[ast.AST | None, ast.AST | None]] = []
                for side in (*expr.args, recv):
                    sub = _mapping_items(side, nxt)
                    if sub is None:
                        out_nc.append((None, side))
                    else:
                        out_nc.extend(sub)
                return out_nc
            if attr in _MAPPING_MERGE_METHODS:
                out: list[tuple[ast.AST | None, ast.AST | None]] = []
                for side in (recv, *expr.args):
                    sub = _mapping_items(side, nxt)
                    if sub is None:
                        out.append((None, side))
                    else:
                        out.extend(sub)
                return out
        proj_name = _projection_factory_name(
            expr,
            projection_aliases=operator_projection_aliases,
            getattr_aliases=frozenset(getattr_aliases),
        )
        if proj_name in _MAPPING_COPY_FUNCS and expr.args:
            # ``copy.copy|deepcopy(x)`` / ``from copy import copy as c; c(x)`` —
            # peel the single operand; return None for list carriers so
            # ``_iter_elements`` preserves sequence structure.
            return _mapping_items(expr.args[0], nxt)
        if proj_name in _MAPPING_MERGE_FUNCS:
            out = []
            for side in expr.args:
                sub = _mapping_items(side, nxt)
                if sub is None:
                    out.append((None, side))
                else:
                    out.extend(sub)
            return out
        # ``copy.copy(d)`` / ``copy.deepcopy(d)`` / Name-bound copy aliases.
        if (
            isinstance(func, ast.Name)
            and (
                func.id in _MAPPING_COPY_FUNCS
                or func.id in adapter_aliases
                or operator_projection_aliases.get(func.id) in _MAPPING_COPY_FUNCS
            )
            and expr.args
        ):
            return _mapping_items(expr.args[0], nxt)
        if (
            isinstance(func, ast.Attribute)
            and func.attr in _MAPPING_COPY_FUNCS
            and expr.args
        ):
            return _mapping_items(expr.args[0], nxt)
        # ``methodcaller("copy")(d)`` / getattr / Name-bound methodcaller product.
        mc: str | None = None
        if isinstance(func, ast.Call):
            mc = _methodcaller_static_name(
                func,
                projection_aliases=operator_projection_aliases,
                getattr_aliases=frozenset(getattr_aliases),
            )
        elif isinstance(func, ast.Name):
            product = projection_factory_products.get(func.id)
            if product is not None and product[0] == "methodcaller":
                mc = product[1]
        if mc in _MAPPING_COPY_FUNCS and expr.args:
            return _mapping_items(expr.args[0], nxt)
        # ``partial(copy.copy)(d)`` / ``partial(copy.copy, d)()`` /
        # ``partial(getattr(copy,"copy"))(d)`` / Name-bound products.
        partial_call: ast.Call | None = None
        if isinstance(func, ast.Call) and _is_partial_factory(
            func,
            partial_aliases=frozenset(partial_aliases),
            getattr_aliases=frozenset(getattr_aliases),
        ):
            partial_call = func
        elif isinstance(func, ast.Name):
            product = projection_factory_products.get(func.id)
            if product is not None and product[0] == "partial":
                # Recover bound mapping from Name-bound partial when zero-arg.
                for pname in partial_product_names.get(func.id, []):
                    if pname in _MAPPING_COPY_FUNCS and expr.args:
                        return _mapping_items(expr.args[0], nxt)
                bound_map = partial_bound_mappings.get(func.id)
                if bound_map is not None and not expr.args:
                    return _mapping_items(bound_map, nxt)
        if partial_call is not None and partial_call.args:
            bound = _peel_call_func(partial_call.args[0])
            bound_is_copy = (
                (
                    isinstance(bound, ast.Attribute)
                    and bound.attr in _MAPPING_COPY_FUNCS
                )
                or (
                    isinstance(bound, ast.Name)
                    and (
                        bound.id in _MAPPING_COPY_FUNCS
                        or operator_projection_aliases.get(bound.id)
                        in _MAPPING_COPY_FUNCS
                    )
                )
                or (
                    isinstance(bound, ast.Call)
                    and _getattr_static_name(
                        bound, getattr_aliases=frozenset(getattr_aliases)
                    )
                    in _MAPPING_COPY_FUNCS
                )
            )
            if bound_is_copy:
                if expr.args:
                    return _mapping_items(expr.args[0], nxt)
                if len(partial_call.args) >= 2:
                    return _mapping_items(partial_call.args[1], nxt)
        # Packed ``[copy.copy][0](d)`` / ``[methodcaller("copy")][0](d)`` /
        # ``[partial(copy.copy)][0](d)`` / ``next(iter([copy.copy]))(d)``.
        for cand in _callee_candidate_exprs(expr.func):
            cand = _peel_call_func(cand)
            if isinstance(cand, ast.Attribute) and cand.attr in _MAPPING_COPY_FUNCS:
                if expr.args:
                    return _mapping_items(expr.args[0], nxt)
            if isinstance(cand, ast.Name) and (
                cand.id in _MAPPING_COPY_FUNCS
                or operator_projection_aliases.get(cand.id) in _MAPPING_COPY_FUNCS
            ):
                if expr.args:
                    return _mapping_items(expr.args[0], nxt)
            if isinstance(cand, ast.Call):
                cand_mc = _methodcaller_static_name(
                    cand,
                    projection_aliases=operator_projection_aliases,
                    getattr_aliases=frozenset(getattr_aliases),
                )
                if cand_mc in _MAPPING_COPY_FUNCS:
                    # Bound ``methodcaller("copy")(d)`` / zero-arg when
                    # the mapping was closed over earlier is not applicable;
                    # mapping is always the applied arg.
                    if expr.args:
                        return _mapping_items(expr.args[0], nxt)
                if _is_partial_factory(
                    cand,
                    partial_aliases=frozenset(partial_aliases),
                    getattr_aliases=frozenset(getattr_aliases),
                ) and cand.args:
                    bound = _peel_call_func(cand.args[0])
                    bound_is_copy = False
                    if (
                        isinstance(bound, ast.Attribute)
                        and bound.attr in _MAPPING_COPY_FUNCS
                    ):
                        bound_is_copy = True
                    elif isinstance(bound, ast.Name) and (
                        bound.id in _MAPPING_COPY_FUNCS
                        or operator_projection_aliases.get(bound.id)
                        in _MAPPING_COPY_FUNCS
                    ):
                        bound_is_copy = True
                    elif isinstance(bound, ast.Call):
                        # ``partial(getattr(copy, "copy"))`` / deepcopy /
                        # ``partial(methodcaller("copy"))``.
                        gcopy = _getattr_static_name(
                            bound, getattr_aliases=frozenset(getattr_aliases)
                        )
                        if gcopy in _MAPPING_COPY_FUNCS:
                            bound_is_copy = True
                        elif (
                            _methodcaller_static_name(
                                bound,
                                projection_aliases=operator_projection_aliases,
                                getattr_aliases=frozenset(getattr_aliases),
                            )
                            in _MAPPING_COPY_FUNCS
                        ):
                            bound_is_copy = True
                    if bound_is_copy:
                        # ``partial(copy.copy)(d)`` / ``partial(copy.copy, d)()``.
                        if expr.args:
                            return _mapping_items(expr.args[0], nxt)
                        if len(cand.args) >= 2:
                            return _mapping_items(cand.args[1], nxt)
            if isinstance(cand, ast.Name):
                product = projection_factory_products.get(cand.id)
                if (
                    product is not None
                    and product[0] == "methodcaller"
                    and product[1] in _MAPPING_COPY_FUNCS
                    and expr.args
                ):
                    return _mapping_items(expr.args[0], nxt)
                if product is not None and product[0] == "partial":
                    for pname in partial_product_names.get(cand.id, []):
                        if pname in _MAPPING_COPY_FUNCS and expr.args:
                            return _mapping_items(expr.args[0], nxt)
        # ``MappingProxyType(d)`` and renamed adapters wrap a mapping.
        if (
            isinstance(func, ast.Name)
            and (func.id == "MappingProxyType" or func.id in adapter_aliases)
        ) or (isinstance(func, ast.Attribute) and func.attr == "MappingProxyType"):
            if expr.args:
                return _mapping_items(expr.args[0], nxt)
        return None

    def _iter_elements(expr: ast.AST, depth: int = 0) -> list[ast.AST] | None:
        """Expressions yielded by iterating ``expr``; ``None`` when unresolved.

        One shared element resolver for For targets, Assign / star unpack and
        Match sequence subjects: literal containers, Name-bound packs, dict
        ``keys`` / ``values`` / ``items`` views (also via ``getattr``),
        ``list`` / ``iter`` / ``sorted`` / ``reversed`` adapters, ``map`` /
        ``filter`` / ``zip`` / ``enumerate``, and comprehensions / generators
        (Unknown > false PASS).
        """

        if depth > 8:
            return None
        expr = _peel_call_func(expr)
        nxt = depth + 1
        # BoolOp/IfExp wrappers around iadd/iconcat / containers (CF For/Match).
        if isinstance(expr, ast.IfExp):
            left = _iter_elements(expr.body, nxt) or []
            right = _iter_elements(expr.orelse, nxt) or []
            return [*left, *right] if (left or right) else None
        if isinstance(expr, ast.BoolOp):
            out_bo: list[ast.AST] = []
            resolved_bo = False
            for value in expr.values:
                sub = _iter_elements(value, nxt)
                if sub is not None:
                    resolved_bo = True
                    out_bo.extend(sub)
            return out_bo if resolved_bo else None
        if isinstance(expr, ast.BinOp) and isinstance(expr.op, (ast.Add, ast.Mult)):
            # ``([partial(...)] + [])[0]`` / ``([p] * 1)[0]`` carriers.
            left = _iter_elements(expr.left, nxt) or []
            if isinstance(expr.op, ast.Mult):
                return left if left else None
            right = _iter_elements(expr.right, nxt) or []
            return [*left, *right] if (left or right) else None
        if isinstance(expr, (ast.List, ast.Tuple, ast.Set)):
            out: list[ast.AST] = []
            for elt in expr.elts:
                if isinstance(elt, ast.Starred):
                    sub = _iter_elements(elt.value, nxt)
                    out.extend(sub if sub is not None else [elt.value])
                else:
                    out.append(elt)
            return out
        if isinstance(expr, ast.Dict):
            keys: list[ast.AST] = []
            for map_key, map_val in zip(expr.keys, expr.values):
                if map_key is None:
                    if map_val is None:
                        continue
                    sub = _iter_elements(map_val, nxt)
                    keys.extend(sub if sub is not None else [map_val])
                else:
                    keys.append(map_key)
            return keys
        if isinstance(expr, ast.Name):
            # Preserve keys/values/items / next(iter) structure for unpack seeds.
            aliased = sequence_view_aliases.get(expr.id)
            if aliased is not None:
                return _iter_elements(aliased, nxt)
            pack = container_packs.get(expr.id)
            if pack is None:
                return None
            return [
                ast.Name(id=pname, ctx=ast.Load()) for pname in _flat_pack_names(pack)
            ]
        # ``cm.maps[i]`` / ``cm.parents[i]`` — ChainMap internal mapping lists.
        if isinstance(expr, ast.Subscript):
            base = _peel_call_func(expr.value)
            # Sequence slices ``xs[:]`` / ``xs[:1]`` / ``xs[0:1]`` / ``xs[::]``
            # / ``xs[slice(...)]`` / ``xs[s]`` / ``copy.copy(xs)[:]`` preserve
            # packed elements for later ``[0]`` peels (Unknown > false PASS).
            if _slice_key(expr.slice):
                return _iter_elements(expr.value, nxt)
            if isinstance(base, ast.Attribute) and base.attr in {"maps", "parents"}:
                # One child mapping carrier: peel the ChainMap constructor args /
                # Name pack as a mapping (``cm.maps[0]`` may-alias any child).
                items = _mapping_items(base.value, nxt)
                if items is None:
                    return [base.value]
                return [
                    ast.Dict(
                        keys=[k for k, _ in items],
                        values=[
                            v if v is not None else ast.Constant(value=None)
                            for _, v in items
                        ],
                    )
                ]
            # Indexed peel: ``list(d.values())[0]`` / ``views[0]`` /
            # ``copy.copy([d])[0]`` — share ``_carrier_element_at`` so Tuple
            # unpack ``C, = …[0]`` observes the same element as Name assign.
            key = _resolve_static_key_value(expr.slice)
            if key is not None:
                elem = _carrier_element_at(expr.value, key)
                if elem is not None:
                    return [elem]
            if isinstance(base, ast.Name) and base.id in container_packs:
                pack = container_packs[base.id]
                if key in pack:
                    return [
                        ast.Name(id=n, ctx=ast.Load()) for n in pack[key]
                    ]
        if isinstance(
            expr, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)
        ):
            tail = expr.key if isinstance(expr, ast.DictComp) else expr.elt
            if len(expr.generators) != 1:
                return [tail]
            gen = expr.generators[0]
            elems = _iter_elements(gen.iter, nxt)
            if elems is None:
                return [tail]
            produced: list[ast.AST] = []
            for elem in elems:
                bind = _destructure_target(gen.target, elem)
                produced.append(_subst_names(tail, bind))
            return produced
        if not isinstance(expr, ast.Call):
            return None
        func = _peel_call_func(expr.func)
        # ``operator.iadd|iconcat(xs, [exec])`` / ``xs.__iadd__([exec])`` —
        # CF For.iter / Match.subject observe the merged element pack.
        proj = _projection_factory_name(
            expr,
            projection_aliases=operator_projection_aliases,
            getattr_aliases=frozenset(getattr_aliases),
        )
        if proj in {"iadd", "iconcat", "concat", "add"} and len(expr.args) >= 2:
            left = _iter_elements(expr.args[0], nxt) or []
            right = _iter_elements(expr.args[1], nxt) or []
            return [*left, *right] if (left or right) else None
        # ``operator.getitem(xs, slice(...))`` / Name-bound getitem with a
        # slice key — packing-transparent like ``xs[slice(...)]``.
        if proj == "getitem" and len(expr.args) >= 2 and _slice_key(expr.args[1]):
            return _iter_elements(expr.args[0], nxt)
        if proj == "getitem" and len(expr.args) >= 2:
            # Index-only ``operator.getitem(xs, 0)`` packing sibling.
            key = _resolve_static_key_value(expr.args[1])
            if key is None:
                key = _static_sequence_index(expr.args[1])
            elem = _carrier_element_at(expr.args[0], key)
            if elem is not None:
                return [elem]
        # Zero-arg / one-arg ``partial(operator.getitem, xs, slice|idx)()`` /
        # ``partial(list.__getitem__, xs, slice)()`` /
        # ``partial(operator.getitem, xs)(slice)`` /
        # ``partial(methodcaller("__getitem__", slice), xs)()``.
        for cand in _callee_candidate_exprs(expr.func):
            cand = _peel_call_func(cand)
            if not (
                isinstance(cand, ast.Call)
                and _is_partial_factory(
                    cand,
                    partial_aliases=frozenset(partial_aliases),
                    getattr_aliases=frozenset(getattr_aliases),
                )
                and cand.args
            ):
                continue
            bound0 = _peel_call_func(cand.args[0])
            is_gi = False
            is_list_gi = False
            mc_gi_key: ast.AST | None = None
            if isinstance(bound0, ast.Name) and (
                bound0.id == "getitem"
                or operator_projection_aliases.get(bound0.id) == "getitem"
            ):
                is_gi = True
            elif isinstance(bound0, ast.Attribute) and (
                bound0.attr == "getitem"
                or _canonical_projection_name(bound0.attr) == "getitem"
            ):
                is_gi = True
            elif isinstance(bound0, ast.Attribute) and bound0.attr == "__getitem__":
                if _is_unbound_list_recv(bound0.value) or (
                    isinstance(_peel_call_func(bound0.value), ast.Name)
                    and _peel_call_func(bound0.value).id == "list"  # type: ignore[union-attr]
                ):
                    is_list_gi = True
                else:
                    is_gi = True
            elif isinstance(bound0, ast.Call):
                gname = _getattr_static_name(
                    bound0, getattr_aliases=frozenset(getattr_aliases)
                )
                if gname == "getitem" or _canonical_projection_name(gname) == "getitem":
                    is_gi = True
                elif gname == "__getitem__" and bound0.args:
                    # Bound ``getattr(xs,"__getitem__")`` vs unbound
                    # ``getattr(list,"__getitem__")``.
                    if _is_unbound_list_recv(bound0.args[0]) or (
                        isinstance(_peel_call_func(bound0.args[0]), ast.Name)
                        and _peel_call_func(bound0.args[0]).id  # type: ignore[union-attr]
                        == "list"
                    ):
                        is_list_gi = True
                    else:
                        is_gi = True
                else:
                    mc = _methodcaller_static_name(
                        bound0,
                        projection_aliases=operator_projection_aliases,
                        getattr_aliases=frozenset(getattr_aliases),
                    )
                    if mc == "__getitem__" and len(bound0.args) >= 2:
                        is_gi = True
                        mc_gi_key = bound0.args[1]
            # ``args=(getitem, xs, slice); partial(*args)()`` — resolve
            # Name-bound tuple/list star packs onto the shared getitem peel
            # before the bare-bound0 gate (Starred is not a getitem Name).
            if (
                len(cand.args) == 1
                and isinstance(cand.args[0], ast.Starred)
                and not expr.args
            ):
                star = _peel_call_func(cand.args[0].value)
                star_elts: list[ast.AST] | None = None
                if isinstance(star, (ast.Tuple, ast.List)):
                    star_elts = list(star.elts)
                elif isinstance(star, ast.Name):
                    aliased = sequence_view_aliases.get(star.id)
                    if isinstance(aliased, (ast.Tuple, ast.List)):
                        star_elts = list(aliased.elts)
                    else:
                        star_elts = _iter_elements(star)
                if star_elts is not None and len(star_elts) >= 3:
                    head = _peel_call_func(star_elts[0])
                    head_gi = (
                        (
                            isinstance(head, ast.Name)
                            and (
                                head.id == "getitem"
                                or operator_projection_aliases.get(head.id)
                                == "getitem"
                            )
                        )
                        or (
                            isinstance(head, ast.Attribute)
                            and (
                                head.attr == "getitem"
                                or _canonical_projection_name(head.attr)
                                == "getitem"
                            )
                        )
                    )
                    if head_gi:
                        carrier = star_elts[1]
                        key_node = star_elts[2]
                        if _slice_key(key_node):
                            return _iter_elements(carrier, nxt)
                        key = _resolve_static_key_value(key_node)
                        if key is None:
                            key = _static_sequence_index(key_node)
                        elem = _carrier_element_at(carrier, key)
                        if elem is not None:
                            return [elem]
            # Nested ``partial(partial(getitem, xs), slice)()`` — peel inner
            # partial factory onto the shared getitem path.
            if (
                not (is_gi or is_list_gi)
                and isinstance(bound0, ast.Call)
                and _is_partial_factory(
                    bound0,
                    partial_aliases=frozenset(partial_aliases),
                    getattr_aliases=frozenset(getattr_aliases),
                )
                and bound0.args
            ):
                inner0 = _peel_call_func(bound0.args[0])
                if isinstance(inner0, ast.Name) and (
                    inner0.id == "getitem"
                    or operator_projection_aliases.get(inner0.id) == "getitem"
                ):
                    is_gi = True
                elif isinstance(inner0, ast.Attribute) and (
                    inner0.attr == "getitem"
                    or _canonical_projection_name(inner0.attr) == "getitem"
                ):
                    is_gi = True
                elif isinstance(inner0, ast.Call):
                    g_inner = _getattr_static_name(
                        inner0, getattr_aliases=frozenset(getattr_aliases)
                    )
                    if g_inner == "getitem" or _canonical_projection_name(
                        g_inner
                    ) == "getitem":
                        is_gi = True
                if is_gi and len(bound0.args) >= 2 and len(cand.args) >= 2 and not expr.args:
                    carrier = bound0.args[1]
                    key_node = cand.args[1]
                    if _slice_key(key_node):
                        return _iter_elements(carrier, nxt)
                    key = _resolve_static_key_value(key_node)
                    if key is None:
                        key = _static_sequence_index(key_node)
                    elem = _carrier_element_at(carrier, key)
                    if elem is not None:
                        return [elem]
            if not (is_gi or is_list_gi):
                continue
            if mc_gi_key is not None and len(cand.args) >= 2 and not expr.args:
                # ``partial(methodcaller("__getitem__", slice), xs)()``.
                carrier = cand.args[1]
                if _slice_key(mc_gi_key):
                    return _iter_elements(carrier, nxt)
                key = _resolve_static_key_value(mc_gi_key)
                if key is None:
                    key = _static_sequence_index(mc_gi_key)
                elem = _carrier_element_at(carrier, key)
                if elem is not None:
                    return [elem]
            # Bound ``partial(xs.__getitem__, slice|idx)()`` /
            # ``partial(getattr(xs,"__getitem__"), slice)()`` — carrier is the
            # Attribute / getattr receiver; key is the first partial-bound arg.
            bound_gi_recv: ast.AST | None = None
            if (
                isinstance(bound0, ast.Attribute)
                and bound0.attr == "__getitem__"
                and not _is_unbound_list_recv(bound0.value)
            ):
                bound_gi_recv = bound0.value
            elif isinstance(bound0, ast.Call):
                g_bound = _getattr_static_name(
                    bound0, getattr_aliases=frozenset(getattr_aliases)
                )
                if (
                    g_bound == "__getitem__"
                    and bound0.args
                    and not _is_unbound_list_recv(bound0.args[0])
                ):
                    bound_gi_recv = bound0.args[0]
            if (
                bound_gi_recv is not None
                and len(cand.args) >= 2
                and not expr.args
            ):
                carrier = bound_gi_recv
                key_node = cand.args[1]
                if _slice_key(key_node):
                    return _iter_elements(carrier, nxt)
                key = _resolve_static_key_value(key_node)
                if key is None:
                    key = _static_sequence_index(key_node)
                elem = _carrier_element_at(carrier, key)
                if elem is not None:
                    return [elem]
            if len(cand.args) >= 3 and not expr.args:
                # ``partial(getitem|list.__getitem__, xs, slice|idx)()``.
                carrier = cand.args[1]
                key_node = cand.args[2]
                if _slice_key(key_node):
                    return _iter_elements(carrier, nxt)
                key = _resolve_static_key_value(key_node)
                if key is None:
                    key = _static_sequence_index(key_node)
                elem = _carrier_element_at(carrier, key)
                if elem is not None:
                    return [elem]
            if len(cand.args) >= 2 and len(expr.args) >= 1:
                # ``partial(getitem, xs)(slice|idx)``.
                carrier = cand.args[1]
                key_node = expr.args[0]
                if _slice_key(key_node):
                    return _iter_elements(carrier, nxt)
                key = _resolve_static_key_value(key_node)
                if key is None:
                    key = _static_sequence_index(key_node)
                elem = _carrier_element_at(carrier, key)
                if elem is not None:
                    return [elem]
        view = _view_call_parts(expr)
        if view is not None:
            attr, recv = view
            if attr in {"keys", "values", "items", "popitem"}:
                items = _mapping_items(recv, nxt)
                if items is None:
                    return None
                if attr == "keys":
                    return [k for k, _ in items if k is not None]
                if attr == "values":
                    return [v for _, v in items if v is not None]
                if attr == "popitem":
                    # ``popitem()`` yields one ``(key, value)`` pair.
                    pairs = [
                        ast.Tuple(
                            elts=[
                                k if k is not None else ast.Constant(value=None),
                                v if v is not None else ast.Constant(value=None),
                            ],
                            ctx=ast.Load(),
                        )
                        for k, v in items
                    ]
                    return pairs[:1] if pairs else None
                return [
                    ast.Tuple(
                        elts=[
                            k if k is not None else ast.Constant(value=None),
                            v if v is not None else ast.Constant(value=None),
                        ],
                        ctx=ast.Load(),
                    )
                    for k, v in items
                ]
            if attr in _MAPPING_COPY_FUNCS:
                # Bound ``d.copy()`` / module ``copy.copy|deepcopy(d)`` /
                # list-carrier ``copy.copy([…])`` (Unknown > false PASS).
                return _iter_elements(recv, nxt)
            if attr == "pop":
                # ``views.pop()`` / ``views.pop(-1)`` / ``views.pop(~0)`` /
                # ``list.pop(views, -1)`` on a list carrier yields one element
                # (Unknown > false PASS). Mapping ``d.pop(key)`` with a
                # non-int key stays on the view path; bare / negative /
                # bitwise last-element peels share the sequence form.
                unbound_list = (
                    (
                        isinstance(recv, ast.Name)
                        and (
                            recv.id == "list"
                            or operator_projection_aliases.get(recv.id) == "list"
                            or recv.id in dict_ctor_aliases
                        )
                    )
                    or (
                        isinstance(recv, ast.Attribute) and recv.attr == "list"
                    )
                )
                pop_carrier: ast.AST | None = None
                pop_idx: int | None = None
                if unbound_list and expr.args:
                    pop_carrier = expr.args[0]
                    pop_idx = (
                        _static_sequence_index(expr.args[1])
                        if len(expr.args) >= 2
                        else -1
                    )
                elif not expr.args:
                    pop_carrier = recv
                    pop_idx = -1
                elif len(expr.args) == 1:
                    pop_idx = _static_sequence_index(expr.args[0])
                    if pop_idx is not None:
                        pop_carrier = recv
                if pop_carrier is not None and pop_idx is not None:
                    elems = _iter_elements(pop_carrier, nxt)
                    if elems is None:
                        return None
                    if not elems:
                        return []
                    try:
                        return [elems[pop_idx]]
                    except IndexError:
                        return elems[-1:]
            if attr == "__getitem__" and expr.args:
                # ``views.__getitem__(0)`` / ``xs.__getitem__(slice(...))`` /
                # ``list.__getitem__(xs, slice(...))`` / methodcaller peels.
                if _slice_key(expr.args[0]):
                    return _iter_elements(recv, nxt)
                # Unbound ``list.__getitem__(xs, slice|idx)``.
                unbound_list_gi = (
                    (
                        isinstance(recv, ast.Name)
                        and (
                            recv.id == "list"
                            or operator_projection_aliases.get(recv.id) == "list"
                            or recv.id in dict_ctor_aliases
                        )
                    )
                    or (
                        isinstance(recv, ast.Attribute) and recv.attr == "list"
                    )
                )
                if unbound_list_gi and len(expr.args) >= 2:
                    if _slice_key(expr.args[1]):
                        return _iter_elements(expr.args[0], nxt)
                    key = _resolve_static_key_value(expr.args[1])
                    if key is None:
                        key = _static_sequence_index(expr.args[1])
                    elem = _carrier_element_at(expr.args[0], key)
                    if elem is not None:
                        return [elem]
                key = _resolve_static_key_value(expr.args[0])
                if key is None:
                    key = _static_sequence_index(expr.args[0])
                elem = _carrier_element_at(recv, key)
                if elem is not None:
                    return [elem]
            if attr == "fromkeys":
                # Unbound / Name-bound ``fromkeys(iterable)`` — recv is iterable.
                return _iter_elements(recv, nxt)
            if attr == "__iter__":
                # ``k().__iter__()`` ≡ iterate ``k()`` (shared peel).
                return _iter_elements(recv, nxt)
            if attr in {"__iadd__", "__iconcat__", "__add__"}:
                # Bound ``xs.__iadd__([exec])`` / ``[p].__add__([])`` /
                # unbound ``list.__iadd__(xs, …)``.
                if (
                    _is_dict_constructor(
                        recv,
                        dict_ctor_aliases=frozenset(dict_ctor_aliases),
                        getattr_aliases=frozenset(getattr_aliases),
                    )
                    or (
                        isinstance(recv, ast.Name)
                        and recv.id in {"list", "set", "tuple", "dict"}
                    )
                    or (
                        isinstance(recv, ast.Attribute)
                        and recv.attr in {"list", "set", "tuple", "dict"}
                    )
                ):
                    if len(expr.args) >= 2:
                        left = _iter_elements(expr.args[0], nxt) or []
                        right = _iter_elements(expr.args[1], nxt) or []
                        return [*left, *right] if (left or right) else None
                elif expr.args:
                    left = _iter_elements(recv, nxt) or []
                    right = _iter_elements(expr.args[0], nxt) or []
                    return [*left, *right] if (left or right) else None
            if attr == "values" and not expr.args:
                # ``{0: p}.values()`` / Name-bound dict values carrier.
                items = _mapping_items(recv, nxt)
                if items is not None:
                    return [v for _, v in items if v is not None]
            if attr in _MAPPING_COPY_FUNCS:
                # Module ``copy.copy|deepcopy(xs)`` /
                # ``getattr(copy,"deepcopy")(xs)`` /
                # ``(0 or getattr(copy,"deepcopy"))(xs)`` /
                # ``[getattr…][0](xs)`` — peel the applied arg.
                # Bound ``d.copy()`` / ``xs.copy()`` — peel the receiver.
                # Shared with ``_mapping_items`` (Unknown > false PASS).
                recv_peel = _peel_call_func(recv)
                if expr.args and (
                    (
                        isinstance(recv_peel, ast.Name)
                        and recv_peel.id
                        in copy_module_aliases | _MAPPING_COPY_FUNCS
                    )
                    or (
                        isinstance(recv_peel, ast.Attribute)
                        and recv_peel.attr in _MAPPING_COPY_FUNCS | {"copy"}
                    )
                    or _is_dict_constructor(
                        recv_peel,
                        dict_ctor_aliases=frozenset(dict_ctor_aliases),
                        getattr_aliases=frozenset(getattr_aliases),
                    )
                ):
                    return _iter_elements(expr.args[0], nxt)
                return _iter_elements(recv, nxt)
        # ``methodcaller("keys|values|popitem|copy|pop|__getitem__")(e)`` /
        # packed ``[methodcaller("keys")][0](e)`` / Name-bound products.
        mc: str | None = None
        mc_factory: ast.Call | None = None
        if isinstance(func, ast.Call):
            mc = _methodcaller_static_name(
                func, projection_aliases=operator_projection_aliases
            )
            if mc is not None:
                mc_factory = func
        elif isinstance(func, ast.Name):
            product = projection_factory_products.get(func.id)
            if product is not None and product[0] == "methodcaller":
                mc = product[1]
        if mc is None:
            for cand in _callee_candidate_exprs(expr.func):
                cand = _peel_call_func(cand)
                if isinstance(cand, ast.Call):
                    mc = _methodcaller_static_name(
                        cand, projection_aliases=operator_projection_aliases
                    )
                    if mc is not None:
                        mc_factory = cand
                elif isinstance(cand, ast.Name):
                    product = projection_factory_products.get(cand.id)
                    if product is not None and product[0] == "methodcaller":
                        mc = product[1]
                if mc in {
                    "keys",
                    "values",
                    "items",
                    "popitem",
                    "copy",
                    "pop",
                    "__getitem__",
                }:
                    break
                mc = None
                mc_factory = None
        if mc in {"keys", "values", "items", "popitem", "copy"} and expr.args:
            synthetic = ast.Call(
                func=ast.Attribute(
                    value=expr.args[0], attr=mc, ctx=ast.Load()
                ),
                args=[],
                keywords=[],
            )
            return _iter_elements(synthetic, nxt)
        if mc in {"pop", "__getitem__"} and expr.args:
            # ``methodcaller("pop", -1)(views)`` /
            # ``methodcaller("__getitem__", 0)(views)`` — share sequence peels.
            syn_args = list(mc_factory.args[1:]) if mc_factory is not None else []
            synthetic = ast.Call(
                func=ast.Attribute(
                    value=expr.args[0], attr=mc, ctx=ast.Load()
                ),
                args=syn_args,
                keywords=[],
            )
            return _iter_elements(synthetic, nxt)
        func_name: str | None = None
        if isinstance(func, ast.Name):
            # Name-bound ``ch = itertools.chain`` / adapter aliases share one peel.
            func_name = operator_projection_aliases.get(func.id, func.id)
            if func.id in adapter_aliases:
                func_name = operator_projection_aliases.get(func.id, func.id)
        elif isinstance(func, ast.Attribute):
            func_name = func.attr
        adapter_name = _itertools_adapter_name(
            func,
            projection_aliases=operator_projection_aliases,
            getattr_aliases=frozenset(getattr_aliases),
        )
        if adapter_name is not None:
            func_name = adapter_name
        if func_name in {
            "list",
            "tuple",
            "set",
            "frozenset",
            "sorted",
            "reversed",
            "iter",
            "next",
        } and expr.args:
            first = expr.args[0]
            # ``next(iter(...))`` / ``next(reversed(...))`` yield one element.
            if func_name == "next":
                sub = _iter_elements(
                    first.value if isinstance(first, ast.Starred) else first, nxt
                )
                if sub is None:
                    return None
                return sub[:1]
            return _iter_elements(
                first.value if isinstance(first, ast.Starred) else first, nxt
            )
        # ``copy.copy|deepcopy(xs)`` / ``from copy import copy as c; c(xs)`` /
        # Name-bound ``fn=copy.copy; fn(xs)`` / packed ``[copy.copy][0](xs)`` /
        # ``(0 or getattr(copy,"deepcopy"))(xs)`` / ``[getattr…][0](xs)``.
        if func_name in _MAPPING_COPY_FUNCS and expr.args:
            return _iter_elements(expr.args[0], nxt)
        # Shared shallow peel before candidate recursion so BoolOp / IfExp /
        # Subscript getattr(copy, …) factories do not miss the copy path.
        if expr.args:
            for cand in _shallow_packed_callee_exprs(expr.func):
                cand = _peel_call_func(cand)
                shallow_copy: str | None = None
                if isinstance(cand, ast.Attribute) and cand.attr in _MAPPING_COPY_FUNCS:
                    shallow_copy = cand.attr
                elif isinstance(cand, ast.Name) and (
                    cand.id in _MAPPING_COPY_FUNCS
                    or operator_projection_aliases.get(cand.id) in _MAPPING_COPY_FUNCS
                ):
                    shallow_copy = operator_projection_aliases.get(cand.id, cand.id)
                elif isinstance(cand, ast.Call):
                    shallow_copy = _getattr_static_name(
                        cand, getattr_aliases=frozenset(getattr_aliases)
                    )
                    if shallow_copy not in _MAPPING_COPY_FUNCS:
                        shallow_copy = None
                if shallow_copy in _MAPPING_COPY_FUNCS:
                    return _iter_elements(expr.args[0], nxt)
        if func_name is None:
            for cand in _callee_candidate_exprs(expr.func):
                cand = _peel_call_func(cand)
                cand_name: str | None = None
                if isinstance(cand, ast.Attribute) and cand.attr in _MAPPING_COPY_FUNCS:
                    cand_name = cand.attr
                elif isinstance(cand, ast.Name):
                    cand_name = operator_projection_aliases.get(cand.id, cand.id)
                    if cand.id in dict_view_products:
                        cand_name = dict_view_products[cand.id].split(".")[-1]
                    product = projection_factory_products.get(cand.id)
                    if product is not None and product[0] == "partial":
                        for pname in partial_product_names.get(cand.id, []):
                            if pname in _MAPPING_COPY_FUNCS and expr.args:
                                return _iter_elements(expr.args[0], nxt)
                elif isinstance(cand, ast.Call):
                    gcopy = _getattr_static_name(
                        cand, getattr_aliases=frozenset(getattr_aliases)
                    )
                    if gcopy in _MAPPING_COPY_FUNCS:
                        cand_name = gcopy
                    elif _is_partial_factory(
                        cand,
                        partial_aliases=frozenset(partial_aliases),
                        getattr_aliases=frozenset(getattr_aliases),
                    ) and cand.args:
                        # ``[partial(copy.deepcopy)][0](xs)`` /
                        # ``(0 or partial(copy.copy))(xs)`` /
                        # ``[partial(methodcaller("copy"))][0](xs)``.
                        bound = _peel_call_func(cand.args[0])
                        bound_copy = (
                            (
                                isinstance(bound, ast.Attribute)
                                and bound.attr in _MAPPING_COPY_FUNCS
                            )
                            or (
                                isinstance(bound, ast.Name)
                                and (
                                    bound.id in _MAPPING_COPY_FUNCS
                                    or operator_projection_aliases.get(bound.id)
                                    in _MAPPING_COPY_FUNCS
                                )
                            )
                            or (
                                isinstance(bound, ast.Call)
                                and _getattr_static_name(
                                    bound,
                                    getattr_aliases=frozenset(getattr_aliases),
                                )
                                in _MAPPING_COPY_FUNCS
                            )
                            or (
                                isinstance(bound, ast.Call)
                                and _methodcaller_static_name(
                                    bound,
                                    projection_aliases=operator_projection_aliases,
                                    getattr_aliases=frozenset(getattr_aliases),
                                )
                                in _MAPPING_COPY_FUNCS
                            )
                        )
                        if bound_copy and expr.args:
                            return _iter_elements(expr.args[0], nxt)
                        if bound_copy and len(cand.args) >= 2 and not expr.args:
                            return _iter_elements(cand.args[1], nxt)
                if cand_name in _MAPPING_COPY_FUNCS and expr.args:
                    return _iter_elements(expr.args[0], nxt)
        if func_name in {"map", "filter"} and len(expr.args) >= 2:
            mapped: list[ast.AST] = []
            resolved = False
            head = _peel_call_func(expr.args[0])
            for arg in expr.args[1:]:
                sub = _iter_elements(arg, nxt)
                if sub is None:
                    continue
                resolved = True
                if isinstance(head, ast.Lambda) and func_name == "map":
                    # ``map(lambda f: f(Mut), [tc])`` — body per element.
                    for elem in sub:
                        bind: dict[str, ast.AST] = {}
                        if head.args.args:
                            bind[head.args.args[0].arg] = elem
                        mapped.append(_subst_names(head.body, bind))
                else:
                    mapped.extend(sub)
            if (
                isinstance(head, ast.Lambda)
                and func_name == "map"
                and not mapped
            ):
                mapped.append(head.body)
                resolved = True
            return mapped if resolved else None
        if func_name in _ITERTOOLS_ADAPTER_NAMES and expr.args:
            chained: list[ast.AST] = []
            resolved_ch = False
            args = expr.args
            if func_name == "starmap" and len(expr.args) >= 2:
                args = expr.args[1:2]
            elif func_name == "islice":
                args = expr.args[:1]
            elif func_name == "compress":
                # ``compress(data, selectors)`` — data is first.
                args = expr.args[:1]
            elif func_name in {
                "filterfalse",
                "dropwhile",
                "takewhile",
                "accumulate",
                "groupby",
            }:
                # Predicate/func first for filterfalse/dropwhile/takewhile;
                # ``accumulate(iterable, func)`` / ``groupby(iterable, key)``
                # — iterable first.
                if func_name in {"accumulate", "groupby"}:
                    args = expr.args[:1]
                else:
                    args = expr.args[1:2] if len(expr.args) >= 2 else ()
            elif func_name == "repeat":
                # ``repeat(exec, 1)`` yields the element itself.
                return [expr.args[0]]
            elif func_name in {"tee", "pairwise", "batched"}:
                args = expr.args[:1]
            for arg in args:
                sub = _iter_elements(
                    arg.value if isinstance(arg, ast.Starred) else arg, nxt
                )
                if sub is not None:
                    resolved_ch = True
                    if func_name in _ITERTOOLS_FLATTEN_ADAPTERS:
                        # One-level flatten: ``chain.from_iterable([[exec]])``.
                        for elem in sub:
                            inner = _iter_elements(elem, nxt)
                            if inner is not None:
                                chained.extend(inner)
                            else:
                                chained.append(elem)
                    elif func_name in {
                        "permutations",
                        "combinations",
                        "combinations_with_replacement",
                        "product",
                        "zip_longest",
                        "starmap",
                        "pairwise",
                        "batched",
                        "groupby",
                    }:
                        # Yield tuples / star-applied rows of element packs.
                        for elem in sub:
                            if func_name == "starmap" and isinstance(
                                elem, (ast.Tuple, ast.List)
                            ):
                                chained.extend(elem.elts)
                            elif func_name == "groupby":
                                # ``(_, group)`` rows — group carries the element.
                                chained.append(
                                    ast.Tuple(
                                        elts=[
                                            ast.Constant(value=None),
                                            ast.List(elts=[elem], ctx=ast.Load()),
                                        ],
                                        ctx=ast.Load(),
                                    )
                                )
                            else:
                                chained.append(
                                    ast.Tuple(elts=[elem], ctx=ast.Load())
                                    if func_name
                                    in {
                                        "permutations",
                                        "combinations",
                                        "combinations_with_replacement",
                                        "product",
                                        "zip_longest",
                                        "pairwise",
                                        "batched",
                                    }
                                    else elem
                                )
                    else:
                        chained.extend(sub)
            return chained if resolved_ch else None
        if func_name == "deque" and expr.args:
            return _iter_elements(
                expr.args[0].value
                if isinstance(expr.args[0], ast.Starred)
                else expr.args[0],
                nxt,
            )
        if func_name == "enumerate" and expr.args:
            sub = _iter_elements(expr.args[0], nxt)
            if sub is None:
                return None
            return [
                ast.Tuple(elts=[ast.Constant(value=0), elem], ctx=ast.Load())
                for elem in sub
            ]
        if func_name == "zip" and expr.args:
            lists = [
                _iter_elements(
                    arg.value if isinstance(arg, ast.Starred) else arg, nxt
                )
                for arg in expr.args
            ]
            if all(lst is None for lst in lists):
                return None
            width = max(len(lst) for lst in lists if lst)
            rows: list[ast.AST] = []
            for i in range(width):
                rows.append(
                    ast.Tuple(
                        elts=[
                            lst[min(i, len(lst) - 1)]
                            if lst
                            else ast.Constant(value=None)
                            for lst in lists
                        ],
                        ctx=ast.Load(),
                    )
                )
            return rows
        if _is_dict_fromkeys(
            func,
            dict_ctor_aliases=frozenset(dict_ctor_aliases),
            dict_view_products=dict_view_products,
        ):
            # ``dict.fromkeys([Mut])`` / ``fk([Mut])`` iterates keys.
            if not expr.args:
                return None
            return _iter_elements(expr.args[0], nxt)
        if _is_dict_constructor(
            func,
            dict_ctor_aliases=frozenset(dict_ctor_aliases),
            getattr_aliases=frozenset(getattr_aliases),
        ):
            items = _mapping_items(expr, nxt)
            if items is None:
                return None
            return [k for k, _ in items if k is not None]
        return None

    _CANDIDATE_VIEW_ATTRS = frozenset({"get", "pop", "setdefault", "__getitem__"})
    _CANDIDATE_ITER_ADAPTERS = frozenset(
        {"next", "iter", "list", "tuple", "sorted", "reversed", "set", "frozenset"}
    )

    def _callee_candidate_exprs(callee: ast.AST, depth: int = 0) -> list[ast.AST]:
        """Expressions a packed / projected ``Call.func`` may denote.

        Mirrors the name-level peel in ``_names_packed_as_callee`` but keeps the
        original expressions so receiver-bearing callees (``n.install``,
        ``getattr(n, "install")``) survive packing in literals, subscripts,
        ``next(iter(...))``, mapping views and conditional expressions.
        """

        callee = _peel_call_func(callee)
        out: list[ast.AST] = [callee]
        if depth > 6:
            return out
        nxt = depth + 1
        # Name-bound Attribute / packed callees from For/Match/Assign seeds.
        if isinstance(callee, ast.Name) and callee.id in bound_callee_exprs:
            out.extend(
                _callee_candidate_exprs(bound_callee_exprs[callee.id], nxt)
            )
        if isinstance(callee, ast.Attribute) and callee.attr in {
            "__call__",
            "__func__",
        }:
            # ``X.__call__`` / ``X.__func__`` denote ``X`` itself for peels.
            out.extend(_callee_candidate_exprs(callee.value, nxt))
            # ``SimpleNamespace(m=Mut.make).m.__call__()`` — project attr pack.
            recv = _peel_call_func(callee.value)
            if isinstance(recv, ast.Attribute):
                out.extend(_callee_candidate_exprs(recv, nxt))
        elif isinstance(callee, ast.Attribute):
            # ``SimpleNamespace(m=Mut.make).m`` / ``ns.m`` / IfExp/BoolOp /
            # copy(ns).m / packed ``[ns][0].m`` pack projections.
            recv = _peel_call_func(callee.value)

            def _project_attr_from(recv_node: ast.AST) -> None:
                recv_node = _peel_call_func(recv_node)
                if isinstance(recv_node, (ast.IfExp,)):
                    _project_attr_from(recv_node.body)
                    _project_attr_from(recv_node.orelse)
                    return
                if isinstance(recv_node, ast.BoolOp):
                    for value in recv_node.values:
                        _project_attr_from(value)
                    return
                if isinstance(recv_node, ast.Subscript):
                    for cand in _callee_candidate_exprs(recv_node, nxt):
                        out.extend(
                            _callee_candidate_exprs(
                                ast.Attribute(
                                    value=cand, attr=callee.attr, ctx=ast.Load()
                                ),
                                nxt,
                            )
                        )
                    return
                if isinstance(recv_node, ast.Call):
                    view = _view_call_parts(recv_node)
                    if view is not None and view[0] in _MAPPING_COPY_FUNCS:
                        _project_attr_from(view[1])
                        return
                    if _is_dict_constructor(
                        recv_node.func,
                        dict_ctor_aliases=frozenset(dict_ctor_aliases),
                        getattr_aliases=frozenset(getattr_aliases),
                    ):
                        for val in _dict_call_values_for_key(
                            recv_node, callee.attr
                        ):
                            out.extend(_callee_candidate_exprs(val, nxt))
                        return
                    # ``next(iter([SN(m=…)]))``.m / ``list([SN]).m`` peels.
                    fpeeled = _peel_call_func(recv_node.func)
                    adapter = None
                    if isinstance(fpeeled, ast.Name):
                        adapter = operator_projection_aliases.get(
                            fpeeled.id, fpeeled.id
                        )
                    elif isinstance(fpeeled, ast.Attribute):
                        adapter = fpeeled.attr
                    if adapter in {
                        "next",
                        "iter",
                        "list",
                        "tuple",
                        "reversed",
                        "sorted",
                    } and recv_node.args:
                        for elt in _iter_elements(recv_node) or []:
                            _project_attr_from(elt)
                        return
                if isinstance(recv_node, ast.Name) and recv_node.id in sequence_view_aliases:
                    aliased = sequence_view_aliases[recv_node.id]
                    items = _mapping_items(aliased)
                    if items is not None:
                        for map_key, val in items:
                            if val is None:
                                continue
                            if (
                                isinstance(map_key, ast.Constant)
                                and map_key.value != callee.attr
                            ):
                                continue
                            if (
                                isinstance(map_key, ast.Constant)
                                and map_key.value == callee.attr
                            ) or not isinstance(map_key, ast.Constant):
                                out.extend(_callee_candidate_exprs(val, nxt))
                    elif recv_node.id in container_packs:
                        for pname in container_packs[recv_node.id].get(
                            callee.attr, ()
                        ):
                            if pname in bound_callee_exprs:
                                out.extend(
                                    _callee_candidate_exprs(
                                        bound_callee_exprs[pname], nxt
                                    )
                                )
                            else:
                                out.append(ast.Name(id=pname, ctx=ast.Load()))
                    return
                if isinstance(recv_node, ast.Name) and recv_node.id in container_packs:
                    for pname in container_packs[recv_node.id].get(callee.attr, ()):
                        if pname in bound_callee_exprs:
                            out.extend(
                                _callee_candidate_exprs(
                                    bound_callee_exprs[pname], nxt
                                )
                            )
                        else:
                            out.append(ast.Name(id=pname, ctx=ast.Load()))
                    return
                if isinstance(recv_node, ast.Name) and recv_node.id in bound_callee_exprs:
                    out.extend(
                        _callee_candidate_exprs(
                            ast.Attribute(
                                value=bound_callee_exprs[recv_node.id],
                                attr=callee.attr,
                                ctx=ast.Load(),
                            ),
                            nxt,
                        )
                    )

            _project_attr_from(recv)
        elif isinstance(callee, ast.IfExp):
            out.extend(_callee_candidate_exprs(callee.body, nxt))
            out.extend(_callee_candidate_exprs(callee.orelse, nxt))
        elif isinstance(callee, ast.BoolOp):
            for value in callee.values:
                out.extend(_callee_candidate_exprs(value, nxt))
        elif isinstance(callee, ast.BinOp) and isinstance(
            callee.op, (ast.Add, ast.Mult)
        ):
            # ``([partial(...)] + [])[0]`` / ``([p] * 1)[0]`` sequence carriers.
            out.extend(_callee_candidate_exprs(callee.left, nxt))
            if isinstance(callee.op, ast.Add):
                out.extend(_callee_candidate_exprs(callee.right, nxt))
        elif isinstance(callee, ast.Subscript):
            # Peel packing-transparent sequence slices so
            # ``deepcopy([n.install])[:][0]`` / ``[…][:1][0]`` /
            # ``[…][slice(0,1)][0]`` share the bare ``[…][0]`` path
            # (Unknown > false PASS).
            base = _peel_slices(callee.value)
            # Prefer sequence-view / literal carriers so ``fns=[n.install];
            # fns[0](evil)`` / ``rest["m"]`` / nested ``views['outer']['v']``
            # keep Attribute receivers (Unknown > false PASS).
            carrier: ast.AST = base
            # Nested subscript carriers: ``views['outer']`` → Dict value.
            resolve_stack = [base]
            while resolve_stack:
                cur = _peel_slices(resolve_stack.pop())
                if isinstance(cur, ast.Name) and cur.id in sequence_view_aliases:
                    carrier = sequence_view_aliases[cur.id]
                    break
                if isinstance(cur, ast.Subscript):
                    parent = _peel_slices(cur.value)
                    parent_carrier = parent
                    if (
                        isinstance(parent, ast.Name)
                        and parent.id in sequence_view_aliases
                    ):
                        parent_carrier = sequence_view_aliases[parent.id]
                    key = _resolve_static_key_value(cur.slice)
                    if key is None:
                        key = _static_key(cur.slice)
                    elem = _carrier_element_at(parent_carrier, key)
                    if elem is not None:
                        carrier = elem
                        resolve_stack.append(elem)
                        continue
                    carrier = cur
                    break
                carrier = cur
                break
            mapped = _mapping_items(carrier)
            if isinstance(carrier, (ast.Dict, ast.DictComp)) or (
                mapped is not None
                and not isinstance(carrier, (ast.List, ast.Tuple, ast.Set))
            ):
                key = _resolve_static_key_value(callee.slice)
                if key is None:
                    key = _static_key(callee.slice)
                if key is None:
                    key = _resolve_static_str(callee.slice)
                for map_key, val in mapped or []:
                    if val is None:
                        continue
                    if key is not None and isinstance(map_key, ast.Constant):
                        if map_key.value != key:
                            continue
                    out.extend(_callee_candidate_exprs(val, nxt))
            else:
                # Sequence carriers: ``pair[1]`` / ``list(items())[0]`` /
                # ``next(iter(items()))[1]`` must honor the static index.
                key = _resolve_static_key_value(callee.slice)
                if key is None:
                    key = _static_key(callee.slice)
                elem = _carrier_element_at(carrier, key)
                if elem is not None:
                    out.extend(_callee_candidate_exprs(elem, nxt))
                else:
                    for elt in _iter_elements(carrier) or []:
                        out.extend(_callee_candidate_exprs(elt, nxt))
        elif isinstance(callee, (ast.List, ast.Tuple, ast.Set)):
            for elt in callee.elts:
                nested = elt.value if isinstance(elt, ast.Starred) else elt
                out.extend(_callee_candidate_exprs(nested, nxt))
        elif isinstance(
            callee, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)
        ):
            # ``[x for x in fns.items()][0][1](evil)`` — shared element peel.
            for elt in _iter_elements(callee) or []:
                out.extend(_callee_candidate_exprs(elt, nxt))
        elif isinstance(callee, ast.Call):
            view = _view_call_parts(callee)
            gname = _getattr_static_name(
                callee, getattr_aliases=frozenset(getattr_aliases)
            )
            if gname == "__call__" and callee.args:
                out.extend(_callee_candidate_exprs(callee.args[0], nxt))
            elif gname is not None and callee.args:
                # ``getattr(Mut, "make")`` ≡ ``Mut.make`` for method / install peels.
                synthetic = ast.Attribute(
                    value=callee.args[0], attr=gname, ctx=ast.Load()
                )
                out.append(synthetic)
                out.extend(_callee_candidate_exprs(synthetic, nxt))
            elif view is not None and view[0] in _CANDIDATE_VIEW_ATTRS:
                for _, val in _mapping_items(_peel_call_func(view[1])) or []:
                    if val is not None:
                        out.extend(_callee_candidate_exprs(val, nxt))
                if view[0] in {"get", "pop", "setdefault"} and len(callee.args) >= 2:
                    out.extend(_callee_candidate_exprs(callee.args[1], nxt))
                # Sequence ``views.pop(-1)`` / ``views.__getitem__(0)`` /
                # Name-bound / BoolOp peels — share ``_iter_elements``.
                if view[0] in {"pop", "__getitem__"}:
                    for elt in _iter_elements(callee) or []:
                        out.extend(_callee_candidate_exprs(elt, nxt))
            elif view is not None and view[0] in _MAPPING_COPY_FUNCS and callee.args:
                # ``copy.deepcopy([n.install])`` / packed list carriers —
                # peel into copied elements (Unknown > false PASS).
                for elt in _iter_elements(view[1]) or []:
                    out.extend(_callee_candidate_exprs(elt, nxt))
            elif (
                isinstance(callee.func, ast.Name)
                and callee.func.id in _CANDIDATE_ITER_ADAPTERS
                and callee.args
            ):
                for elt in _iter_elements(callee.args[0]) or []:
                    out.extend(_callee_candidate_exprs(elt, nxt))
            else:
                # ``operator.getitem(xs, slice(...))`` / packed partial(copy) /
                # ``[copy.deepcopy([n.install])][0]`` recover carriers via
                # ``_iter_elements`` (Unknown > false PASS).
                proj = _projection_factory_name(
                    callee,
                    projection_aliases=operator_projection_aliases,
                    getattr_aliases=frozenset(getattr_aliases),
                )
                if (
                    proj == "getitem"
                    and len(callee.args) >= 2
                    and _slice_key(callee.args[1])
                ):
                    for elt in _iter_elements(callee.args[0]) or []:
                        out.extend(_callee_candidate_exprs(elt, nxt))
                else:
                    for elt in _iter_elements(callee) or []:
                        out.extend(_callee_candidate_exprs(elt, nxt))
        return out

    def _accounted_attr_refs(cand: ast.AST) -> list[tuple[ast.AST, str]]:
        """``(receiver, attr)`` refs for ``n.attr`` / ``getattr(n, "attr")``.

        ``X.__call__`` and ``getattr(X, "__call__")`` are transparent: they
        denote ``X`` itself, so ``n.install.__call__`` refs ``(n, "install")``.
        """

        cand = _peel_call_func(cand)
        if isinstance(cand, ast.Attribute):
            if cand.attr == "__call__":
                inner = _accounted_attr_refs(cand.value)
                if inner:
                    return inner
            return [(cand.value, cand.attr)]
        if isinstance(cand, ast.Call) and cand.args:
            name = _getattr_static_name(
                cand, getattr_aliases=frozenset(getattr_aliases)
            )
            if name is not None:
                if name == "__call__":
                    inner = _accounted_attr_refs(cand.args[0])
                    if inner:
                        return inner
                return [(cand.args[0], name)]
        return []

    def _pack_from_items(
        items: Sequence[tuple[ast.AST | None, ast.AST | None]],
    ) -> dict[object, tuple[str, ...]]:
        pack: dict[object, tuple[str, ...]] = {}
        for key, val in items:
            if val is not None:
                names = _packed_names_deep(val)
                if isinstance(key, ast.Constant):
                    _pack_add(pack, key.value, names)
                else:
                    _pack_add(pack, None, names)
            if key is not None and not isinstance(key, ast.Constant):
                _pack_add(pack, _KEYS_SLOT, _packed_names_deep(key))
        return pack

    def _container_pack_from_expr(
        value: ast.AST,
    ) -> dict[object, tuple[str, ...]] | None:
        """Key→packed-name map for dict/list/tuple/set / ``dict(...)`` packs."""

        value = _peel_call_func(value)
        if isinstance(value, ast.Name):
            if value.id in container_packs:
                return dict(container_packs[value.id])
            return None
        pack: dict[object, tuple[str, ...]] = {}
        if isinstance(value, (ast.List, ast.Tuple)):
            for index, elt in enumerate(value.elts):
                if isinstance(elt, ast.Starred):
                    sub = _iter_elements(elt.value)
                    names = (
                        [n for e in sub for n in _packed_names_deep(e)]
                        if sub is not None
                        else _packed_names_deep(elt.value)
                    )
                    _pack_add(pack, None, names)
                    continue
                _pack_add(pack, index, _packed_names_deep(elt))
            return pack or None
        if isinstance(value, ast.Set):
            # Sets have no stable keys; pack under None for full peel.
            names = []
            for elt in value.elts:
                nested = elt.value if isinstance(elt, ast.Starred) else elt
                names.extend(_packed_names_deep(nested))
            if names:
                return {None: tuple(dict.fromkeys(names))}
            return None
        items = _mapping_items(value)
        if items is not None:
            return _pack_from_items(items) or None
        elems = _iter_elements(value)
        if elems is not None:
            # Preserve list-carrier index slots for ``views[0]`` after
            # ``copy.copy`` / ``xs[:]`` / ``list(xs)`` peels (Unknown > false PASS).
            pack: dict[object, tuple[str, ...]] = {}
            for index, elt in enumerate(elems):
                _pack_add(pack, index, _packed_names_deep(elt))
            if pack:
                return pack
            flat = [n for e in elems for n in _packed_names_deep(e)]
            if flat:
                return {None: tuple(dict.fromkeys(flat))}
        return None

    def _is_sequence_copy_or_slice(value: ast.AST) -> bool:
        """True for ``xs[:]`` / ``xs[:1]`` / ``xs[slice(...)]`` / ``copy.copy(xs)`` / ``list(xs)``."""

        node = _peel_call_func(value)
        if isinstance(node, ast.Subscript) and _slice_key(node.slice):
            return True
        if not isinstance(node, ast.Call):
            return False
        func = _peel_call_func(node.func)
        if isinstance(func, ast.Name) and (
            func.id in {"list", "tuple"}
            or operator_projection_aliases.get(func.id)
            in _MAPPING_COPY_FUNCS | {"list", "tuple"}
        ):
            return True
        if isinstance(func, ast.Attribute) and func.attr in _MAPPING_COPY_FUNCS | {
            "list",
            "tuple",
        }:
            return True
        view = _view_call_parts(node)
        if view is not None and view[0] in _MAPPING_COPY_FUNCS:
            return True
        # ``operator.getitem(xs, slice(...))`` is packing-transparent.
        proj = _projection_factory_name(
            node,
            projection_aliases=operator_projection_aliases,
            getattr_aliases=frozenset(getattr_aliases),
        )
        if proj == "getitem" and len(node.args) >= 2 and _slice_key(node.args[1]):
            return True
        return False

    def _note_container_pack_from_value(name: str, value: ast.AST) -> None:
        node = _peel_call_func(value)
        # ``views = xs[:]`` / ``views = xs[:1]`` / ``views = xs[slice(...)]`` /
        # ``views = copy.copy(xs)[:]`` — share the base sequence carrier peels
        # (Unknown > false PASS).
        if isinstance(node, ast.Subscript) and _slice_key(node.slice):
            base = _peel_call_func(node.value)
            if isinstance(base, ast.Name) and (
                base.id in sequence_view_aliases or base.id in container_packs
            ):
                if base.id in container_packs:
                    container_packs[name] = dict(container_packs[base.id])
                if base.id in sequence_view_aliases:
                    aliased = sequence_view_aliases[base.id]
                    if isinstance(aliased, (ast.List, ast.Tuple)):
                        sequence_view_aliases[name] = ast.List(
                            elts=list(aliased.elts), ctx=ast.Load()
                        )
                    else:
                        sequence_view_aliases[name] = aliased
                elif base.id in container_packs:
                    # Reconstruct a List carrier from int-keyed packs when
                    # only name packs were retained.
                    pack = container_packs[base.id]
                    if pack and all(isinstance(k, int) for k in pack):
                        elts = [
                            ast.Name(id=n, ctx=ast.Load())
                            for k in sorted(pack)
                            for n in pack[k]
                        ]
                        sequence_view_aliases[name] = ast.List(
                            elts=elts, ctx=ast.Load()
                        )
                return
            # Inline ``[{…}][:]`` / ``[{…}][:1]`` / ``copy.copy([…])[:]``.
            seq_elems = _iter_elements(node.value)
            if seq_elems is not None:
                pack: dict[object, tuple[str, ...]] = {}
                for index, elt in enumerate(seq_elems):
                    _pack_add(pack, index, _packed_names_deep(elt))
                if pack:
                    container_packs[name] = pack
                sequence_view_aliases[name] = ast.List(
                    elts=list(seq_elems), ctx=ast.Load()
                )
                return
            # Last resort: seed from the sliced expression's container pack
            # when element materialization is unresolved.
            syn_pack = _container_pack_from_expr(node.value)
            if syn_pack is not None:
                container_packs[name] = dict(syn_pack)
                elems = _iter_elements(node.value)
                if elems is not None:
                    sequence_view_aliases[name] = ast.List(
                        elts=list(elems), ctx=ast.Load()
                    )
                return
        pack = _container_pack_from_expr(value)
        seq_peel = _is_sequence_copy_or_slice(value)
        seq_elems = _iter_elements(value) if seq_peel else None
        if pack is not None:
            container_packs[name] = pack
            # Preserve Attribute values (``Mut.make`` / ``n.install``) so
            # Name-bound NS / nested dict packs still peel receivers
            # (``ns.m()`` / ``views['outer']['v']()`` — Unknown > false PASS).
            # Prefer mapping aliases over sequence elems: ``copy.copy(d)`` is
            # both a copy peel and a mapping carrier; installing a List of
            # keys would false-PASS later ``e.keys()`` / methodcaller('keys').
            items = _mapping_items(value)
            if items is not None:
                sequence_view_aliases[name] = ast.Dict(
                    keys=[k for k, _ in items],
                    values=[
                        v if v is not None else ast.Constant(value=None)
                        for _, v in items
                    ],
                )
            elif isinstance(value, (ast.List, ast.Tuple, ast.Set, ast.Dict)):
                sequence_view_aliases[name] = value
            elif seq_elems is not None:
                sequence_view_aliases[name] = ast.List(
                    elts=list(seq_elems), ctx=ast.Load()
                )
            else:
                elems = _iter_elements(value)
                if elems is not None:
                    sequence_view_aliases[name] = ast.List(
                        elts=list(elems), ctx=ast.Load()
                    )
        elif seq_elems is not None:
            pack = {}
            for index, elt in enumerate(seq_elems):
                _pack_add(pack, index, _packed_names_deep(elt))
            if pack:
                container_packs[name] = pack
            sequence_view_aliases[name] = ast.List(
                elts=list(seq_elems), ctx=ast.Load()
            )
        else:
            container_packs.pop(name, None)

    def _grow_named_pack(
        base_name: str,
        attr: str,
        args: Sequence[ast.AST],
        keywords: Sequence[ast.keyword],
    ) -> None:
        """Grow ``container_packs[base_name]`` via update/setdefault/setitem/add."""

        if attr not in {"update", "setdefault", "__setitem__"} | _PACK_ADD_METHODS:
            return
        pack = dict(container_packs.get(base_name, {}))
        if attr == "update":
            for kw in keywords:
                if kw.arg is None:
                    # ``**(kw if True else {})`` / ``**(kw or {})`` /
                    # Name-bound ``kw={"m": Mut.make}`` spreads.
                    for arm in _iter_boolop_ifexp_arms(kw.value):
                        arm = _peel_call_func(arm)
                        sub = _container_pack_from_expr(arm)
                        if not sub and isinstance(arm, ast.Name):
                            sub = dict(container_packs.get(arm.id, {}))
                            if not sub:
                                aliased = sequence_view_aliases.get(arm.id)
                                if aliased is not None:
                                    sub = _container_pack_from_expr(aliased) or {}
                        pack = _pack_union(pack, sub)
                        if not sub:
                            _pack_add(pack, None, _packed_names_deep(arm))
                else:
                    _pack_add(pack, kw.arg, _packed_names_deep(kw.value))
            for arg in args:
                nested = arg.value if isinstance(arg, ast.Starred) else arg
                sub_items = _mapping_items(nested)
                if sub_items is not None:
                    pack = _pack_union(pack, _pack_from_items(sub_items))
                else:
                    pairs = _iter_elements(nested)
                    if pairs is not None:
                        added = False
                        for pair in pairs:
                            pair = _peel_call_func(pair)
                            # Prefer mapping-element merge before pair/next peels
                            # so ``extend([{"e": exec}])`` does not collapse the
                            # Dict via ``_iter_elements`` (keys-only).
                            elem_items = _mapping_items(pair)
                            if elem_items is not None:
                                pack = _pack_union(
                                    pack, _pack_from_items(elem_items)
                                )
                                added = True
                                continue
                            if not (
                                isinstance(pair, (ast.Tuple, ast.List))
                                and len(pair.elts) == 2
                            ):
                                # ``next(it)`` over ``d.items()`` → one pair.
                                if isinstance(pair, ast.Call):
                                    peeled_pair = _iter_elements(pair)
                                    if peeled_pair and len(peeled_pair) == 1:
                                        pair = _peel_call_func(peeled_pair[0])
                            if (
                                isinstance(pair, (ast.Tuple, ast.List))
                                and len(pair.elts) == 2
                            ):
                                pack = _pack_union(
                                    pack,
                                    _pack_from_items([(pair.elts[0], pair.elts[1])]),
                                )
                                added = True
                            else:
                                # ``s.update([exec])`` — element identities.
                                _pack_add(
                                    pack, None, _packed_names_deep(pair)
                                )
                                added = True
                        if not added:
                            _pack_add(pack, None, _packed_names_deep(nested))
                    else:
                        _pack_add(pack, None, _packed_names_deep(nested))
        elif attr in {"setdefault", "__setitem__"}:
            if len(args) >= 2:
                pack = _pack_union(pack, _pack_from_items([(args[0], args[1])]))
                # Preserve Attribute / Call values (``Mut.make`` / ``n.install``)
                # so ``vars(ns).setdefault("m", Mut.make); ns.m()`` peels
                # (Unknown > false PASS).
                key_node, val_node = args[0], args[1]
                if isinstance(key_node, ast.Constant):
                    prev = sequence_view_aliases.get(base_name)
                    by_key: dict[object, ast.AST] = {}
                    if prev is not None:
                        for mk, mv in _mapping_items(prev) or []:
                            if isinstance(mk, ast.Constant) and mv is not None:
                                by_key[mk.value] = mv
                    by_key[key_node.value] = val_node
                    sequence_view_aliases[base_name] = ast.Dict(
                        keys=[ast.Constant(value=k) for k in by_key],
                        values=list(by_key.values()),
                    )
            elif args:
                _pack_add(pack, None, _packed_names_deep(args[0]))
        else:
            value_args = args[1:] if attr == "insert" else args
            for arg in value_args:
                nested = arg.value if isinstance(arg, ast.Starred) else arg
                if attr in {"extend", "extendleft"}:
                    sub = _iter_elements(nested)
                    names = (
                        [n for e in sub for n in _packed_names_deep(e)]
                        if sub is not None
                        else _packed_names_deep(nested)
                    )
                    _pack_add(pack, None, names)
                else:
                    _pack_add(pack, None, _packed_names_deep(nested))
            # Preserve Call / Attribute element AST so
            # ``xs.append(partial(...)); xs[0](...)`` /
            # ``views.insert(0, n.install); views[0](...)`` share the
            # Name-bound List peel (Unknown > false PASS).
            prev_seq = sequence_view_aliases.get(base_name)
            prev_elts: list[ast.AST] = []
            if isinstance(prev_seq, (ast.List, ast.Tuple)):
                prev_elts = list(prev_seq.elts)
            elif prev_seq is not None:
                prev_elts = list(_iter_elements(prev_seq) or [])
            new_elts = list(prev_elts)
            if attr == "insert" and len(args) >= 2:
                idx = _static_sequence_index(args[0])
                if idx is None:
                    idx = 0
                new_elts.insert(int(idx), args[1])
            else:
                for arg in value_args:
                    nested = arg.value if isinstance(arg, ast.Starred) else arg
                    if attr in {"extend", "extendleft"}:
                        sub = _iter_elements(nested)
                        if sub is not None:
                            new_elts.extend(sub)
                        else:
                            new_elts.append(nested)
                    else:
                        new_elts.append(nested)
            sequence_view_aliases[base_name] = ast.List(
                elts=new_elts, ctx=ast.Load()
            )
            # Index slots for later ``xs[0]`` peels.
            for index, elt in enumerate(new_elts):
                _pack_add(pack, index, _packed_names_deep(elt))
        if pack:
            container_packs[base_name] = pack
            # Preserve Attribute values from the grow args so later
            # ``d['e'](evil)`` / ``ns.m()`` peels keep receivers
            # (``d.update({'e': n.install})`` — Unknown > false PASS).
            items = _mapping_items(ast.Name(id=base_name, ctx=ast.Load()))
            if items is not None:
                sequence_view_aliases[base_name] = ast.Dict(
                    keys=[k for k, _ in items],
                    values=[
                        v if v is not None else ast.Constant(value=None)
                        for _, v in items
                    ],
                )
            # Also merge RHS mapping literals' Attribute values directly.
            for arg in args:
                nested = arg.value if isinstance(arg, ast.Starred) else arg
                rhs_items = _mapping_items(nested)
                if rhs_items is None:
                    # ``d.update([next(it)])`` / ``maps.extend([{"e": exec}])``.
                    pairs = _iter_elements(nested)
                    if pairs is not None:
                        rhs_items = []
                        for pair in pairs:
                            pair = _peel_call_func(pair)
                            elem_items = _mapping_items(pair)
                            if elem_items is not None:
                                rhs_items.extend(elem_items)
                                continue
                            # ``next(it)`` may still be a Call — peel one more
                            # element level to the underlying (key, value) row.
                            if not (
                                isinstance(pair, (ast.Tuple, ast.List))
                                and len(pair.elts) == 2
                            ):
                                if isinstance(pair, ast.Call):
                                    peeled_pair = _iter_elements(pair)
                                    if peeled_pair and len(peeled_pair) == 1:
                                        pair = _peel_call_func(peeled_pair[0])
                            if (
                                isinstance(pair, (ast.Tuple, ast.List))
                                and len(pair.elts) == 2
                            ):
                                rhs_items.append((pair.elts[0], pair.elts[1]))
                if not rhs_items:
                    continue
                prev = sequence_view_aliases.get(base_name)
                prev_items = list(_mapping_items(prev) or []) if prev else []
                # Replace/extend by static key with Attribute-preserving values.
                by_key: dict[object, ast.AST] = {}
                for k, v in prev_items:
                    if isinstance(k, ast.Constant) and v is not None:
                        by_key[k.value] = v
                for k, v in rhs_items:
                    if isinstance(k, ast.Constant) and v is not None:
                        by_key[k.value] = v
                if by_key:
                    sequence_view_aliases[base_name] = ast.Dict(
                        keys=[ast.Constant(value=k) for k in by_key],
                        values=list(by_key.values()),
                    )
            for kw in keywords:
                prev = sequence_view_aliases.get(base_name)
                prev_items = list(_mapping_items(prev) or []) if prev else []
                by_key = {
                    k.value: v
                    for k, v in prev_items
                    if isinstance(k, ast.Constant) and v is not None
                }
                if kw.arg is None:
                    # ``d.update(**{"m": Mut.make})`` / ``d.update(**kw)`` /
                    # ``**(kw if True else {})`` / ``**(kw or {})`` —
                    # preserve Attribute values from the spread mapping.
                    rhs_items: list[tuple[ast.AST | None, ast.AST | None]] = []
                    for arm in _iter_boolop_ifexp_arms(kw.value):
                        arm = _peel_call_func(arm)
                        arm_items = _mapping_items(arm)
                        if arm_items is None and isinstance(arm, ast.Name):
                            aliased = sequence_view_aliases.get(arm.id)
                            if aliased is not None:
                                arm_items = _mapping_items(aliased)
                            if arm_items is None and arm.id in container_packs:
                                # Rebuild items from Name-bound Dict packs.
                                aliased = sequence_view_aliases.get(arm.id)
                                if aliased is not None:
                                    arm_items = _mapping_items(aliased)
                        if arm_items:
                            rhs_items.extend(arm_items)
                    for map_key, map_val in rhs_items:
                        if (
                            isinstance(map_key, ast.Constant)
                            and map_val is not None
                        ):
                            by_key[map_key.value] = map_val
                    if by_key:
                        sequence_view_aliases[base_name] = ast.Dict(
                            keys=[ast.Constant(value=k) for k in by_key],
                            values=list(by_key.values()),
                        )
                    continue
                by_key[kw.arg] = kw.value
                sequence_view_aliases[base_name] = ast.Dict(
                    keys=[ast.Constant(value=k) for k in by_key],
                    values=list(by_key.values()),
                )

    def _chainmap_list_parts(
        expr: ast.AST,
    ) -> tuple[str, str] | None:
        """``cm.maps`` / ``getattr(cm, "maps")`` / Name alias → ``(cm, attr)``.

        Also ``object.__getattribute__(cm, "maps")`` / ``attrgetter("maps")(cm)``
        so getattribute / attrgetter packing cannot skip ChainMap list growth
        (Unknown > false PASS).
        """

        node = _peel_call_func(expr)
        if isinstance(node, ast.Name) and node.id in chainmap_list_aliases:
            return chainmap_list_aliases[node.id]
        peeled = _peel_getattr_attr(
            node, getattr_aliases=frozenset(getattr_aliases)
        )
        if peeled is None and isinstance(node, ast.Call) and node.args:
            # ``attrgetter("maps")(cm)`` / ``operator.attrgetter("maps")(cm)`` /
            # Name-bound ``ag = attrgetter("maps"); ag(cm)`` /
            # packed ``[attrgetter("maps")][0](cm)`` /
            # ``(0 or attrgetter("maps"))(cm)`` / IfExp / getattr packs /
            # ``(0 or operator.attrgetter)("maps")(cm)``.
            ag: str | None = None
            factory = _peel_call_func(node.func)
            candidates = [factory, *_callee_candidate_exprs(node.func)]
            for cand in candidates:
                cand = _peel_call_func(cand)
                if isinstance(cand, ast.Call):
                    # Applied product ``attrgetter("maps")`` as Call.func, or
                    # bare ``attrgetter("maps")`` recovered from packing.
                    ag = _attrgetter_static_name(
                        cand,
                        projection_aliases=operator_projection_aliases,
                        getattr_aliases=frozenset(getattr_aliases),
                    )
                    if ag is None and cand.args:
                        # ``(0 or operator.attrgetter)("maps")`` — cand is the
                        # outer apply of a packed factory onto the attr name.
                        if _is_projection_factory_expr(
                            cand.func,
                            "attrgetter",
                            projection_aliases=operator_projection_aliases,
                            getattr_aliases=frozenset(getattr_aliases),
                        ):
                            ag = _static_str(cand.args[0])
                elif isinstance(cand, ast.Name):
                    product = projection_factory_products.get(cand.id)
                    if product is not None and product[0] == "attrgetter":
                        ag = product[1]
                if ag in _CHAINMAP_LIST_ATTRS:
                    break
                ag = None
            if ag in _CHAINMAP_LIST_ATTRS:
                cm = _peel_call_func(node.args[0])
                if isinstance(cm, ast.Name):
                    return cm.id, ag
            # ``object.__getattribute__(cm, "maps")`` / packed getattribute.
            for cand in candidates:
                fpeeled = _peel_call_func(cand)
                is_ga = (
                    isinstance(fpeeled, ast.Attribute)
                    and fpeeled.attr == "__getattribute__"
                ) or (
                    isinstance(fpeeled, ast.Name)
                    and fpeeled.id == "__getattribute__"
                )
                if is_ga and len(node.args) >= 2:
                    attr = _static_str(node.args[1])
                    if attr in _CHAINMAP_LIST_ATTRS:
                        cm = _peel_call_func(node.args[0])
                        if isinstance(cm, ast.Name):
                            return cm.id, attr
            return None
        if peeled is None:
            return None
        recv, attr = peeled
        if attr not in _CHAINMAP_LIST_ATTRS:
            return None
        cm = _peel_call_func(recv)
        if isinstance(cm, ast.Name):
            return cm.id, attr
        return None

    def _chainmap_carrier_name(expr: ast.AST) -> str | None:
        """``cm.maps[i]`` / ``cm.parents[i]`` / ``cm.maps`` → ChainMap Name id.

        Also ``getattr(cm, "maps")`` / ``getattr(cm, "maps")[i]``. Bare Names
        are not ChainMap carriers (``list.__iadd__(xs, …)`` must not treat
        ``list`` as a pack target) unless Name-bound via ``m = cm.maps``.
        """

        node = _peel_call_func(expr)
        if isinstance(node, ast.Name) and node.id in chainmap_list_aliases:
            return chainmap_list_aliases[node.id][0]
        if isinstance(node, ast.Subscript):
            parts = _chainmap_list_parts(node.value)
            if parts is not None:
                return parts[0]
        parts = _chainmap_list_parts(node)
        if parts is not None:
            return parts[0]
        return None

    def _ns_dict_carrier_name(expr: ast.AST) -> str | None:
        """``ns`` / ``vars(ns)`` / ``ns.__dict__`` / ``getattr(ns, "__dict__")``.

        Also ``object.__getattribute__(ns, "__dict__")`` /
        ``attrgetter("__dict__")(ns)`` / packed forms (Unknown > false PASS).
        """

        node = _peel_call_func(expr)
        if isinstance(node, ast.Name):
            # ``d = vars(ns); d["e"] = exec`` grows the owning ns pack.
            root = ns_dict_alias_roots.get(node.id)
            if root is not None:
                return root
            return node.id
        attr_parts = _peel_getattr_attr(
            node, getattr_aliases=frozenset(getattr_aliases)
        )
        if attr_parts is not None:
            recv, attr = attr_parts
            if attr == "__dict__":
                base = _peel_call_func(recv)
                if isinstance(base, ast.Name):
                    return ns_dict_alias_roots.get(base.id, base.id)
        if isinstance(node, ast.Call):
            func = _peel_call_func(node.func)
            # Packed ``[getattr(builtins,"vars")][0](ns)`` / Attribute vars.
            is_vars = False
            if isinstance(func, ast.Name) and (
                func.id in {"vars", "globals", "locals"}
                or func.id in ns_projection_aliases
            ):
                is_vars = True
            elif isinstance(func, ast.Attribute) and func.attr in {
                "vars",
                "globals",
                "locals",
            }:
                is_vars = True
            else:
                for cand in _callee_candidate_exprs(func):
                    cand = _peel_call_func(cand)
                    if isinstance(cand, ast.Name) and (
                        cand.id in {"vars", "globals", "locals"}
                        or cand.id in ns_projection_aliases
                    ):
                        is_vars = True
                        break
                    if isinstance(cand, ast.Attribute) and cand.attr in {
                        "vars",
                        "globals",
                        "locals",
                    }:
                        is_vars = True
                        break
            if is_vars and node.args:
                base = _peel_call_func(node.args[0])
                if isinstance(base, ast.Name):
                    return ns_dict_alias_roots.get(base.id, base.id)
            # ``attrgetter("__dict__")(ns)`` / packed attrgetter products.
            ag: str | None = None
            for cand in [func, *_callee_candidate_exprs(node.func)]:
                cand = _peel_call_func(cand)
                if isinstance(cand, ast.Call):
                    ag = _attrgetter_static_name(
                        cand,
                        projection_aliases=operator_projection_aliases,
                        getattr_aliases=frozenset(getattr_aliases),
                    )
                elif isinstance(cand, ast.Name):
                    product = projection_factory_products.get(cand.id)
                    if product is not None and product[0] == "attrgetter":
                        ag = product[1]
                if ag == "__dict__":
                    base = _peel_call_func(node.args[0])
                    if isinstance(base, ast.Name):
                        return ns_dict_alias_roots.get(base.id, base.id)
                ag = None
            # ``object.__getattribute__(ns, "__dict__")`` / packed.
            for cand in [func, *_callee_candidate_exprs(node.func)]:
                fpeeled = _peel_call_func(cand)
                is_ga = (
                    isinstance(fpeeled, ast.Attribute)
                    and fpeeled.attr == "__getattribute__"
                ) or (
                    isinstance(fpeeled, ast.Name)
                    and fpeeled.id == "__getattribute__"
                )
                if is_ga and len(node.args) >= 2:
                    if _static_str(node.args[1]) == "__dict__":
                        base = _peel_call_func(node.args[0])
                        if isinstance(base, ast.Name):
                            return ns_dict_alias_roots.get(base.id, base.id)
        return None

    def _merge_inplace_pack(left: ast.AST, right: ast.AST) -> None:
        """Merge ``right`` pack into Name / ChainMap / vars(ns) carrier ``left``.

        Also preserves Attribute values in ``sequence_view_aliases`` so
        ``d.__ior__({'e': n.install})`` / ``operator.ior(d, …)`` /
        ``operator.ior(vars(ns), …)`` share the AugAssign ``|=`` peel
        (Unknown > false PASS).
        """

        name = _chainmap_carrier_name(left)
        peeled_left = _peel_call_func(left)
        if name is None and isinstance(peeled_left, ast.Name):
            name = ns_dict_alias_roots.get(peeled_left.id, peeled_left.id)
        if name is None:
            # Direct ``vars(ns)`` / ``ns.__dict__`` / ``getattr(ns,"__dict__")``.
            name = _ns_dict_carrier_name(left)
        if name is None:
            return
        left_pack = _container_pack_from_expr(left) or container_packs.get(name) or {}
        right_pack = _container_pack_from_expr(right) or {}
        merged = _pack_union(left_pack, right_pack)
        if merged:
            container_packs[name] = merged
        # Preserve Attribute / nested carriers for later install peels.
        saved_seq = sequence_view_aliases.get(name)
        left_items = (
            list(_mapping_items(saved_seq) or []) if saved_seq is not None else []
        )
        rhs_items = _mapping_items(right)
        if rhs_items is not None or left_items:
            by_key: dict[object, ast.AST] = {}
            for k, v in left_items:
                if isinstance(k, ast.Constant) and v is not None:
                    by_key[k.value] = v
            for k, v in rhs_items or []:
                if isinstance(k, ast.Constant) and v is not None:
                    by_key[k.value] = v
            if by_key:
                sequence_view_aliases[name] = ast.Dict(
                    keys=[ast.Constant(value=k) for k in by_key],
                    values=list(by_key.values()),
                )
            elif rhs_items is not None:
                sequence_view_aliases[name] = ast.Dict(
                    keys=[k for k, _ in rhs_items],
                    values=[
                        v if v is not None else ast.Constant(value=None)
                        for _, v in rhs_items
                    ],
                )

    def _note_container_mutation(call: ast.Call) -> None:
        """``d.update(...)`` / getattr/Name-bound / ``operator.setitem`` grow packs."""

        func = _peel_transparent_callee(call.func)
        # ``operator.setitem(d, "e", exec)`` / renamed setitem.
        # ``operator.iadd|iconcat|ior(xs, [exec])`` merge packs in place.
        proj = _projection_factory_name(
            call,
            projection_aliases=operator_projection_aliases,
            getattr_aliases=frozenset(getattr_aliases),
        )
        if proj in _INPLACE_MERGE_FUNCS | _INPLACE_MERGE_METHODS and len(call.args) >= 2:
            _merge_inplace_pack(call.args[0], call.args[1])
            return
        if proj == "setitem" and len(call.args) >= 3:
            base = _peel_call_func(call.args[0])
            carrier = _chainmap_carrier_name(base)
            if carrier is None:
                carrier = _ns_dict_carrier_name(base)
            if carrier is not None:
                _grow_named_pack(
                    carrier, "__setitem__", list(call.args[1:3]), ()
                )
            return
        # Packed ``[partial(operator.setitem, vars(ns), "e")][0](exec)`` /
        # BoolOp / IfExp partial(setitem) peels (Name-bound ``p=partial(...);
        # p(exec)`` already closed via factory products).
        for cand in _callee_candidate_exprs(call.func):
            cand = _peel_call_func(cand)
            if not (
                isinstance(cand, ast.Call)
                and _is_partial_factory(
                    cand,
                    partial_aliases=frozenset(partial_aliases),
                    getattr_aliases=frozenset(getattr_aliases),
                )
                and len(cand.args) >= 3
            ):
                continue
            bound0 = _peel_call_func(cand.args[0])
            is_setitem = False
            if isinstance(bound0, ast.Name) and (
                bound0.id == "setitem"
                or operator_projection_aliases.get(bound0.id) == "setitem"
            ):
                is_setitem = True
            elif isinstance(bound0, ast.Attribute) and (
                bound0.attr == "setitem"
                or _canonical_projection_name(bound0.attr) == "setitem"
            ):
                is_setitem = True
            elif isinstance(bound0, ast.Call):
                gname = _getattr_static_name(
                    bound0, getattr_aliases=frozenset(getattr_aliases)
                )
                if gname == "setitem" or _canonical_projection_name(gname) == "setitem":
                    is_setitem = True
            if not is_setitem:
                continue
            base = _peel_call_func(cand.args[1])
            carrier = _chainmap_carrier_name(base)
            if carrier is None:
                carrier = _ns_dict_carrier_name(base)
            if carrier is not None and call.args:
                _grow_named_pack(
                    carrier,
                    "__setitem__",
                    [cand.args[2], call.args[0]],
                    (),
                )
                return
        # ``methodcaller("append", {…})(getattr(cm,"maps"))`` /
        # ``methodcaller("update|setdefault|__setitem__", …)(vars(ns))`` /
        # ``next(iter([methodcaller("update", **…)]))(vars(ns))`` packed forms.
        mc_func: ast.AST | None = None
        mc_name: str | None = None
        if isinstance(func, ast.Call):
            mc_name = _methodcaller_static_name(
                func,
                projection_aliases=operator_projection_aliases,
                getattr_aliases=frozenset(getattr_aliases),
            )
            if mc_name is not None:
                mc_func = func
        if mc_func is None:
            for cand in _callee_candidate_exprs(call.func):
                cand = _peel_call_func(cand)
                if isinstance(cand, ast.Call):
                    cand_mc = _methodcaller_static_name(
                        cand,
                        projection_aliases=operator_projection_aliases,
                        getattr_aliases=frozenset(getattr_aliases),
                    )
                    if cand_mc is not None:
                        mc_func = cand
                        mc_name = cand_mc
                        break
        if isinstance(mc_func, ast.Call):
            if mc_name is None:
                mc_name = _methodcaller_static_name(
                    mc_func,
                    projection_aliases=operator_projection_aliases,
                    getattr_aliases=frozenset(getattr_aliases),
                )
            if (
                mc_name
                in _PACK_ADD_METHODS
                | _INPLACE_MERGE_METHODS
                | {"update", "setdefault", "__setitem__"}
                and call.args
            ):
                maps_parts = _chainmap_list_parts(call.args[0])
                if maps_parts is not None:
                    cm_name, _maps_attr = maps_parts
                    bound_args = list(mc_func.args[1:]) + list(call.args[1:])
                    if mc_name in _INPLACE_MERGE_METHODS and bound_args:
                        _merge_inplace_pack(
                            ast.Name(id=cm_name, ctx=ast.Load()), bound_args[0]
                        )
                    else:
                        grow = (
                            "update"
                            if mc_name in _PACK_ADD_METHODS
                            else mc_name
                        )
                        _grow_named_pack(
                            cm_name, grow, bound_args, call.keywords
                        )
                    return
                ns_name = _ns_dict_carrier_name(call.args[0])
                if ns_name is not None and mc_name in {
                    "update",
                    "setdefault",
                    "__setitem__",
                } | _INPLACE_MERGE_METHODS:
                    bound_args = list(mc_func.args[1:]) + list(call.args[1:])
                    # Factory-bound kwargs: ``methodcaller("update", m=…)(vars)``.
                    bound_keywords = list(mc_func.keywords) + list(call.keywords)
                    if mc_name in _INPLACE_MERGE_METHODS and bound_args:
                        _merge_inplace_pack(
                            ast.Name(id=ns_name, ctx=ast.Load()), bound_args[0]
                        )
                    else:
                        _grow_named_pack(
                            ns_name, mc_name, bound_args, bound_keywords
                        )
                    return
                if (
                    isinstance(_peel_call_func(call.args[0]), ast.Name)
                    and mc_name in _INPLACE_MERGE_METHODS
                ):
                    bound_args = list(mc_func.args[1:]) + list(call.args[1:])
                    if bound_args:
                        _merge_inplace_pack(call.args[0], bound_args[0])
                        return
        # ``getattr(d, "update")(...)`` / ``getattr(dict, "update")(d, ...)`` /
        # ``getattr(cm.maps, "append")(...)`` / ``getattr(cm, "maps").append``.
        if isinstance(func, ast.Call):
            gname = _getattr_static_name(
                func, getattr_aliases=frozenset(getattr_aliases)
            )
            if gname is not None and func.args:
                recv = _peel_call_func(func.args[0])
                # ``getattr(cm.maps, "append|extend|insert|__iadd__")(...)``.
                maps_parts = _chainmap_list_parts(recv)
                if (
                    maps_parts is not None
                    and gname in _PACK_ADD_METHODS | _INPLACE_MERGE_METHODS
                ):
                    cm_name, _maps_attr = maps_parts
                    if gname in _INPLACE_MERGE_METHODS and call.args:
                        _merge_inplace_pack(
                            ast.Name(id=cm_name, ctx=ast.Load()), call.args[0]
                        )
                    else:
                        _grow_named_pack(
                            cm_name, "update", call.args, call.keywords
                        )
                    return
                if gname in _INPLACE_MERGE_METHODS and call.args:
                    # ``getattr(d, "__ior__")({…})`` / ``getattr(list, "__iadd__")``.
                    if _is_dict_constructor(
                        recv,
                        dict_ctor_aliases=frozenset(dict_ctor_aliases),
                        getattr_aliases=frozenset(getattr_aliases),
                    ) or (
                        isinstance(recv, ast.Name)
                        and recv.id in {"list", "set", "tuple", "dict"}
                    ):
                        if len(call.args) >= 2:
                            _merge_inplace_pack(call.args[0], call.args[1])
                        return
                    _merge_inplace_pack(recv, call.args[0])
                    return
                if gname in {"update", "setdefault", "__setitem__"}:
                    if _is_dict_constructor(
                        recv,
                        dict_ctor_aliases=frozenset(dict_ctor_aliases),
                        getattr_aliases=frozenset(getattr_aliases),
                    ):
                        # Unbound ``getattr(dict, "update")(vars(ns)|d, ...)`` —
                        # share NS carrier resolution with ``d.update``.
                        if call.args:
                            target = _peel_call_func(call.args[0])
                            ns_name = _ns_dict_carrier_name(target)
                            if ns_name is not None:
                                _grow_named_pack(
                                    ns_name,
                                    gname,
                                    list(call.args[1:]),
                                    call.keywords,
                                )
                            elif isinstance(target, ast.Name):
                                root = ns_dict_alias_roots.get(target.id, target.id)
                                _grow_named_pack(
                                    root,
                                    gname,
                                    list(call.args[1:]),
                                    call.keywords,
                                )
                    else:
                        ns_name = _ns_dict_carrier_name(recv)
                        if ns_name is not None:
                            _grow_named_pack(
                                ns_name, gname, call.args, call.keywords
                            )
                        elif isinstance(recv, ast.Name):
                            _grow_named_pack(
                                recv.id, gname, call.args, call.keywords
                            )
                    return
        # Name-bound ``u = d.update; u(...)`` / ``u = dict.update; u(d, ...)``.
        if isinstance(func, ast.Name) and func.id in dict_view_products:
            view = dict_view_products[func.id]
            base_attr = view.split(".")[-1]
            if base_attr not in {
                "update",
                "setdefault",
                "__setitem__",
            } | _PACK_ADD_METHODS | _INPLACE_MERGE_METHODS:
                return
            if view.startswith("dict.") and call.args:
                recv = _peel_call_func(call.args[0])
                maps_parts = _chainmap_list_parts(recv)
                if maps_parts is not None and base_attr in _PACK_ADD_METHODS | _INPLACE_MERGE_METHODS:
                    cm_name, _ = maps_parts
                    if base_attr in _INPLACE_MERGE_METHODS and len(call.args) >= 2:
                        _merge_inplace_pack(call.args[0], call.args[1])
                    else:
                        _grow_named_pack(
                            cm_name, "update", list(call.args[1:]), call.keywords
                        )
                    return
                ns_name = _ns_dict_carrier_name(recv)
                if ns_name is not None and base_attr in {
                    "update",
                    "setdefault",
                    "__setitem__",
                }:
                    _grow_named_pack(
                        ns_name, base_attr, list(call.args[1:]), call.keywords
                    )
                    return
                if isinstance(recv, ast.Name):
                    _grow_named_pack(
                        recv.id, base_attr, list(call.args[1:]), call.keywords
                    )
                return
            recv_name = bound_view_receivers.get(func.id)
            if recv_name is not None:
                maps_parts = _chainmap_list_parts(
                    ast.Name(id=recv_name, ctx=ast.Load())
                )
                if maps_parts is not None and base_attr in _PACK_ADD_METHODS | _INPLACE_MERGE_METHODS:
                    cm_name, _ = maps_parts
                    if base_attr in _INPLACE_MERGE_METHODS and call.args:
                        _merge_inplace_pack(
                            ast.Name(id=cm_name, ctx=ast.Load()), call.args[0]
                        )
                    else:
                        _grow_named_pack(
                            cm_name, "update", call.args, call.keywords
                        )
                    return
                root = ns_dict_alias_roots.get(recv_name, recv_name)
                _grow_named_pack(root, base_attr, call.args, call.keywords)
            return
        # ``getattr(cm, "maps").append(...)`` — Attribute on getattr Call.
        if isinstance(func, ast.Attribute):
            attr = func.attr
            base = _peel_call_func(func.value)
            maps_parts = _chainmap_list_parts(base)
            if (
                maps_parts is not None
                and attr in _PACK_ADD_METHODS | _INPLACE_MERGE_METHODS
            ):
                cm_name, _maps_attr = maps_parts
                if attr in _INPLACE_MERGE_METHODS and call.args:
                    _merge_inplace_pack(
                        ast.Name(id=cm_name, ctx=ast.Load()), call.args[0]
                    )
                else:
                    _grow_named_pack(cm_name, "update", call.args, call.keywords)
                return
        if not isinstance(func, ast.Attribute):
            # Packed / BoolOp / IfExp unbound mutators:
            # ``[list.append][0](getattr(cm,"maps"), …)`` /
            # ``(False or list.append)(…)`` / ``getattr(builtins,"list").append``.
            for cand in _callee_candidate_exprs(call.func):
                cand = _peel_transparent_callee(cand)
                if isinstance(cand, ast.Attribute) and cand.attr in (
                    _PACK_ADD_METHODS
                    | _INPLACE_MERGE_METHODS
                    | {"update", "setdefault", "__setitem__"}
                ):
                    _note_container_mutation(
                        ast.Call(
                            func=cand,
                            args=list(call.args),
                            keywords=list(call.keywords),
                        )
                    )
                    return
                if isinstance(cand, ast.Call):
                    gname = _getattr_static_name(
                        cand, getattr_aliases=frozenset(getattr_aliases)
                    )
                    if gname in {"list", "set", "tuple", "dict"} and call.args:
                        # ``getattr(builtins,"list").append`` arrives as
                        # Attribute on getattr Call — handled above via
                        # ``_callee_candidate_exprs`` Attribute expansion.
                        continue
            return
        attr = func.attr
        base = _peel_call_func(func.value)
        # ``cm.maps.append|insert|extend|__iadd__({…})`` / Name-bound maps.
        maps_parts = _chainmap_list_parts(base)
        if (
            maps_parts is not None
            and attr in _PACK_ADD_METHODS | _INPLACE_MERGE_METHODS
        ):
            cm_name, _maps_attr = maps_parts
            if attr in _INPLACE_MERGE_METHODS and call.args:
                _merge_inplace_pack(
                    ast.Name(id=cm_name, ctx=ast.Load()), call.args[0]
                )
            else:
                _grow_named_pack(cm_name, "update", call.args, call.keywords)
            return
        # ``cm.maps[0].update({…})`` / ``cm.maps[0].__iadd__`` — child mapping.
        carrier = _chainmap_carrier_name(base)
        if carrier is not None and attr in {
            "update",
            "setdefault",
            "__setitem__",
        } | _PACK_ADD_METHODS | _INPLACE_MERGE_METHODS:
            if attr in _INPLACE_MERGE_METHODS and call.args:
                _merge_inplace_pack(
                    ast.Name(id=carrier, ctx=ast.Load()), call.args[0]
                )
            else:
                grow_attr = "update" if attr in _PACK_ADD_METHODS else attr
                _grow_named_pack(carrier, grow_attr, call.args, call.keywords)
            return
        # ``xs.__iadd__([exec])`` / ``s.__ior__({exec})`` / ``list.__iadd__(xs, …)``
        # / unbound ``list.append(getattr(cm,"maps"), …)`` /
        # ``from builtins import list as L; L.append(...)``.
        unbound_list_name = (
            isinstance(base, ast.Name)
            and (
                base.id in {"list", "set", "tuple", "dict"}
                or base.id in dict_ctor_aliases
                or operator_projection_aliases.get(base.id)
                in {"list", "set", "tuple", "dict"}
            )
        )
        unbound_list_attr = (
            isinstance(base, ast.Attribute)
            and base.attr in {"list", "set", "tuple", "dict"}
        )
        unbound_list_getattr = (
            isinstance(base, ast.Call)
            and _getattr_static_name(
                base, getattr_aliases=frozenset(getattr_aliases)
            )
            in {"list", "set", "tuple", "dict"}
        )
        unbound_list = (
            unbound_list_name
            or unbound_list_attr
            or unbound_list_getattr
            or _is_dict_constructor(
                base,
                dict_ctor_aliases=frozenset(dict_ctor_aliases),
                getattr_aliases=frozenset(getattr_aliases),
            )
        )
        if attr in _INPLACE_MERGE_METHODS:
            if unbound_list and len(call.args) >= 2:
                _merge_inplace_pack(call.args[0], call.args[1])
            elif call.args:
                _merge_inplace_pack(base, call.args[0])
            return
        if (
            unbound_list
            and attr in _PACK_ADD_METHODS
            and call.args
        ):
            maps_parts = _chainmap_list_parts(call.args[0])
            if maps_parts is not None:
                cm_name, _ = maps_parts
                _grow_named_pack(
                    cm_name, "update", list(call.args[1:]), call.keywords
                )
                return
        # Unbound ``dict.update(d, ...)``.
        if (
            attr in {"update", "setdefault", "__setitem__"}
            and _is_dict_constructor(
                base,
                dict_ctor_aliases=frozenset(dict_ctor_aliases),
                getattr_aliases=frozenset(getattr_aliases),
            )
            and call.args
        ):
            recv = _peel_call_func(call.args[0])
            ns_name = _ns_dict_carrier_name(recv)
            if ns_name is not None:
                _grow_named_pack(
                    ns_name, attr, list(call.args[1:]), call.keywords
                )
                return
            if isinstance(recv, ast.Name):
                _grow_named_pack(
                    recv.id, attr, list(call.args[1:]), call.keywords
                )
            return
        # ``vars(ns).update|setdefault(...)`` / ``ns.__dict__.update(...)``.
        if attr in {"update", "setdefault", "__setitem__"}:
            ns_name = _ns_dict_carrier_name(base)
            if ns_name is not None:
                _grow_named_pack(ns_name, attr, call.args, call.keywords)
                return
        if not isinstance(base, ast.Name):
            return
        root = ns_dict_alias_roots.get(base.id, base.id)
        _grow_named_pack(root, attr, call.args, call.keywords)

    def _seed_pack_binder(
        name: str,
        pack: Mapping[object, tuple[str, ...]],
        *,
        active_classes: dict[str, ast.ClassDef],
    ) -> None:
        """Bind ``name`` to a container pack (star binder / mapping ``**rest``)."""

        if not pack:
            container_packs.pop(name, None)
            return
        container_packs[name] = dict(pack)
        class_names = [
            n
            for n in _flat_pack_names(pack)
            if _lookup_class(n, active_classes) is not None
        ]
        if class_names:
            class_projection_products[name] = class_names
            src = _lookup_class(class_names[0], active_classes)
            if src is not None:
                active_classes[name] = src
                class_registry[name] = src
        else:
            class_projection_products.pop(name, None)

    def _seed_name_from_elements(
        name: str,
        items: Sequence[ast.AST],
        *,
        active_classes: dict[str, ast.ClassDef],
    ) -> None:
        """Bind ``name`` to the may-union of ``items`` (shared protocol/class seed)."""

        if not items:
            return
        keep_tables = (
            type_protocol_products,
            dict_view_products,
            projection_factory_products,
            partial_product_names,
            operator_projection_aliases,
            bound_callee_exprs,
        )
        kept: dict[int, object] = {}
        pack_union: dict[object, tuple[str, ...]] = {}
        class_union: list[str] = []
        for item in items:
            _note_protocol_alias_from_value(name, item)
            for index, table in enumerate(keep_tables):
                if name in table and index not in kept:
                    kept[index] = table[name]  # type: ignore[index]
            pack_union = _pack_union(pack_union, container_packs.get(name))
            class_union.extend(class_projection_products.get(name, ()))
            class_union.extend(_packed_names_deep(item))
        for index, table in enumerate(keep_tables):
            if index in kept:
                table[name] = kept[index]  # type: ignore[index]
        if pack_union:
            container_packs[name] = pack_union
        class_names = [
            n
            for n in dict.fromkeys(class_union)
            if _lookup_class(n, active_classes) is not None
        ]
        if class_names:
            class_projection_products[name] = class_names
            src = _lookup_class(class_names[0], active_classes)
            if src is not None:
                active_classes[name] = src
                class_registry[name] = src
        else:
            class_projection_products.pop(name, None)

    def _distribute_items(
        slot_count: int,
        star_index: int | None,
        items: Sequence[ast.AST],
    ) -> list[list[ast.AST]]:
        """Distribute unpacked ``items`` over target / pattern slots.

        Literal sequences and resolvable iterables align positionally when the
        arity matches; otherwise every slot receives every element (may-alias).
        The star slot receives synthetic Lists of its middle elements.
        """

        slots: list[list[ast.AST]] = [[] for _ in range(slot_count)]
        for item in items:
            item = _peel_call_func(item)
            if isinstance(item, (ast.Tuple, ast.List)) and not any(
                isinstance(e, ast.Starred) for e in item.elts
            ):
                elems: list[ast.AST] | None = list(item.elts)
            else:
                elems = _iter_elements(item)
            if elems is None:
                continue
            count = len(elems)
            if star_index is None:
                if count == slot_count:
                    for i, elem in enumerate(elems):
                        slots[i].append(elem)
                elif (
                    count == 1
                    and isinstance(elems[0], (ast.Tuple, ast.List))
                    and len(elems[0].elts) == slot_count
                    and not any(isinstance(e, ast.Starred) for e in elems[0].elts)
                ):
                    # ``k, f = d.popitem()`` / single pair from items view.
                    for i, elem in enumerate(elems[0].elts):
                        slots[i].append(elem)
                else:
                    for i in range(slot_count):
                        slots[i].extend(elems)
                continue
            after = slot_count - 1 - star_index
            if count >= star_index + after:
                for i in range(star_index):
                    slots[i].append(elems[i])
                slots[star_index].append(
                    ast.List(elts=list(elems[star_index : count - after]), ctx=ast.Load())
                )
                for j in range(after):
                    slots[star_index + 1 + j].append(elems[count - after + j])
            else:
                for i in range(slot_count):
                    if i == star_index:
                        slots[i].append(ast.List(elts=list(elems), ctx=ast.Load()))
                    else:
                        slots[i].extend(elems)
        return slots

    def _seed_star_binder(
        name: str,
        lists: Sequence[ast.AST],
        *,
        active_classes: dict[str, ast.ClassDef],
    ) -> None:
        """``*xs`` / ``case [*xs]`` binders pack the union of their middle lists."""

        elts: list[ast.AST] = []
        for lst in lists:
            if isinstance(lst, ast.List):
                elts.extend(lst.elts)
        if not elts:
            return
        synthetic = ast.List(elts=elts, ctx=ast.Load())
        _note_protocol_alias_from_value(name, synthetic)
        _seed_pack_binder(
            name,
            _container_pack_from_expr(synthetic) or {},
            active_classes=active_classes,
        )

    def _seed_unpack_union(
        target: ast.AST,
        items: Sequence[ast.AST],
        *,
        active_classes: dict[str, ast.ClassDef],
    ) -> None:
        """Seed ``target`` from the may-union of ``items`` (For / Assign / Match)."""

        if not items:
            return
        if isinstance(target, ast.Name):
            _seed_name_from_elements(target.id, items, active_classes=active_classes)
            return
        if isinstance(target, ast.Starred):
            _seed_unpack_union(target.value, items, active_classes=active_classes)
            return
        if isinstance(target, (ast.Tuple, ast.List)):
            star_index = next(
                (i for i, e in enumerate(target.elts) if isinstance(e, ast.Starred)),
                None,
            )
            slots = _distribute_items(len(target.elts), star_index, items)
            for index, (sub_target, slot) in enumerate(zip(target.elts, slots)):
                if isinstance(sub_target, ast.Starred):
                    if isinstance(sub_target.value, ast.Name):
                        _seed_star_binder(
                            sub_target.value.id, slot, active_classes=active_classes
                        )
                    continue
                _seed_unpack_union(sub_target, slot, active_classes=active_classes)

    def _seed_for_iter_class_aliases(
        target: ast.AST,
        iter_expr: ast.AST,
        *,
        active_classes: dict[str, ast.ClassDef],
    ) -> None:
        """Seed For/AsyncFor targets from the iterated element union.

        Shared with Assign / star unpack and Match binds: class, exec/eval,
        type-protocol, operator.call and container-pack aliases all flow
        through ``_note_protocol_alias_from_value`` per element.
        """

        elems = _iter_elements(iter_expr)
        if elems is None:
            return
        _seed_unpack_union(target, elems, active_classes=active_classes)

    def _seed_assign_unpack_aliases(
        target: ast.AST,
        value: ast.AST,
        *,
        active_classes: dict[str, ast.ClassDef],
    ) -> None:
        """Seed class/protocol/container aliases through Assign unpack peels.

        Shared path for ``C, = [Cls]`` / ``[C] = {Cls: 1}.keys()`` /
        ``C = next(iter({Mut: 1}))`` / ``*xs, = [Mut]`` so later ``C()`` /
        ``xs[0]()`` observe construction (Unknown > false PASS).
        """

        if isinstance(target, ast.Name):
            # ``C = next(iter({Mut: 1}))`` / ``C = next(iter(k()))`` seeds from
            # yielded elements. Do NOT flatten dict view Calls (``k()`` /
            # ``d.keys()``) — those stay sequence/view carriers for later unpack.
            # Do NOT peel Dict/List literals — that would replace a mapping pack.
            peeled = _peel_call_func(value)
            if isinstance(peeled, ast.Subscript):
                # ``C = list(k())[0]`` / ``C = next(k().__iter__())`` via
                # shared element peel on the subscript carrier.
                # Full / partial slices (``views = xs[:]`` / ``copy.copy(xs)[:]``)
                # keep the sequence carrier — do NOT flatten into element packs
                # (that would overwrite the list alias with the first element
                # and false-PASS later ``views[0]['v']()``).
                if isinstance(peeled.slice, ast.Slice):
                    return
                base = _peel_call_func(peeled.value)
                elems = _iter_elements(base)
                key = _static_key(peeled.slice)
                if elems is not None:
                    if isinstance(key, int) and 0 <= key < len(elems):
                        elems = [elems[key]]
                    _seed_name_from_elements(
                        target.id, elems, active_classes=active_classes
                    )
                return
            if isinstance(peeled, ast.Call):
                view = _view_call_parts(peeled)
                if view is not None and view[0] in _DICT_ITER_VIEW_ATTRS:
                    return
                fpeeled = _peel_call_func(peeled.func)
                fname: str | None = None
                if isinstance(fpeeled, ast.Name):
                    fname = operator_projection_aliases.get(fpeeled.id, fpeeled.id)
                elif isinstance(fpeeled, ast.Attribute):
                    fname = fpeeled.attr
                if fname == "next":
                    elems = _iter_elements(value)
                    if elems is not None:
                        _seed_name_from_elements(
                            target.id, elems, active_classes=active_classes
                        )
            return
        # ``a, b = itertools.tee([exec])`` — each binder aliases the source
        # iterable (not a single yielded element).
        tee_src: ast.AST | None = None
        peeled_val = _peel_call_func(value)
        if isinstance(peeled_val, ast.Call):
            tname = _itertools_adapter_name(
                peeled_val.func,
                projection_aliases=operator_projection_aliases,
                getattr_aliases=frozenset(getattr_aliases),
            )
            if tname == "tee" and peeled_val.args:
                tee_src = peeled_val.args[0]
        if tee_src is not None and isinstance(target, (ast.Tuple, ast.List)):
            for elt in target.elts:
                if isinstance(elt, ast.Name):
                    sequence_view_aliases[elt.id] = tee_src
                    _note_protocol_alias_from_value(elt.id, tee_src)
                    _note_container_pack_from_value(elt.id, tee_src)
            return
        # Tuple/List unpack still peels ``value`` inside ``_distribute_items``
        # so ``C, = d.keys()`` resolves the view Call (not pre-flattened elts).
        _seed_unpack_union(target, [value], active_classes=active_classes)

    def _seed_match_binds(
        pattern: ast.AST,
        items: Sequence[ast.AST],
        *,
        active_classes: dict[str, ast.ClassDef],
        on_class_alias: Callable[[str, ast.AST], None] | None = None,
    ) -> None:
        """Seed Match pattern binders from the may-union of subject ``items``.

        Subjects normalize through the shared element / mapping resolvers
        (walrus, Name-bound packs, ``dict()`` constructors, ``**`` spreads,
        non-constant keys, ``.items()`` views, zip / enumerate / comps) before
        MatchAs / MatchSequence / MatchMapping ``rest`` / MatchStar seeding, so
        ``match d: case {**rest}: rest["c"]()`` observes construction.
        """

        if not items:
            return
        if isinstance(pattern, ast.MatchAs):
            if pattern.name:
                _seed_name_from_elements(
                    pattern.name, items, active_classes=active_classes
                )
                for item in items:
                    peeled = _peel_call_func(item)
                    packed_inst: str | None = None
                    if isinstance(peeled, ast.Call) and isinstance(
                        peeled.func, ast.Name
                    ):
                        packed_inst = peeled.func.id
                    elif isinstance(peeled, ast.Name):
                        packed_inst = instance_class_of.get(peeled.id)
                    if packed_inst is not None and _lookup_class(
                        packed_inst, active_classes
                    ) is not None:
                        instance_class_of[pattern.name] = packed_inst
                    if on_class_alias is not None and isinstance(peeled, ast.Name):
                        if _lookup_class(peeled.id, active_classes) is not None:
                            on_class_alias(pattern.name, peeled)
            if pattern.pattern is not None:
                _seed_match_binds(
                    pattern.pattern,
                    items,
                    active_classes=active_classes,
                    on_class_alias=on_class_alias,
                )
            return
        if isinstance(pattern, ast.MatchSequence):
            star_index = next(
                (
                    i
                    for i, sub in enumerate(pattern.patterns)
                    if isinstance(sub, ast.MatchStar)
                ),
                None,
            )
            slots = _distribute_items(len(pattern.patterns), star_index, items)
            for sub_pat, slot in zip(pattern.patterns, slots):
                if isinstance(sub_pat, ast.MatchStar):
                    if sub_pat.name:
                        _seed_star_binder(
                            sub_pat.name, slot, active_classes=active_classes
                        )
                    continue
                _seed_match_binds(
                    sub_pat,
                    slot,
                    active_classes=active_classes,
                    on_class_alias=on_class_alias,
                )
            return
        if isinstance(pattern, ast.MatchMapping):
            entries: list[tuple[ast.AST | None, ast.AST | None]] = []
            for item in items:
                resolved = _mapping_items(item)
                if resolved is not None:
                    entries.extend(resolved)
            fixed_keys: set[object] = set()
            for key_node, sub_pat in zip(pattern.keys, pattern.patterns):
                if isinstance(key_node, ast.Constant):
                    fixed_keys.add(key_node.value)
                    selected = [
                        val
                        for key, val in entries
                        if val is not None
                        and (
                            not isinstance(key, ast.Constant)
                            or key.value == key_node.value
                        )
                    ]
                else:
                    selected = [val for _, val in entries if val is not None]
                _seed_match_binds(
                    sub_pat,
                    selected,
                    active_classes=active_classes,
                    on_class_alias=on_class_alias,
                )
            if pattern.rest is not None:
                remaining = [
                    (key, val)
                    for key, val in entries
                    if not (
                        isinstance(key, ast.Constant) and key.value in fixed_keys
                    )
                ]
                _seed_pack_binder(
                    pattern.rest,
                    _pack_from_items(remaining),
                    active_classes=active_classes,
                )
                # Preserve Attribute values (``Mut.make``) for later
                # ``rest["m"].__call__()`` method peels (Unknown > false PASS).
                if remaining:
                    sequence_view_aliases[pattern.rest] = ast.Dict(
                        keys=[k for k, _ in remaining],
                        values=[
                            v if v is not None else ast.Constant(value=None)
                            for _, v in remaining
                        ],
                    )
            return
        if isinstance(pattern, ast.MatchOr):
            for alt in pattern.patterns:
                _seed_match_binds(
                    alt,
                    items,
                    active_classes=active_classes,
                    on_class_alias=on_class_alias,
                )
            return
        if isinstance(pattern, ast.MatchClass):
            # ``match ns: case SimpleNamespace(m=mk): mk()`` — seed kwd attrs
            # from subject mapping / NS packs (shared with attr peels).
            entries: list[tuple[ast.AST | None, ast.AST | None]] = []
            for item in items:
                resolved = _mapping_items(item)
                if resolved is not None:
                    entries.extend(resolved)
                else:
                    peeled = _peel_call_func(item)
                    if isinstance(peeled, ast.Name) and peeled.id in sequence_view_aliases:
                        nested = _mapping_items(sequence_view_aliases[peeled.id])
                        if nested is not None:
                            entries.extend(nested)
            for attr_name, sub_pat in zip(pattern.kwd_attrs, pattern.kwd_patterns):
                selected = [
                    val
                    for key, val in entries
                    if val is not None
                    and isinstance(key, ast.Constant)
                    and key.value == attr_name
                ]
                if not selected:
                    # Also project from Name-bound container packs by attr.
                    for item in items:
                        peeled = _peel_call_func(item)
                        if isinstance(peeled, ast.Name) and peeled.id in container_packs:
                            for pname in container_packs[peeled.id].get(attr_name, ()):
                                if pname in bound_callee_exprs:
                                    selected.append(bound_callee_exprs[pname])
                                else:
                                    selected.append(
                                        ast.Name(id=pname, ctx=ast.Load())
                                    )
                _seed_match_binds(
                    sub_pat,
                    selected,
                    active_classes=active_classes,
                    on_class_alias=on_class_alias,
                )
            for sub_pat in pattern.patterns:
                _seed_match_binds(
                    sub_pat,
                    items,
                    active_classes=active_classes,
                    on_class_alias=on_class_alias,
                )
            return

    def _base_is_namespace_projection(base: ast.AST) -> bool:
        """True for ``types.__dict__`` / ``vars(types)`` / ``getattr(..., "__dict__")``."""

        base = _peel_call_func(base)
        if isinstance(base, ast.Attribute) and base.attr == "__dict__":
            return True
        # Name-bound namespace carriers: ``ns = types.__dict__; ns.get(...)``.
        if isinstance(base, ast.Name) and base.id in ns_dict_aliases:
            return True
        if isinstance(base, ast.Call):
            bfunc = _peel_call_func(base.func)
            if isinstance(bfunc, ast.Name) and (
                bfunc.id in {"vars", "globals", "locals"}
                or bfunc.id in ns_projection_aliases
            ):
                return True
            if isinstance(bfunc, ast.Attribute) and bfunc.attr in {
                "vars",
                "globals",
                "locals",
            }:
                return True
            if (
                _getattr_static_name(base, getattr_aliases=frozenset(getattr_aliases))
                == "__dict__"
            ):
                return True
        return False

    def _seed_ns_key_aliases(name: str, key: str) -> None:
        if key == "MappingProxyType":
            adapter_aliases.add(name)
        if key in _MAPPING_CTOR_NAMES:
            dict_ctor_aliases.add(name)
        if key == "list":
            # ``L = vars(builtins).get("list")`` / ``__dict__.get("list")`` /
            # ``__getitem__("list")`` — share subscript ``["list"]`` seed
            # for unbound ``L.sort`` key= peels (Unknown > false PASS).
            operator_projection_aliases[name] = "list"
            dict_ctor_aliases.add(name)
        if key in _OPERATOR_PROJECTION_NAMES:
            operator_projection_aliases[name] = key
        if key in _EXEC_EVAL_COMPILE_NAMES:
            exec_eval_compile_aliases.add(name)
        if key == _TYPE_BUILTIN_NAME:
            type_aliases.add(name)
        if key == "partial":
            partial_aliases.add(name)
        if key == "getattr":
            getattr_aliases.add(name)

    def _note_adapter_from_subscript(name: str, value: ast.AST) -> None:
        """``Proxy = vars(types)["MappingProxyType"]`` / ``types.__dict__[…]``."""

        if not isinstance(value, ast.Subscript):
            return
        key = _resolve_static_str(value.slice)
        if key is None:
            return
        if not _base_is_namespace_projection(value.value):
            # Ordinary dict key projection of a class: ``m = d["Mut"]``.
            class_projection_products[name] = list(
                dict.fromkeys([key, *_packed_names(value.value)])
            )
            return
        _seed_ns_key_aliases(name, key)

    def _note_class_product_from_value(name: str, value: ast.AST) -> None:
        """Track intermediate class carriers: ``m = gi({"Mut": Mut}, "Mut")``."""

        value = _peel_call_func(value)
        if isinstance(value, ast.Name):
            if value.id in class_projection_products:
                class_projection_products[name] = list(
                    class_projection_products[value.id]
                )
            elif value.id in class_registry:
                class_projection_products[name] = [value.id]
            else:
                class_projection_products.pop(name, None)
            return
        if isinstance(value, ast.Subscript):
            key = _static_str(value.slice)
            names = list(_packed_names(value))
            if key is not None and key not in names:
                names.insert(0, key)
            if names:
                class_projection_products[name] = names
            else:
                class_projection_products.pop(name, None)
            return
        if isinstance(value, ast.Call):
            names = list(_packed_names(value))
            # Bound ``g = {}.get; m = g("missing", Mut)``.
            fpeeled = _peel_call_func(value.func)
            if isinstance(fpeeled, ast.Name) and fpeeled.id in dict_view_products:
                exprs, keys = _dict_view_applied_parts(
                    dict_view_products[fpeeled.id], value.args
                )
                for expr in exprs:
                    names.extend(_packed_names_deep(expr))
                names.extend(keys)
            if names:
                class_projection_products[name] = list(dict.fromkeys(names))
            else:
                class_projection_products.pop(name, None)
            return
        class_projection_products.pop(name, None)

    def _note_protocol_alias_from_value(name: str, value: ast.AST) -> None:
        """Install exec/new_class/type/getattr aliases from an Assign/walrus RHS."""

        value = _peel_call_func(value)
        # Static string keys: ``k = "MappingProxyType"`` / ``k = keys[0]`` /
        # ``k = keys["x"]`` / ``k = keys.get("x")`` after shared projection.
        resolved_str = _resolve_static_str(value)
        if resolved_str is not None:
            string_constant_names[name] = resolved_str
            static_constant_names[name] = resolved_str
        elif isinstance(value, ast.Constant) and isinstance(
            value.value, (str, int, float, bytes, bool)
        ):
            if isinstance(value.value, str):
                string_constant_names[name] = value.value
            else:
                string_constant_names.pop(name, None)
            static_constant_names[name] = value.value
        else:
            string_constant_names.pop(name, None)
            # Preserve Name-bound int/str aliases: ``idx2 = idx``.
            if isinstance(value, ast.Name) and value.id in static_constant_names:
                static_constant_names[name] = static_constant_names[value.id]
                if value.id in string_constant_names:
                    string_constant_names[name] = string_constant_names[value.id]
            else:
                static_constant_names.pop(name, None)
        # Type protocol products first (``tn = type.__new__`` / getattr /
        # nested ``tc.__call__`` / ``type.__call__.__call__``).
        tproto = _type_protocol_attr_from_value(
            value,
            getattr_aliases=frozenset(getattr_aliases),
            protocol_products=type_protocol_products,
            type_aliases=frozenset(type_aliases),
        )
        if tproto is not None:
            type_protocol_products[name] = tproto
        else:
            type_protocol_products.pop(name, None)
        # Name-bound mapping constructors and namespace carriers (shared
        # across Name / Attribute / Subscript / Call RHS forms).
        if _is_dict_constructor(
            value,
            dict_ctor_aliases=frozenset(dict_ctor_aliases),
            getattr_aliases=frozenset(getattr_aliases),
        ):
            dict_ctor_aliases.add(name)
        if _base_is_namespace_projection(value):
            ns_dict_aliases.add(name)
            # ``d = vars(ns)`` / ``d = ns.__dict__`` → root owning namespace.
            root = _ns_dict_carrier_name(value)
            if root is not None:
                ns_dict_alias_roots[name] = root
            else:
                ns_dict_alias_roots.pop(name, None)
        else:
            ns_dict_aliases.discard(name)
            ns_dict_alias_roots.pop(name, None)
        # ``m = cm.maps`` / ``m = getattr(cm, "maps")`` ChainMap list aliases.
        maps_parts = _chainmap_list_parts(value)
        if maps_parts is not None:
            chainmap_list_aliases[name] = maps_parts
        else:
            chainmap_list_aliases.pop(name, None)
        # Sequence/view carriers: ``it = d.items()`` / ``C = next(iter(keys))`` /
        # ``fns = [n.install]`` / ``fns = {0: n.install}`` (preserve Attribute
        # elements for accounted peels — Unknown > false PASS).
        if isinstance(value, (ast.List, ast.Tuple, ast.Set, ast.Dict)):
            sequence_view_aliases[name] = value
        elif isinstance(value, ast.Call):
            view = _view_call_parts(value)
            if view is not None and view[0] in _DICT_ITER_VIEW_ATTRS | {
                "keys",
                "values",
                "items",
                "fromkeys",
            } | _MAPPING_COPY_FUNCS:
                # ``copy.copy([…])`` / ``deepcopy`` / items views — keep Call
                # so later element peels share one path.
                sequence_view_aliases[name] = value
            elif _is_dict_fromkeys(
                _peel_call_func(value.func),
                dict_ctor_aliases=frozenset(dict_ctor_aliases),
                dict_view_products=dict_view_products,
            ):
                # ``ks = fk([Mut])`` / ``ks = dict.fromkeys([Mut])``.
                sequence_view_aliases[name] = value
            elif (
                isinstance(_peel_call_func(value.func), ast.Name)
                and _peel_call_func(value.func).id  # type: ignore[union-attr]
                in {"next", "iter", "list", "tuple", "reversed"}
            ):
                sequence_view_aliases[name] = value
            else:
                elems = _iter_elements(value)
                if elems is not None:
                    sequence_view_aliases[name] = ast.List(
                        elts=list(elems), ctx=ast.Load()
                    )
                else:
                    sequence_view_aliases.pop(name, None)
        elif isinstance(value, ast.Name) and value.id in sequence_view_aliases:
            sequence_view_aliases[name] = sequence_view_aliases[value.id]
        else:
            sequence_view_aliases.pop(name, None)
        if isinstance(value, ast.Name):
            if value.id in _EXEC_EVAL_COMPILE_NAMES or value.id in exec_eval_compile_aliases:
                exec_eval_compile_aliases.add(name)
            if value.id == _TYPES_NEW_CLASS_NAME or value.id in new_class_aliases:
                new_class_aliases.add(name)
            if value.id == _TYPE_BUILTIN_NAME or value.id in type_aliases:
                type_aliases.add(name)
            if value.id in getattr_aliases:
                getattr_aliases.add(name)
            if value.id in setattr_aliases:
                setattr_aliases.add(name)
            if value.id in slice_aliases:
                slice_aliases.add(name)
            if value.id in partial_aliases:
                partial_aliases.add(name)
            if value.id in {"vars", "globals", "locals"} or value.id in ns_projection_aliases:
                ns_projection_aliases.add(name)
            if value.id in _CALLEE_ADAPTER_NAMES or value.id in adapter_aliases:
                if value.id == "MappingProxyType" or value.id in adapter_aliases:
                    adapter_aliases.add(name)
            if value.id in _MAPPING_CTOR_NAMES or value.id in dict_ctor_aliases:
                dict_ctor_aliases.add(name)
            if value.id in copy_module_aliases:
                copy_module_aliases.add(name)
            if value.id in _OPERATOR_PROJECTION_NAMES | _KEY_APPLICATOR_NAMES:
                operator_projection_aliases[name] = value.id
            elif value.id in operator_projection_aliases:
                operator_projection_aliases[name] = operator_projection_aliases[value.id]
            if value.id in dict_view_products:
                dict_view_products[name] = dict_view_products[value.id]
                if value.id in bound_view_receivers:
                    bound_view_receivers[name] = bound_view_receivers[value.id]
                else:
                    bound_view_receivers.pop(name, None)
                if value.id in bound_view_expr_receivers:
                    bound_view_expr_receivers[name] = bound_view_expr_receivers[
                        value.id
                    ]
                else:
                    bound_view_expr_receivers.pop(name, None)
            else:
                dict_view_products.pop(name, None)
                bound_view_receivers.pop(name, None)
                bound_view_expr_receivers.pop(name, None)
            if value.id in bound_callee_exprs:
                bound_callee_exprs[name] = bound_callee_exprs[value.id]
            else:
                bound_callee_exprs.pop(name, None)
            _note_factory_product_from_value(name, value)
            _note_class_product_from_value(name, value)
            _note_container_pack_from_value(name, value)
            return
        if isinstance(value, ast.Attribute):
            if value.attr in _EXEC_EVAL_COMPILE_NAMES:
                exec_eval_compile_aliases.add(name)
            if value.attr == _TYPES_NEW_CLASS_NAME:
                new_class_aliases.add(name)
            if value.attr == _TYPE_BUILTIN_NAME:
                type_aliases.add(name)
            if value.attr == "partial":
                partial_aliases.add(name)
            if value.attr == "getattr":
                getattr_aliases.add(name)
            if value.attr == "setattr":
                setattr_aliases.add(name)
            if value.attr == "slice":
                slice_aliases.add(name)
            if value.attr in {"vars", "globals", "locals"}:
                ns_projection_aliases.add(name)
            if value.attr == "MappingProxyType":
                adapter_aliases.add(name)
            if value.attr in _MAPPING_CTOR_NAMES:
                dict_ctor_aliases.add(name)
            if value.attr in _OPERATOR_PROJECTION_NAMES:
                operator_projection_aliases[name] = value.attr
            # ``d = oc.__call__`` / ``d = tc.__call__`` / ``e = d["e"].__call__``
            # — operator.call / type / exec products through transparent
            # ``__call__`` (``tc = type.__call__; d = tc.__call__; d(Mut)``).
            if value.attr == "__call__":
                if _expr_is_operator_call_receiver(
                    value.value,
                    projection_aliases=operator_projection_aliases,
                    getattr_aliases=frozenset(getattr_aliases),
                    partial_aliases=frozenset(partial_aliases),
                    adapter_aliases=frozenset(adapter_aliases),
                    container_packs=container_packs,
                    factory_products=projection_factory_products,
                    dict_view_products=dict_view_products,
                ):
                    operator_projection_aliases[name] = "call"
                recv = _peel_call_func(value.value)
                if isinstance(recv, ast.Name) and recv.id in type_protocol_products:
                    type_protocol_products[name] = type_protocol_products[recv.id]
                # Packed receivers: ``e = rest["e"].__call__`` / ``d["e"].__call__`` /
                # ``g = getattr(builtins, "sorted").__call__``.
                for pname in _packed_names(value.value):
                    if (
                        pname in _EXEC_EVAL_COMPILE_NAMES
                        or pname in exec_eval_compile_aliases
                    ):
                        exec_eval_compile_aliases.add(name)
                    if pname in operator_projection_aliases:
                        operator_projection_aliases[name] = (
                            operator_projection_aliases[pname]
                        )
                    elif pname in _KEY_APPLICATOR_NAMES | {"sort", "list.sort"}:
                        operator_projection_aliases[name] = pname
                        dict_view_products[name] = pname
                    elif _name_is_operator_call_alias(
                        pname, projection_aliases=operator_projection_aliases
                    ):
                        operator_projection_aliases[name] = "call"
                    if pname in type_protocol_products:
                        type_protocol_products[name] = type_protocol_products[pname]
                    if pname in new_class_aliases or pname == _TYPES_NEW_CLASS_NAME:
                        new_class_aliases.add(name)
            # ``fn = copy.copy`` / ``fn = copy.deepcopy`` module peels must win
            # over mapping ``.copy`` view products (shared Name applicator path).
            _copy_recv = _peel_call_func(value.value)
            _is_module_copy = value.attr in _MAPPING_COPY_FUNCS and (
                (
                    isinstance(_copy_recv, ast.Name)
                    and (
                        _copy_recv.id in copy_module_aliases
                        or operator_projection_aliases.get(_copy_recv.id) == "copy"
                    )
                )
                or (
                    isinstance(_copy_recv, ast.Attribute)
                    and _copy_recv.attr in copy_module_aliases | {"copy"}
                )
            )
            if _is_module_copy:
                operator_projection_aliases[name] = value.attr
                dict_view_products.pop(name, None)
                bound_view_receivers.pop(name, None)
                bound_view_expr_receivers.pop(name, None)
            elif value.attr in _NS_DICT_VIEW_ATTRS | _DICT_ITER_VIEW_ATTRS | _DICT_MUTATOR_ATTRS | {
                "fromkeys",
                "copy",
            }:
                if _is_dict_constructor(
                    value.value,
                    dict_ctor_aliases=frozenset(dict_ctor_aliases),
                    getattr_aliases=frozenset(getattr_aliases),
                ):
                    dict_view_products[name] = f"dict.{value.attr}"
                    bound_view_receivers.pop(name, None)
                    bound_view_expr_receivers.pop(name, None)
                else:
                    dict_view_products[name] = value.attr
                    recv = _peel_call_func(value.value)
                    if isinstance(recv, ast.Name):
                        bound_view_receivers[name] = recv.id
                        bound_view_expr_receivers.pop(name, None)
                    else:
                        # ``g = {"c": Mut}.items`` — keep Dict/Call receivers.
                        bound_view_receivers.pop(name, None)
                        bound_view_expr_receivers[name] = recv
            elif value.attr == "sort":
                sort_recv = _peel_call_func(value.value)
                # ``(0 or L).sort`` / ``(L if True else list).sort`` /
                # ``builtins.list.sort`` / ``getattr(builtins,"list").sort``.
                unbound_list_sort = _is_unbound_list_recv(sort_recv)
                if unbound_list_sort:
                    # ``g = list.sort`` / ``g = L.sort`` after
                    # ``from builtins import list as L`` — unbound key=.
                    dict_view_products[name] = "list.sort"
                    operator_projection_aliases[name] = "list.sort"
                    bound_view_receivers.pop(name, None)
                    bound_view_expr_receivers.pop(name, None)
                else:
                    # ``g = xs.sort`` — bound key= applicator on the list.
                    dict_view_products[name] = "sort"
                    operator_projection_aliases[name] = "sort"
                    if isinstance(sort_recv, ast.Name):
                        bound_view_receivers[name] = sort_recv.id
                        bound_view_expr_receivers.pop(name, None)
                    else:
                        bound_view_receivers.pop(name, None)
                        bound_view_expr_receivers[name] = sort_recv
            elif value.attr == "list":
                # ``L = builtins.list`` / ``L = getattr(builtins,"list").__…``
                # seed unbound list.sort receivers (Unknown > false PASS).
                operator_projection_aliases[name] = "list"
                dict_ctor_aliases.add(name)
                dict_view_products.pop(name, None)
                bound_view_receivers.pop(name, None)
                bound_view_expr_receivers.pop(name, None)
            else:
                dict_view_products.pop(name, None)
                bound_view_receivers.pop(name, None)
                bound_view_expr_receivers.pop(name, None)
            # ``g = ns.e`` when ``ns`` packs ``e→exec`` / SimpleNamespace attrs.
            recv = _peel_call_func(value.value)
            if isinstance(recv, ast.Name) and recv.id in container_packs:
                for pname in container_packs[recv.id].get(value.attr, ()):
                    if (
                        pname in _EXEC_EVAL_COMPILE_NAMES
                        or pname in exec_eval_compile_aliases
                    ):
                        exec_eval_compile_aliases.add(name)
                    if pname in type_protocol_products:
                        type_protocol_products[name] = type_protocol_products[pname]
                    if pname in operator_projection_aliases:
                        operator_projection_aliases[name] = (
                            operator_projection_aliases[pname]
                        )
                    src_cls = _lookup_class(pname, class_registry)
                    if src_cls is not None:
                        class_projection_products[name] = [pname]
            # ``f = n.install.__call__`` / ``m = Mut.make.__call__`` /
            # ``g = getattr(builtins, "sorted").__call__`` — peel.
            if value.attr == "__call__":
                inner = _peel_call_func(value.value)
                if isinstance(inner, ast.Attribute):
                    _note_protocol_alias_from_value(
                        name,
                        inner,
                    )
                    return
                # Key applicators via getattr / Name-bound sorted products.
                gname = None
                if isinstance(value.value, ast.Call):
                    gname = _getattr_static_name(
                        value.value,
                        getattr_aliases=frozenset(getattr_aliases),
                    )
                elif isinstance(inner, ast.Name):
                    gname = operator_projection_aliases.get(inner.id, inner.id)
                if gname in _KEY_APPLICATOR_NAMES | {"sort", "list.sort"}:
                    operator_projection_aliases[name] = gname
                    dict_view_products[name] = gname
                    bound_callee_exprs[name] = value
                    return
            # Preserve Attribute callee for For/Match Name binders / Assign.
            bound_callee_exprs[name] = value
            _note_class_product_from_value(name, value)
            _note_container_pack_from_value(name, value)
            return
        if isinstance(value, ast.Subscript):
            # ``g = p[0]`` after ``p = {0: L.sort}`` / ``{0: getattr(L,"sort")}``
            # — re-seed from the concrete element (Unknown > false PASS).
            elem = _carrier_element_at(
                value.value, _resolve_static_key_value(value.slice)
            )
            if elem is not None and elem is not value:
                peeled_elem = _peel_call_func(elem)
                if isinstance(
                    peeled_elem, (ast.Attribute, ast.Call, ast.Name, ast.Subscript)
                ):
                    _note_protocol_alias_from_value(name, peeled_elem)
                    return
            # ``L = builtins.__dict__["list"]`` / ``vars(builtins)["list"]``.
            sub_key = _resolve_static_str(value.slice)
            if sub_key == "list":
                operator_projection_aliases[name] = "list"
                dict_ctor_aliases.add(name)
            bound_callee_exprs.pop(name, None)
            _note_adapter_from_subscript(name, value)
            _note_class_product_from_value(name, value)
            _note_container_pack_from_value(name, value)
            return
        if isinstance(value, ast.Call):
            attr = _getattr_static_name(
                value, getattr_aliases=frozenset(getattr_aliases)
            )
            if attr in _EXEC_EVAL_COMPILE_NAMES:
                exec_eval_compile_aliases.add(name)
            if attr == _TYPES_NEW_CLASS_NAME:
                new_class_aliases.add(name)
            if attr == _TYPE_BUILTIN_NAME:
                type_aliases.add(name)
            if attr == "partial":
                partial_aliases.add(name)
            if attr == "getattr":
                getattr_aliases.add(name)
            if attr == "MappingProxyType":
                adapter_aliases.add(name)
            if attr in {"vars", "globals", "locals"}:
                ns_projection_aliases.add(name)
            if attr in _OPERATOR_PROJECTION_NAMES:
                operator_projection_aliases[name] = attr
            if attr in _MAPPING_CTOR_NAMES:
                dict_ctor_aliases.add(name)
            if attr == "list":
                # ``L = getattr(builtins, "list")`` —
                # seed unbound list.sort receivers.
                operator_projection_aliases[name] = "list"
                dict_ctor_aliases.add(name)
            if attr == "slice":
                slice_aliases.add(name)
            if attr == "sort" and value.args:
                # ``g = getattr(L, "sort")`` / ``getattr(list, "sort")``.
                sort_recv = _peel_call_func(value.args[0])
                if _is_unbound_list_recv(sort_recv):
                    dict_view_products[name] = "list.sort"
                    operator_projection_aliases[name] = "list.sort"
                    bound_view_receivers.pop(name, None)
                    bound_view_expr_receivers.pop(name, None)
                else:
                    dict_view_products[name] = "sort"
                    operator_projection_aliases[name] = "sort"
                    if isinstance(sort_recv, ast.Name):
                        bound_view_receivers[name] = sort_recv.id
                        bound_view_expr_receivers.pop(name, None)
                    else:
                        bound_view_receivers.pop(name, None)
                        bound_view_expr_receivers[name] = sort_recv
            # ``g = getattr(ns, "get"|"pop"|"__getitem__")`` — ns view product.
            # ``fk = getattr(dict, "fromkeys")`` — unbound dict.fromkeys product.
            if attr in _NS_DICT_VIEW_ATTRS | _DICT_ITER_VIEW_ATTRS | {"fromkeys"}:
                if attr == "fromkeys" and value.args:
                    recv = _peel_call_func(value.args[0])
                    if _is_dict_constructor(
                        recv,
                        dict_ctor_aliases=frozenset(dict_ctor_aliases),
                        getattr_aliases=frozenset(getattr_aliases),
                    ) or (
                        isinstance(recv, ast.Name) and recv.id == "dict"
                    ) or (
                        isinstance(recv, ast.Attribute) and recv.attr == "dict"
                    ):
                        dict_view_products[name] = "dict.fromkeys"
                        bound_view_receivers.pop(name, None)
                        bound_view_expr_receivers.pop(name, None)
                    else:
                        dict_view_products[name] = attr
                        if isinstance(recv, ast.Name):
                            bound_view_receivers[name] = recv.id
                            bound_view_expr_receivers.pop(name, None)
                        else:
                            bound_view_receivers.pop(name, None)
                            bound_view_expr_receivers[name] = recv
                else:
                    dict_view_products[name] = attr
                    if attr in _NS_DICT_VIEW_ATTRS | _DICT_ITER_VIEW_ATTRS | {
                        "fromkeys"
                    } and value.args:
                        recv = _peel_call_func(value.args[0])
                        if isinstance(recv, ast.Name):
                            bound_view_receivers[name] = recv.id
                            bound_view_expr_receivers.pop(name, None)
                        else:
                            bound_view_receivers.pop(name, None)
                            bound_view_expr_receivers[name] = recv
            # ``Proxy = types.__dict__.get("MappingProxyType")`` /
            # ``vars(types).get("MappingProxyType")`` /
            # ``getattr(types.__dict__, "get"|"__getitem__"|"pop")("MappingProxyType")`` /
            # ``g = getattr(ns,"get"); Proxy = g(key)`` /
            # ``getattr(getattr(ns,"get"),"__call__")(key)``.
            fpeeled = _peel_call_func(value.func)
            # Peel trailing ``.__call__`` on ns views:
            # ``getattr(ns,"setdefault").__call__("MappingProxyType")``.
            view_func = _peel_transparent_callee(value.func)
            if isinstance(view_func, ast.Attribute):
                fpeeled = view_func
            elif isinstance(view_func, ast.Call):
                fpeeled = view_func
            # Shared peel: BoolOp / IfExp / packed ``(0 or ns.get)(key)`` /
            # ``(getattr(dict,"get") if True else None)(key)``.
            ns_view_candidates = [fpeeled, *_callee_candidate_exprs(value.func)]
            seeded_ns_key = False
            for view_cand in ns_view_candidates:
                view_cand = _peel_call_func(view_cand)
                if (
                    isinstance(view_cand, ast.Attribute)
                    and view_cand.attr in _NS_DICT_VIEW_ATTRS
                    and value.args
                ):
                    key = _resolve_static_str(value.args[0])
                    if key is not None and _base_is_namespace_projection(
                        view_cand.value
                    ):
                        _seed_ns_key_aliases(name, key)
                        seeded_ns_key = True
                        break
                if isinstance(view_cand, ast.Call) and value.args:
                    # ``getattr(types.__dict__, "get"|"__getitem__"|"pop")(key)`` /
                    # ``getattr(ns, "setdefault").__call__(key)`` after peel.
                    gname = _getattr_static_name(
                        view_cand, getattr_aliases=frozenset(getattr_aliases)
                    )
                    if gname in _NS_DICT_VIEW_ATTRS and view_cand.args:
                        key = _resolve_static_str(value.args[0])
                        if key is not None and _base_is_namespace_projection(
                            view_cand.args[0]
                        ):
                            _seed_ns_key_aliases(name, key)
                            seeded_ns_key = True
                            break
                if isinstance(view_cand, ast.Name) and value.args:
                    # Name-bound ns view: ``g = getattr(ns,"get"); Proxy = g(key)`` /
                    # ``g = ns.get; Proxy = g(key)``.
                    view = dict_view_products.get(view_cand.id)
                    if (
                        view is not None
                        and view.split(".")[-1] in _NS_DICT_VIEW_ATTRS
                    ):
                        key = _resolve_static_str(value.args[0])
                        recv_name = bound_view_receivers.get(view_cand.id)
                        expr_recv = bound_view_expr_receivers.get(view_cand.id)
                        ns_recv: ast.AST | None = None
                        if recv_name is not None:
                            ns_recv = ast.Name(id=recv_name, ctx=ast.Load())
                        elif expr_recv is not None:
                            ns_recv = expr_recv
                        if key is not None and ns_recv is not None and (
                            _base_is_namespace_projection(ns_recv)
                            or (
                                isinstance(ns_recv, ast.Name)
                                and ns_recv.id in ns_dict_aliases
                            )
                        ):
                            _seed_ns_key_aliases(name, key)
                            seeded_ns_key = True
                            break
            # ``L = operator.getitem(vars(builtins)|builtins.__dict__, "list")`` /
            # BoolOp / packed getitem — share ``.get("list")`` seed.
            if not seeded_ns_key and len(value.args) >= 2:
                gi_proj = _projection_factory_name(
                    value,
                    projection_aliases=operator_projection_aliases,
                    getattr_aliases=frozenset(getattr_aliases),
                )
                if gi_proj == "getitem":
                    key = _resolve_static_str(value.args[1])
                    if key is not None and (
                        _base_is_namespace_projection(value.args[0])
                        or (
                            isinstance(_peel_call_func(value.args[0]), ast.Name)
                            and _peel_call_func(value.args[0]).id  # type: ignore[union-attr]
                            in ns_dict_aliases
                        )
                    ):
                        _seed_ns_key_aliases(name, key)
                        seeded_ns_key = True
            del seeded_ns_key
            if attr is None:
                # Applied view Call (``g(key)``) is a product, not a view binder.
                # Preserve attrgetter("sort")(L) / slice(...) seeds installed below.
                if not (
                    isinstance(fpeeled, ast.Name)
                    and fpeeled.id in dict_view_products
                ):
                    dict_view_products.pop(name, None)
                    bound_view_receivers.pop(name, None)
                    bound_view_expr_receivers.pop(name, None)
            # ``s = slice(0, 1)`` / ``builtins.slice(...)`` / packed factory.
            if _is_slice_factory_expr(
                value.func,
                slice_aliases=frozenset(slice_aliases),
                getattr_aliases=frozenset(getattr_aliases),
            ) or (
                isinstance(value.func, ast.Name) and value.func.id in slice_aliases
            ):
                slice_aliases.add(name)
            # ``g = attrgetter("sort")(L)`` / packed attrgetter apply.
            if value.args:
                ag_applied: str | None = None
                for cand in [value.func, *_callee_candidate_exprs(value.func)]:
                    cand = _peel_call_func(cand)
                    if isinstance(cand, ast.Call):
                        ag_applied = _attrgetter_static_name(
                            cand,
                            projection_aliases=operator_projection_aliases,
                            getattr_aliases=frozenset(getattr_aliases),
                        )
                    elif isinstance(cand, ast.Name):
                        product = projection_factory_products.get(cand.id)
                        if product is not None and product[0] == "attrgetter":
                            ag_applied = product[1]
                    if ag_applied == "sort":
                        sort_recv = _peel_call_func(value.args[0])
                        if _is_unbound_list_recv(sort_recv):
                            dict_view_products[name] = "list.sort"
                            operator_projection_aliases[name] = "list.sort"
                            bound_view_receivers.pop(name, None)
                            bound_view_expr_receivers.pop(name, None)
                        else:
                            dict_view_products[name] = "sort"
                            operator_projection_aliases[name] = "sort"
                            if isinstance(sort_recv, ast.Name):
                                bound_view_receivers[name] = sort_recv.id
                                bound_view_expr_receivers.pop(name, None)
                            else:
                                bound_view_receivers.pop(name, None)
                                bound_view_expr_receivers[name] = sort_recv
                        break
                    ag_applied = None
            # ``g = list.sort.__get__(None, list)`` / BoolOp / getattr __get__ /
            # ``next(iter([list.sort.__get__]))`` / ``object.__getattribute__`` /
            # ``list.__dict__.get("sort").__get__`` (Unknown > false PASS).
            get_func = _peel_call_func(value.func)
            get_attr = None
            get_recv: ast.AST | None = None
            if isinstance(get_func, ast.Attribute) and get_func.attr == "__get__":
                get_attr = "__get__"
                get_recv = get_func.value
            if get_attr is None and isinstance(get_func, ast.Call):
                g_get = _getattr_static_name(
                    get_func, getattr_aliases=frozenset(getattr_aliases)
                )
                if g_get == "__get__" and get_func.args:
                    get_attr = "__get__"
                    get_recv = get_func.args[0]
                else:
                    # ``object.__getattribute__(list.sort, "__get__")``.
                    f_ga = _peel_call_func(get_func.func)
                    is_getattribute = (
                        isinstance(f_ga, ast.Attribute)
                        and f_ga.attr == "__getattribute__"
                    ) or (
                        isinstance(f_ga, ast.Name) and f_ga.id == "__getattribute__"
                    )
                    if (
                        is_getattribute
                        and len(get_func.args) >= 2
                        and _resolve_static_str(get_func.args[1]) == "__get__"
                    ):
                        get_attr = "__get__"
                        get_recv = get_func.args[0]
            if get_attr is None:
                for cand in _callee_candidate_exprs(value.func):
                    cand = _peel_call_func(cand)
                    if isinstance(cand, ast.Attribute) and cand.attr == "__get__":
                        get_attr = "__get__"
                        get_recv = cand.value
                        break
                    if isinstance(cand, ast.Call):
                        g_get = _getattr_static_name(
                            cand, getattr_aliases=frozenset(getattr_aliases)
                        )
                        if g_get == "__get__" and cand.args:
                            get_attr = "__get__"
                            get_recv = cand.args[0]
                            break
                        f_ga = _peel_call_func(cand.func)
                        is_getattribute = (
                            isinstance(f_ga, ast.Attribute)
                            and f_ga.attr == "__getattribute__"
                        ) or (
                            isinstance(f_ga, ast.Name)
                            and f_ga.id == "__getattribute__"
                        )
                        if (
                            is_getattribute
                            and len(cand.args) >= 2
                            and _resolve_static_str(cand.args[1]) == "__get__"
                        ):
                            get_attr = "__get__"
                            get_recv = cand.args[0]
                            break
            if get_attr == "__get__" and get_recv is not None:
                sort_recv = _peel_call_func(get_recv)
                if isinstance(sort_recv, ast.Attribute) and sort_recv.attr == "sort":
                    if _is_unbound_list_recv(sort_recv.value):
                        dict_view_products[name] = "list.sort"
                        operator_projection_aliases[name] = "list.sort"
                        bound_view_receivers.pop(name, None)
                        bound_view_expr_receivers.pop(name, None)
                    else:
                        dict_view_products[name] = "sort"
                        operator_projection_aliases[name] = "sort"
                        inner = _peel_call_func(sort_recv.value)
                        if isinstance(inner, ast.Name):
                            bound_view_receivers[name] = inner.id
                            bound_view_expr_receivers.pop(name, None)
                        else:
                            bound_view_receivers.pop(name, None)
                            bound_view_expr_receivers[name] = inner
                elif isinstance(sort_recv, ast.Name) and (
                    operator_projection_aliases.get(sort_recv.id) == "list.sort"
                    or dict_view_products.get(sort_recv.id) == "list.sort"
                ):
                    # ``inner=getattr(list,"sort"); getattr(inner,"__get__")``.
                    dict_view_products[name] = "list.sort"
                    operator_projection_aliases[name] = "list.sort"
                    bound_view_receivers.pop(name, None)
                    bound_view_expr_receivers.pop(name, None)
                elif isinstance(sort_recv, ast.Subscript):
                    # ``list.__dict__["sort"].__get__(None, list)``.
                    sub_key = _resolve_static_str(sort_recv.slice)
                    if sub_key == "sort":
                        dict_view_products[name] = "list.sort"
                        operator_projection_aliases[name] = "list.sort"
                        bound_view_receivers.pop(name, None)
                        bound_view_expr_receivers.pop(name, None)
                elif isinstance(sort_recv, ast.Call):
                    # ``getattr(list,"sort").__get__`` /
                    # ``getattr(getattr(list,"sort"),"__get__")`` —
                    # peel nested getattr sort before dict.get paths.
                    g_sort = _getattr_static_name(
                        sort_recv, getattr_aliases=frozenset(getattr_aliases)
                    )
                    if (
                        g_sort == "sort"
                        and sort_recv.args
                        and _is_unbound_list_recv(sort_recv.args[0])
                    ):
                        dict_view_products[name] = "list.sort"
                        operator_projection_aliases[name] = "list.sort"
                        bound_view_receivers.pop(name, None)
                        bound_view_expr_receivers.pop(name, None)
                    else:
                        # ``list.__dict__.get("sort").__get__`` /
                        # ``vars(list).get|pop("sort").__get__`` /
                        # BoolOp get before __get__.
                        view = _view_call_parts(sort_recv)
                        view_attr = view[0] if view is not None else None
                        view_recv = view[1] if view is not None else None
                        if view_attr is None:
                            for vc in _callee_candidate_exprs(sort_recv.func):
                                vc = _peel_call_func(vc)
                                if isinstance(vc, ast.Attribute) and vc.attr in {
                                    "get",
                                    "pop",
                                    "__getitem__",
                                }:
                                    view_attr = vc.attr
                                    view_recv = vc.value
                                    break
                                if isinstance(vc, ast.Call):
                                    vg = _getattr_static_name(
                                        vc,
                                        getattr_aliases=frozenset(getattr_aliases),
                                    )
                                    if (
                                        vg in {"get", "pop", "__getitem__"}
                                        and vc.args
                                    ):
                                        view_attr = vg
                                        view_recv = vc.args[0]
                                        break
                        if (
                            view_attr in {"get", "pop", "__getitem__"}
                            and view_recv is not None
                            and sort_recv.args
                            and _resolve_static_str(sort_recv.args[0]) == "sort"
                        ):
                            dict_base = _peel_call_func(view_recv)
                            is_list_dict = (
                                isinstance(dict_base, ast.Attribute)
                                and dict_base.attr == "__dict__"
                                and _is_unbound_list_recv(dict_base.value)
                            ) or (
                                isinstance(dict_base, ast.Call)
                                and (
                                    (
                                        isinstance(
                                            _peel_call_func(dict_base.func),
                                            ast.Name,
                                        )
                                        and _peel_call_func(dict_base.func).id  # type: ignore[union-attr]
                                        == "vars"
                                    )
                                    or (
                                        isinstance(
                                            _peel_call_func(dict_base.func),
                                            ast.Attribute,
                                        )
                                        and _peel_call_func(dict_base.func).attr  # type: ignore[union-attr]
                                        == "vars"
                                    )
                                )
                                and dict_base.args
                                and _is_unbound_list_recv(dict_base.args[0])
                            )
                            if is_list_dict:
                                dict_view_products[name] = "list.sort"
                                operator_projection_aliases[name] = "list.sort"
                                bound_view_receivers.pop(name, None)
                                bound_view_expr_receivers.pop(name, None)
            # Keep partial / methodcaller Call AST so Name-bound
            # ``next(iter([p|mc]))`` / BinOp / concat peels recover the factory
            # with bound args (Unknown > false PASS).
            if _is_partial_factory(
                value,
                partial_aliases=frozenset(partial_aliases),
                getattr_aliases=frozenset(getattr_aliases),
            ) or (
                _methodcaller_static_name(
                    value,
                    projection_aliases=operator_projection_aliases,
                    getattr_aliases=frozenset(getattr_aliases),
                )
                is not None
            ):
                bound_callee_exprs[name] = value
            else:
                bound_callee_exprs.pop(name, None)
            _note_factory_product_from_value(name, value)
            _note_class_product_from_value(name, value)
            _note_container_pack_from_value(name, value)
            return
        # Literal / ``dict(...)`` / ``{}|{"e": exec}`` container packs.
        bound_callee_exprs.pop(name, None)
        _note_class_product_from_value(name, value)
        _note_container_pack_from_value(name, value)

    def _note_export(module_path: str, name: str) -> None:
        accum.export_mutations.setdefault(module_path, set()).add(name)

    def _note_behavior(
        identity: tuple[str, str],
        *,
        mutation_path: str,
        mutation_index: int,
    ) -> None:
        defining_path, export_name = identity
        if defining_path == mutation_path:
            establish = _final_binding_establish_index(
                trees[defining_path], export_name
            )
            # Later unconditional rebinding in the defining module restores a
            # fresh source-grounded callable; mutations before that index do
            # not poison the final object.
            if establish is not None and mutation_index < establish:
                return
        accum.behavior_mutations.add(identity)

    def _poison_atoms(
        points: _IdentityPointsTo,
        *,
        export_name: str | None,
        behavior: bool,
        mutation_path: str,
        mutation_index: int,
    ) -> None:
        for atom in points.known:
            if isinstance(atom, ModuleObject):
                _note_export(atom.path, "*" if export_name is None else export_name)
            elif isinstance(atom, ModuleNamespace):
                _note_export(
                    atom.module_path, "*" if export_name is None else export_name
                )
            elif isinstance(atom, CallableObject) and behavior:
                _note_behavior(
                    (atom.defining_path, atom.export_name),
                    mutation_path=mutation_path,
                    mutation_index=mutation_index,
                )

    def _escape_identity(points: _IdentityPointsTo) -> None:
        """Container escape of module/callable identity → poison (#165)."""

        for atom in points.known:
            if isinstance(atom, ModuleObject):
                _note_export(atom.path, "*")
            elif isinstance(atom, ModuleNamespace):
                _note_export(atom.module_path, "*")
            elif isinstance(atom, CallableObject):
                accum.behavior_mutations.add((atom.defining_path, atom.export_name))

    def _lookup_name(
        name: str,
        env: Mapping[str, _IdentityPointsTo],
        *,
        path: str,
    ) -> _IdentityPointsTo:
        if name in env:
            return env[name]
        return _identity_from_final_binding(
            name,
            path=path,
            bindings_by_path=bindings_by_path,
            available_paths=available_paths,
            import_roots=import_roots,
        )

    def _has_tracked_identity(points: _IdentityPointsTo) -> bool:
        return any(
            isinstance(a, (ModuleObject, CallableObject, ModuleNamespace))
            for a in points.known
        )

    def _escape_if_tracked(points: _IdentityPointsTo) -> None:
        if _has_tracked_identity(points):
            _escape_identity(points)

    # Statement-scan context so value-position calls (Assign RHS, nested
    # make()(), defaults) still follow local helpers for mutation effects.
    _scan_ctx: dict[str, object] = {
        "index": 0,
        "visited_fns": set(),
        "local_fns": None,
        "local_classes": None,
    }

    def _register_module_classes(path: str) -> None:
        tree = trees.get(path)
        if tree is None:
            return
        for node in getattr(tree, "body", ()):
            if isinstance(node, ast.ClassDef):
                class_registry[node.name] = node

    def _lookup_class(
        name: str,
        local_classes: Mapping[str, ast.ClassDef] | None,
    ) -> ast.ClassDef | None:
        if local_classes is not None and name in local_classes:
            return local_classes[name]
        return class_registry.get(name)

    def _resolve_receiver_class(
        receiver: ast.AST,
        *,
        local_classes: Mapping[str, ast.ClassDef] | None,
    ) -> ast.ClassDef | None:
        """Resolve ``Mut`` / ``Mut()`` / instance aliases to a ClassDef."""

        if isinstance(receiver, ast.NamedExpr):
            return _resolve_receiver_class(
                receiver.value, local_classes=local_classes
            )
        if isinstance(receiver, ast.Name):
            direct = _lookup_class(receiver.id, local_classes)
            if direct is not None:
                return direct
            cname = instance_class_of.get(receiver.id)
            if cname is not None:
                return _lookup_class(cname, local_classes)
            return None
        if isinstance(receiver, ast.Call) and isinstance(receiver.func, ast.Name):
            return _lookup_class(receiver.func.id, local_classes)
        return None

    def _resolve_attribute_method(
        func: ast.Attribute,
        *,
        local_classes: Mapping[str, ast.ClassDef] | None,
    ) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
        class_node = _resolve_receiver_class(
            func.value, local_classes=local_classes
        )
        if class_node is None:
            return None
        return _class_method_by_name(class_node, func.attr)

    def _methods_named(
        method_name: str,
        *,
        local_classes: Mapping[str, ast.ClassDef] | None,
    ) -> list[ast.FunctionDef | ast.AsyncFunctionDef]:
        """Conservative may-execute set of methods with ``method_name``."""

        seen: set[int] = set()
        methods: list[ast.FunctionDef | ast.AsyncFunctionDef] = []
        classes: dict[str, ast.ClassDef] = dict(class_registry)
        if local_classes is not None:
            classes.update(local_classes)
        for class_node in classes.values():
            method = _class_method_by_name(class_node, method_name)
            if method is None or id(method) in seen:
                continue
            seen.add(id(method))
            methods.append(method)
        return methods

    def _follow_methods_named(
        method_name: str,
        call: ast.Call,
        *,
        path: str,
        index: int,
        env: dict[str, _IdentityPointsTo],
        visited_fns: set[int],
        local_fns: Mapping[str, ast.FunctionDef | ast.AsyncFunctionDef] | None,
        local_classes: Mapping[str, ast.ClassDef] | None,
    ) -> bool:
        methods = _methods_named(method_name, local_classes=local_classes)
        if not methods:
            return False
        for method in methods:
            scan_classes = dict(local_classes or {})
            # ``@classmethod`` ``return cls()`` constructs the owning class.
            if _method_has_decorator(method, frozenset({"classmethod"})):
                for class_node in (local_classes or class_registry).values():
                    if _class_method_by_name(class_node, method.name) is method:
                        if method.args.args:
                            scan_classes[method.args.args[0].arg] = class_node
                        break
            _scan_fn_body(
                method,
                path=path,
                index=index,
                env=env,
                visited_fns=visited_fns,
                local_fns=local_fns,
                local_classes=scan_classes,
                formals=_formal_bindings_for_call(call, method, env, path=path),
            )
        return True

    def _scan_fn_body(
        fn_node: ast.FunctionDef | ast.AsyncFunctionDef,
        *,
        path: str,
        index: int,
        env: dict[str, _IdentityPointsTo],
        visited_fns: set[int],
        local_fns: Mapping[str, ast.FunctionDef | ast.AsyncFunctionDef] | None,
        local_classes: Mapping[str, ast.ClassDef] | None,
        formals: Mapping[str, _IdentityPointsTo] | None = None,
    ) -> None:
        fn_id = id(fn_node)
        if fn_id in visited_fns:
            return
        visited_fns.add(fn_id)
        call_env = _copy_env(env)
        if formals is not None:
            call_env.update(formals)
        nested_fns = dict(local_fns or {})
        nested_classes = dict(local_classes or {})
        declared_globals: set[str] = set()
        for stmt in fn_node.body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                nested_fns[stmt.name] = stmt
            elif isinstance(stmt, ast.ClassDef):
                nested_classes[stmt.name] = stmt
                class_registry[stmt.name] = stmt
            elif isinstance(stmt, ast.Global):
                declared_globals.update(stmt.names)
        _scan_stmts(
            fn_node.body,
            path=path,
            index=index,
            env=call_env,
            visited_fns=visited_fns,
            local_fns=nested_fns,
            local_classes=nested_classes,
            declared_globals=declared_globals,
        )
        _scan_nested_defs_conservatively(
            fn_node,
            path=path,
            index=index,
            call_env=call_env,
            visited_fns=visited_fns,
            local_fns=nested_fns,
            local_classes=nested_classes,
        )

    def _poison_unknown_receiver(
        *,
        export_name: str | None,
        behavior: bool,
    ) -> None:
        """Spelling poison when the receiver *may* be a tracked object.

        Closed-world: an ``unknown`` (not bottom) receiver that mutates a
        static export name may be any module exporting that name; a dynamic
        name or callable-behavior surface poisons broadly. Severed aliases
        use bottom and do not enter this path.
        """

        if behavior or (export_name is not None and export_name in _CALLABLE_BEHAVIOR_ATTRS):
            for mod_path, bindings in bindings_by_path.items():
                for local, binding in bindings.items():
                    if binding.kind == "function":
                        accum.behavior_mutations.add((mod_path, local))
                    elif (
                        binding.kind == "import_name"
                        and binding.module_name is not None
                        and binding.imported_name is not None
                    ):
                        resolved = _module_path_for_import_name(
                            binding.module_name,
                            available_paths=available_paths,
                            import_roots=import_roots,
                        )
                        if resolved is not None:
                            accum.behavior_mutations.add(
                                (resolved, binding.imported_name)
                            )
            if export_name is None or export_name in _CALLABLE_BEHAVIOR_ATTRS:
                # Dynamic / behavior-shaped write on unknown callable surface.
                for mod_path in available_paths:
                    _note_export(mod_path, "*")
            return
        if export_name is None:
            for mod_path in available_paths:
                _note_export(mod_path, "*")
            return
        for mod_path in available_paths:
            _note_export(mod_path, export_name)

    def _eval_type_params(
        type_params: Sequence[ast.AST],
        env: Mapping[str, _IdentityPointsTo],
        *,
        path: str,
    ) -> None:
        """PEP 695 type parameters evaluate bounds/defaults at definition."""

        for param in type_params:
            bound = getattr(param, "bound", None)
            if bound is not None:
                _eval_expr(bound, env, path=path)
            default = getattr(param, "default_value", None)
            if default is not None:
                _eval_expr(default, env, path=path)

    def _eval_expr(
        expr: ast.AST,
        env: Mapping[str, _IdentityPointsTo],
        *,
        path: str,
    ) -> _IdentityPointsTo:
        expr = _unwrap_await(expr)
        if isinstance(expr, ast.Name):
            return _lookup_name(expr.id, env, path=path)
        if isinstance(expr, ast.NamedExpr):
            # Walrus: evaluate RHS (including nested call effects) and bind when
            # the environment is mutable (#173 executed-expression closure).
            points = _eval_expr(expr.value, env, path=path)
            if isinstance(expr.target, ast.Name) and isinstance(env, dict):
                env[expr.target.id] = points
                if isinstance(expr.value, ast.Lambda):
                    lambda_bindings[expr.target.id] = expr.value
                else:
                    lambda_bindings.pop(expr.target.id, None)
                # ``(run := exec)(...)`` / ``(nc := types.new_class)(...)``.
                _note_protocol_alias_from_value(expr.target.id, expr.value)
                # ``(mk := Mut.make)()`` — seed method bindings like Assign.
                method_attr = _peel_transparent_callee(expr.value)
                if isinstance(method_attr, ast.Attribute):
                    if method_attr.attr == "__call__":
                        peeled = _peel_transparent_callee(method_attr.value)
                        if isinstance(peeled, ast.Attribute):
                            method_attr = peeled
                    method = _resolve_attribute_method(
                        method_attr,
                        local_classes=_scan_ctx.get("local_classes"),  # type: ignore[arg-type]
                    )
                    if method is not None:
                        method_bindings[expr.target.id] = method
                    else:
                        method_bindings.pop(expr.target.id, None)
                else:
                    method_bindings.pop(expr.target.id, None)
                if (
                    isinstance(expr.value, ast.Call)
                    and isinstance(expr.value.func, ast.Name)
                    and _lookup_class(
                        expr.value.func.id,
                        _scan_ctx["local_classes"],  # type: ignore[arg-type]
                    )
                    is not None
                ):
                    instance_class_of[expr.target.id] = expr.value.func.id
            return points
        if isinstance(expr, ast.IfExp):
            # Test executes before arm selection; omitting it false-PASSes
            # ``if (False if poison() else False):`` (#173).
            _eval_expr(expr.test, env, path=path)
            # Conditional value: may-point-to join (Unknown > false PASS).
            return _eval_expr(expr.body, env, path=path).join(
                _eval_expr(expr.orelse, env, path=path)
            )
        if isinstance(expr, ast.BoolOp):
            points = _IdentityPointsTo()
            for value in expr.values:
                points = points.join(_eval_expr(value, env, path=path))
            return points
        if isinstance(expr, ast.Attribute):
            if expr.attr == "__dict__":
                base = _eval_expr(expr.value, env, path=path)
                known: set[_ObjectAtom] = set()
                for atom in base.known:
                    if isinstance(atom, ModuleObject):
                        known.add(ModuleNamespace(atom.path))
                    elif isinstance(atom, ModuleNamespace):
                        known.add(atom)
                return _IdentityPointsTo(known=frozenset(known), unknown=base.unknown)
            # Transparent ``X.__call__`` — denotes X (``f = n.install.__call__``).
            if expr.attr == "__call__":
                return _eval_expr(expr.value, env, path=path)
            base = _eval_expr(expr.value, env, path=path)
            # module.attr → CallableObject when base is ModuleObject
            known_callables: set[_ObjectAtom] = set()
            for atom in base.known:
                if isinstance(atom, ModuleObject):
                    known_callables.add(CallableObject(atom.path, expr.attr))
            if known_callables:
                return _IdentityPointsTo(
                    known=frozenset(known_callables),
                    unknown=base.unknown,
                )
            if base.known or base.unknown:
                return _IdentityPointsTo.unknown_only()
            return _IdentityPointsTo.unknown_only()
        if (
            isinstance(expr, ast.Call)
            and isinstance(expr.func, ast.Name)
            and expr.func.id == "vars"
            and len(expr.args) == 1
            and not expr.keywords
        ):
            base = _eval_expr(expr.args[0], env, path=path)
            known_ns: set[_ObjectAtom] = set()
            for atom in base.known:
                if isinstance(atom, ModuleObject):
                    known_ns.add(ModuleNamespace(atom.path))
                elif isinstance(atom, ModuleNamespace):
                    known_ns.add(atom)
            return _IdentityPointsTo(known=frozenset(known_ns), unknown=base.unknown)
        if (
            isinstance(expr, ast.Call)
            and isinstance(expr.func, ast.Name)
            and expr.func.id in getattr_aliases
            and len(expr.args) >= 2
            and not expr.keywords
        ):
            # getattr(module, "export") may alias a callable; model when attr is
            # static, otherwise escape the receiver (Unknown > false PASS).
            # Default arg executes when the attribute is missing
            # (``getattr(obj, "missing", poison)``).
            owner = _eval_expr(expr.args[0], env, path=path)
            _eval_expr(expr.args[1], env, path=path)
            if len(expr.args) >= 3:
                _eval_expr(expr.args[2], env, path=path)
            attr = _static_str(expr.args[1])
            if attr == "__dict__":
                known_ns: set[_ObjectAtom] = set()
                for atom in owner.known:
                    if isinstance(atom, ModuleObject):
                        known_ns.add(ModuleNamespace(atom.path))
                    elif isinstance(atom, ModuleNamespace):
                        known_ns.add(atom)
                if known_ns or owner.unknown:
                    return _IdentityPointsTo(
                        known=frozenset(known_ns),
                        unknown=owner.unknown,
                    )
            if attr is not None:
                known_callables = set()
                for atom in owner.known:
                    if isinstance(atom, ModuleObject):
                        known_callables.add(CallableObject(atom.path, attr))
                    elif isinstance(atom, ModuleNamespace):
                        known_callables.add(CallableObject(atom.module_path, attr))
                if known_callables:
                    return _IdentityPointsTo(
                        known=frozenset(known_callables),
                        unknown=owner.unknown,
                    )
            _escape_if_tracked(owner)
            return _IdentityPointsTo.unknown_only()
        if isinstance(expr, (ast.Tuple, ast.List, ast.Set)):
            for elt in expr.elts:
                if isinstance(elt, ast.Starred):
                    _escape_identity(_eval_expr(elt.value, env, path=path))
                else:
                    points = _eval_expr(elt, env, path=path)
                    _escape_if_tracked(points)
            return _IdentityPointsTo.unknown_only()
        if isinstance(expr, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
            # Comprehension packing is an unmodeled container escape.
            # Attribute/subscript for-targets rebind exports
            # (``[0 for helpers.write_state in [evil]]``).
            # Also apply elt / if bodies per element so
            # ``[f(Mut) for f in [type.__call__]]`` observes construction.
            env_dict = env if isinstance(env, dict) else dict(env)
            _observe_comprehension_applies(
                expr,
                path=path,
                index=int(_scan_ctx["index"]),  # type: ignore[arg-type]
                env=env_dict,
                visited_fns=_scan_ctx["visited_fns"],  # type: ignore[arg-type]
                local_fns=_scan_ctx["local_fns"],  # type: ignore[arg-type]
                local_classes=_scan_ctx["local_classes"],  # type: ignore[arg-type]
            )
            _escape_if_tracked(_eval_expr(expr.elt, env, path=path))
            for gen in expr.generators:
                iter_points = _eval_expr(gen.iter, env, path=path)
                _escape_if_tracked(iter_points)
                if _assign_target_has_attr_or_subscript(gen.target):
                    _scan_assign_target(
                        gen.target,
                        path=path,
                        index=int(_scan_ctx["index"]),  # type: ignore[arg-type]
                        env=env if isinstance(env, dict) else dict(env),
                        value_points=iter_points,
                    )
                for if_clause in gen.ifs:
                    _escape_if_tracked(_eval_expr(if_clause, env, path=path))
            return _IdentityPointsTo.unknown_only()
        if isinstance(expr, ast.DictComp):
            env_dict = env if isinstance(env, dict) else dict(env)
            _observe_comprehension_applies(
                expr,
                path=path,
                index=int(_scan_ctx["index"]),  # type: ignore[arg-type]
                env=env_dict,
                visited_fns=_scan_ctx["visited_fns"],  # type: ignore[arg-type]
                local_fns=_scan_ctx["local_fns"],  # type: ignore[arg-type]
                local_classes=_scan_ctx["local_classes"],  # type: ignore[arg-type]
            )
            _escape_if_tracked(_eval_expr(expr.key, env, path=path))
            _escape_if_tracked(_eval_expr(expr.value, env, path=path))
            for gen in expr.generators:
                iter_points = _eval_expr(gen.iter, env, path=path)
                _escape_if_tracked(iter_points)
                if _assign_target_has_attr_or_subscript(gen.target):
                    _scan_assign_target(
                        gen.target,
                        path=path,
                        index=int(_scan_ctx["index"]),  # type: ignore[arg-type]
                        env=env if isinstance(env, dict) else dict(env),
                        value_points=iter_points,
                    )
                for if_clause in gen.ifs:
                    _escape_if_tracked(_eval_expr(if_clause, env, path=path))
            return _IdentityPointsTo.unknown_only()
        if isinstance(expr, ast.Dict):
            for key, value in zip(expr.keys, expr.values):
                for part in (key, value):
                    if part is None:
                        continue
                    points = _eval_expr(part, env, path=path)
                    _escape_if_tracked(points)
            return _IdentityPointsTo.unknown_only()
        if isinstance(expr, ast.Starred):
            points = _eval_expr(expr.value, env, path=path)
            _escape_if_tracked(points)
            return _IdentityPointsTo.unknown_only()
        if isinstance(expr, ast.Subscript):
            # Container projection is unmodeled → UNKNOWN (may escape).
            # Index/slice expressions still execute (``xs[poison()]``).
            base = _eval_expr(expr.value, env, path=path)
            _escape_if_tracked(base)
            _eval_expr(expr.slice, env, path=path)
            return _IdentityPointsTo.unknown_only()
        if isinstance(expr, ast.BinOp):
            for side in (expr.left, expr.right):
                points = _eval_expr(side, env, path=path)
                _escape_if_tracked(points)
            return _IdentityPointsTo.unknown_only()
        if isinstance(expr, ast.Call):
            # Value-position / nested calls must still follow local helpers
            # (e.g. ``f = make(); f()``, ``make()()``, defaults). Special cases
            # ``vars`` / ``getattr`` are handled above.
            env_dict = env if isinstance(env, dict) else dict(env)
            _scan_call(
                expr,
                path=path,
                index=int(_scan_ctx["index"]),  # type: ignore[arg-type]
                env=env_dict,
                visited_fns=_scan_ctx["visited_fns"],  # type: ignore[arg-type]
                local_fns=_scan_ctx["local_fns"],  # type: ignore[arg-type]
                local_classes=_scan_ctx["local_classes"],  # type: ignore[arg-type]
            )
            return _IdentityPointsTo.unknown_only()
        if isinstance(expr, ast.Lambda):
            # Defaults execute at definition; body does not. Omitting defaults
            # false-PASSes ``f = lambda x=poison(): x`` beside a later trusted
            # helper write (Unknown > false PASS, #173).
            for default in expr.args.defaults:
                _eval_expr(default, env, path=path)
            for default in expr.args.kw_defaults:
                if default is not None:
                    _eval_expr(default, env, path=path)
            return _IdentityPointsTo.unknown_only()
        # Unmodeled expression forms still execute nested subexpressions
        # (UnaryOp ``not poison()``, Compare, JoinedStr / f-strings, Slice, …).
        # Omission here false-PASSes request-time callable-identity closure
        # beside a later trusted helper write (Unknown > false PASS, #173).
        for child in ast.iter_child_nodes(expr):
            if isinstance(child, ast.expr):
                _eval_expr(child, env, path=path)
        return _IdentityPointsTo.unknown_only()

    def _bind_target_names(
        target: ast.AST,
        points: _IdentityPointsTo,
        env: dict[str, _IdentityPointsTo],
    ) -> None:
        if isinstance(target, ast.Name):
            env[target.id] = points
        elif isinstance(target, ast.Tuple | ast.List):
            # Unpack: identity escapes unless we model element-wise (we don't).
            if any(
                isinstance(a, (ModuleObject, CallableObject, ModuleNamespace))
                for a in points.known
            ):
                _escape_identity(points)
            for elt in target.elts:
                if isinstance(elt, ast.Starred):
                    if isinstance(elt.value, ast.Name):
                        env[elt.value.id] = _IdentityPointsTo.unknown_only()
                    elif isinstance(elt.value, (ast.Tuple, ast.List)):
                        _bind_target_names(elt.value, _IdentityPointsTo.unknown_only(), env)
                elif isinstance(elt, ast.Name):
                    env[elt.id] = _IdentityPointsTo.unknown_only()
                elif isinstance(elt, (ast.Tuple, ast.List)):
                    _bind_target_names(elt, _IdentityPointsTo.unknown_only(), env)
                else:
                    # Attribute/subscript unpack target is a mutation surface.
                    pass
        elif isinstance(target, ast.Starred) and isinstance(target.value, ast.Name):
            env[target.value.id] = _IdentityPointsTo.unknown_only()

    def _apply_import_identities(
        node: ast.AST,
        env: dict[str, _IdentityPointsTo],
        *,
        path: str,
    ) -> None:
        if isinstance(node, ast.ImportFrom):
            if any(alias.name == "*" for alias in node.names):
                for key in list(env):
                    env[key] = _IdentityPointsTo.unknown_only()
                return
            module_name = import_module_name_from_importer(node, importer_path=path)
            module_path = (
                _module_path_for_import_name(
                    module_name,
                    available_paths=available_paths,
                    import_roots=import_roots,
                )
                if module_name is not None
                else None
            )
            for alias in node.names:
                local = alias.asname or alias.name
                if alias.name in _EXEC_EVAL_COMPILE_NAMES:
                    # ``from builtins import exec as run``.
                    exec_eval_compile_aliases.add(local)
                elif alias.name == _TYPES_NEW_CLASS_NAME:
                    # ``from types import new_class as nc``.
                    new_class_aliases.add(local)
                elif alias.name == _TYPE_BUILTIN_NAME:
                    type_aliases.add(local)
                elif alias.name in _OPERATOR_PROJECTION_NAMES | _KEY_APPLICATOR_NAMES:
                    # ``from operator import itemgetter as ig`` / ``call as opcall``
                    # / ``from builtins import sorted as s`` /
                    # ``from functools import reduce as rd``.
                    operator_projection_aliases[local] = alias.name
                elif alias.name == "partial":
                    partial_aliases.add(local)
                elif alias.name == "MappingProxyType":
                    adapter_aliases.add(local)
                elif alias.name == "getattr":
                    getattr_aliases.add(local)
                elif alias.name == "setattr":
                    setattr_aliases.add(local)
                elif alias.name == "slice":
                    slice_aliases.add(local)
                elif alias.name in {"vars", "globals", "locals"}:
                    ns_projection_aliases.add(local)
                elif alias.name == "__dict__":
                    # ``from builtins import __dict__ as D; D.get("list")`` —
                    # share namespace-projection seeds (Unknown > false PASS).
                    ns_dict_aliases.add(local)
                    ns_projection_aliases.add(local)
                elif alias.name in _MAPPING_CTOR_NAMES | {"list", "set", "tuple"}:
                    # ``from collections import OrderedDict as OD`` /
                    # ``from builtins import list as L`` (unbound L.sort / L.append).
                    dict_ctor_aliases.add(local)
                    if alias.name in {"list", "set", "tuple"}:
                        operator_projection_aliases[local] = alias.name
                elif alias.name in _MAPPING_COPY_FUNCS:
                    # ``from copy import copy as c`` / ``deepcopy as dc``.
                    operator_projection_aliases[local] = alias.name
                if module_path is None:
                    env[local] = _IdentityPointsTo.unknown_only()
                else:
                    env[local] = _IdentityPointsTo.precise(
                        CallableObject(module_path, alias.name)
                    )
        elif isinstance(node, ast.Import):
            for alias in node.names:
                top = alias.name.split(".", 1)[0]
                local = alias.asname or top
                if top == "copy":
                    copy_module_aliases.add(local)
                if alias.asname:
                    module_path = _module_path_for_import_name(
                        alias.name,
                        available_paths=available_paths,
                        import_roots=import_roots,
                    )
                    env[alias.asname] = (
                        _IdentityPointsTo.precise(ModuleObject(module_path))
                        if module_path is not None
                        else _IdentityPointsTo.unknown_only()
                    )
                else:
                    module_path = _module_path_for_import_name(
                        top,
                        available_paths=available_paths,
                        import_roots=import_roots,
                    )
                    env[top] = (
                        _IdentityPointsTo.precise(ModuleObject(module_path))
                        if module_path is not None
                        else _IdentityPointsTo.unknown_only()
                    )
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.decorator_list:
                env[node.name] = _IdentityPointsTo.unknown_only()
            else:
                env[node.name] = _IdentityPointsTo.precise(
                    CallableObject(path, node.name)
                )
        elif isinstance(node, ast.ClassDef):
            env[node.name] = _IdentityPointsTo.unknown_only()

    def _mutate_through_expr(
        base: ast.AST,
        *,
        export_name: str | None,
        behavior: bool,
        env: Mapping[str, _IdentityPointsTo],
        path: str,
        index: int,
    ) -> None:
        if _is_sys_modules_expr(base) or (
            isinstance(base, ast.Subscript) and _is_sys_modules_expr(base.value)
        ):
            accum.unsupported = True
            if (
                isinstance(base, ast.Subscript)
                and _is_sys_modules_expr(base.value)
            ):
                key = _static_str(base.slice)
                attr = export_name
                if key is not None:
                    candidates = module_candidates_in_manifest(
                        key,
                        set(available_paths),
                        import_roots=import_roots,
                    )
                    if len(candidates) == 1:
                        _note_export(candidates[0], attr if attr is not None else "*")
                    else:
                        for mod_path in available_paths:
                            _note_export(mod_path, "*")
                else:
                    for mod_path in available_paths:
                        _note_export(mod_path, "*")
            else:
                for mod_path in available_paths:
                    _note_export(mod_path, "*")
            return
        points = _eval_expr(base, env, path=path)
        _poison_atoms(
            points,
            export_name=export_name,
            behavior=behavior,
            mutation_path=path,
            mutation_index=index,
        )
        if points.unknown:
            _poison_unknown_receiver(export_name=export_name, behavior=behavior)

    def _scan_assign_target(
        target: ast.AST,
        *,
        path: str,
        index: int,
        env: dict[str, _IdentityPointsTo],
        value_points: _IdentityPointsTo | None,
    ) -> None:
        if isinstance(target, ast.Name):
            if value_points is not None:
                env[target.id] = value_points
            else:
                env[target.id] = _IdentityPointsTo.unknown_only()
            return
        if isinstance(target, (ast.Tuple, ast.List)):
            if value_points is not None:
                _bind_target_names(target, value_points, env)
            else:
                _bind_target_names(target, _IdentityPointsTo.unknown_only(), env)
            # Attribute/subscript unpack targets mutate (``(helpers.write_state,) = (evil,)``).
            for elt in target.elts:
                nested = elt.value if isinstance(elt, ast.Starred) else elt
                if isinstance(nested, (ast.Attribute, ast.Subscript, ast.Tuple, ast.List)):
                    _scan_assign_target(
                        nested,
                        path=path,
                        index=index,
                        env=env,
                        value_points=value_points,
                    )
            return
        if isinstance(target, ast.Attribute):
            # Bind walrus names appearing in the attribute base.
            for child in ast.walk(target.value):
                if isinstance(child, ast.NamedExpr) and isinstance(
                    child.target, ast.Name
                ):
                    env[child.target.id] = _eval_expr(child.value, env, path=path)
            # sys.modules[...] surfaces (#163) — check before identity eval.
            if _is_sys_modules_expr(target.value) or (
                isinstance(target.value, ast.Subscript)
                and _is_sys_modules_expr(target.value.value)
            ):
                _mutate_through_expr(
                    target.value,
                    export_name=target.attr,
                    behavior=False,
                    env=env,
                    path=path,
                    index=index,
                )
                return
            # Attribute write on module → export; on callable → behavior.
            # helpers.write_state.__code__: base eval → CallableObject.
            base_points = _eval_expr(target.value, env, path=path)
            for atom in base_points.known:
                if isinstance(atom, ModuleObject):
                    _note_export(atom.path, target.attr)
                elif isinstance(atom, ModuleNamespace):
                    _note_export(atom.module_path, target.attr)
                elif isinstance(atom, CallableObject):
                    _note_behavior(
                        (atom.defining_path, atom.export_name),
                        mutation_path=path,
                        mutation_index=index,
                    )
            if base_points.unknown:
                _poison_unknown_receiver(
                    export_name=target.attr,
                    behavior=target.attr in _CALLABLE_BEHAVIOR_ATTRS,
                )
            return
        if isinstance(target, ast.Subscript):
            if _is_sys_modules_expr(target.value):
                accum.unsupported = True
                key = _static_str(target.slice)
                if key is not None:
                    candidates = module_candidates_in_manifest(
                        key,
                        set(available_paths),
                        import_roots=import_roots,
                    )
                    if len(candidates) == 1:
                        _note_export(candidates[0], "*")
                    else:
                        for mod_path in available_paths:
                            _note_export(mod_path, "*")
                else:
                    for mod_path in available_paths:
                        _note_export(mod_path, "*")
                return
            key = _static_str(target.slice)
            base_points = _eval_expr(target.value, env, path=path)
            for atom in base_points.known:
                if isinstance(atom, ModuleNamespace):
                    _note_export(atom.module_path, key if key is not None else "*")
                elif isinstance(atom, ModuleObject):
                    # Rare: subscript on module object itself.
                    _note_export(atom.path, key if key is not None else "*")
                elif isinstance(atom, CallableObject):
                    _note_behavior(
                        (atom.defining_path, atom.export_name),
                        mutation_path=path,
                        mutation_index=index,
                    )
            if base_points.unknown:
                _poison_unknown_receiver(
                    export_name=key,
                    behavior=key is not None and key in _CALLABLE_BEHAVIOR_ATTRS,
                )
            # fn.__globals__[x] where base is Attribute
            if isinstance(target.value, ast.Attribute):
                owner = _eval_expr(target.value.value, env, path=path)
                _poison_atoms(
                    owner,
                    export_name=None,
                    behavior=True,
                    mutation_path=path,
                    mutation_index=index,
                )
                if owner.unknown:
                    _poison_unknown_receiver(export_name=None, behavior=True)
            return

    def _formal_bindings_for_call(
        call: ast.Call,
        fn: ast.FunctionDef | ast.AsyncFunctionDef,
        env: Mapping[str, _IdentityPointsTo],
        *,
        path: str,
    ) -> dict[str, _IdentityPointsTo] | None:
        """Bind actual→formal identities for a local helper (#165).

        Supports positional-only, ordinary, and keyword-only parameters plus
        default-value identity when an actual is omitted. ``*args``/``**kwargs``
        escape tracked actuals (container loss).
        """

        posonly = [a.arg for a in fn.args.posonlyargs]
        ordinary = [a.arg for a in fn.args.args]
        kwonly = [a.arg for a in fn.args.kwonlyargs]
        positional_params = posonly + ordinary

        if fn.args.vararg is not None or fn.args.kwarg is not None:
            # Escaping into *args/**kwargs loses precise formal identity.
            for arg in call.args:
                points = _eval_expr(arg, env, path=path)
                if any(
                    isinstance(a, (ModuleObject, CallableObject, ModuleNamespace))
                    for a in points.known
                ):
                    _escape_identity(points)
            for kw in call.keywords:
                points = _eval_expr(kw.value, env, path=path)
                if any(
                    isinstance(a, (ModuleObject, CallableObject, ModuleNamespace))
                    for a in points.known
                ):
                    _escape_identity(points)
            return None

        formals: dict[str, _IdentityPointsTo] = {}
        for index, arg in enumerate(call.args):
            if index >= len(positional_params):
                points = _eval_expr(arg, env, path=path)
                _escape_identity(points)
                continue
            formals[positional_params[index]] = _eval_expr(arg, env, path=path)
        for kw in call.keywords:
            if kw.arg is None:
                _escape_identity(_eval_expr(kw.value, env, path=path))
                continue
            if kw.arg in positional_params or kw.arg in kwonly:
                formals[kw.arg] = _eval_expr(kw.value, env, path=path)
            else:
                points = _eval_expr(kw.value, env, path=path)
                if any(
                    isinstance(a, (ModuleObject, CallableObject, ModuleNamespace))
                    for a in points.known
                ):
                    _escape_identity(points)

        # Default-value identity for omitted formals (evaluated in caller env).
        defaults = list(fn.args.defaults)
        if defaults:
            default_start = len(positional_params) - len(defaults)
            for offset, default_expr in enumerate(defaults):
                param = positional_params[default_start + offset]
                if param not in formals:
                    formals[param] = _eval_expr(default_expr, env, path=path)
        for param, default_expr in zip(fn.args.kwonlyargs, fn.args.kw_defaults):
            if default_expr is None or param.arg in formals:
                continue
            formals[param.arg] = _eval_expr(default_expr, env, path=path)
        return formals

    def _scan_nested_defs_conservatively(
        fn_node: ast.FunctionDef | ast.AsyncFunctionDef,
        *,
        path: str,
        index: int,
        call_env: dict[str, _IdentityPointsTo],
        visited_fns: set[int],
        local_fns: Mapping[str, ast.FunctionDef | ast.AsyncFunctionDef] | None,
        local_classes: Mapping[str, ast.ClassDef] | None = None,
    ) -> None:
        """May-execute nested defs (returned/stored closures) under call_env."""

        for child in fn_node.body:
            for node in ast.walk(child):
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                nested_id = id(node)
                if nested_id in visited_fns:
                    continue
                visited_fns.add(nested_id)
                nest_env = _copy_env(call_env)
                for arg in (
                    list(node.args.posonlyargs)
                    + list(node.args.args)
                    + list(node.args.kwonlyargs)
                ):
                    # Nested formals are unmodeled unless this nested def is
                    # itself followed as a callee; keep free-var identities.
                    nest_env[arg.arg] = _IdentityPointsTo.unknown_only()
                nested_local = dict(local_fns or {})
                nested_local[node.name] = node
                nested_classes = dict(local_classes or {})
                for stmt in node.body:
                    if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        nested_local[stmt.name] = stmt
                    elif isinstance(stmt, ast.ClassDef):
                        nested_classes[stmt.name] = stmt
                        class_registry[stmt.name] = stmt
                _scan_stmts(
                    node.body,
                    path=path,
                    index=index,
                    env=nest_env,
                    visited_fns=visited_fns,
                    local_fns=nested_local,
                    local_classes=nested_classes,
                )

    def _follow_local_callee(
        call: ast.Call,
        *,
        path: str,
        index: int,
        env: dict[str, _IdentityPointsTo],
        visited_fns: set[int],
        local_fns: Mapping[str, ast.FunctionDef | ast.AsyncFunctionDef] | None = None,
        local_classes: Mapping[str, ast.ClassDef] | None = None,
    ) -> None:
        func = call.func
        # ``(mk := Mut.make)()`` — evaluate walrus then peel to Attribute/Name.
        if isinstance(func, ast.NamedExpr):
            _eval_expr(func, env, path=path)
            if isinstance(func.target, ast.Name) and func.target.id in method_bindings:
                synthetic = ast.Call(
                    func=ast.Name(id=func.target.id, ctx=ast.Load()),
                    args=list(call.args),
                    keywords=list(call.keywords),
                )
                _follow_local_callee(
                    synthetic,
                    path=path,
                    index=index,
                    env=env,
                    visited_fns=visited_fns,
                    local_fns=local_fns,
                    local_classes=local_classes,
                )
                return
            func = _peel_call_func(func)
        # ``getattr(Mut.make, "__call__")()`` — Call-form transparent peels only.
        # Do not peel Attribute ``X.__call__`` here: that path owns packed
        # method follow (``next(iter([Mut.make])).__call__()``).
        if isinstance(func, ast.Call):
            peeled_func = _peel_transparent_callee(func)
            if peeled_func is not func:
                _follow_local_callee(
                    ast.Call(
                        func=peeled_func,
                        args=list(call.args),
                        keywords=list(call.keywords),
                    ),
                    path=path,
                    index=index,
                    env=env,
                    visited_fns=visited_fns,
                    local_fns=local_fns,
                    local_classes=local_classes,
                )
                return
        # ``getattr(functools, "reduce")(…)`` / ``getattr(itertools, "starmap")``
        # / ``getattr(builtins, "sorted|max|min")(…, key=…)`` /
        # ``getattr(mk, "__func__")(Mut)`` / ``getattr(list, "sort")(…)``.
        if isinstance(func, ast.Call):
            gname = _getattr_static_name(
                func, getattr_aliases=frozenset(getattr_aliases)
            )
            if gname == "__func__" and func.args:
                _follow_local_callee(
                    ast.Call(
                        func=ast.Attribute(
                            value=func.args[0], attr="__func__", ctx=ast.Load()
                        ),
                        args=list(call.args),
                        keywords=list(call.keywords),
                    ),
                    path=path,
                    index=index,
                    env=env,
                    visited_fns=visited_fns,
                    local_fns=local_fns,
                    local_classes=local_classes,
                )
                return
            if gname == "sort":
                _follow_local_callee(
                    ast.Call(
                        func=ast.Attribute(
                            value=func.args[0] if func.args else ast.Name(id="list", ctx=ast.Load()),
                            attr="sort",
                            ctx=ast.Load(),
                        ),
                        args=list(call.args),
                        keywords=list(call.keywords),
                    ),
                    path=path,
                    index=index,
                    env=env,
                    visited_fns=visited_fns,
                    local_fns=local_fns,
                    local_classes=local_classes,
                )
                return
            if gname in _KEY_APPLICATOR_NAMES | {"starmap"} | _ITERTOOLS_ADAPTER_NAMES:
                _follow_local_callee(
                    ast.Call(
                        func=ast.Name(id=gname, ctx=ast.Load()),
                        args=list(call.args),
                        keywords=list(call.keywords),
                    ),
                    path=path,
                    index=index,
                    env=env,
                    visited_fns=visited_fns,
                    local_fns=local_fns,
                    local_classes=local_classes,
                )
                return
            # ``(lambda: n.install)()(evil)`` /
            # ``(lambda: getattr(n, "install"))()(evil)`` — returning-lambda.
            inner_func = _peel_call_func(func.func)
            if isinstance(inner_func, ast.Lambda):
                # Apply the zero-arg (or arg) lambda, then call its body product.
                _follow_local_callee(
                    func,
                    path=path,
                    index=index,
                    env=env,
                    visited_fns=visited_fns,
                    local_fns=local_fns,
                    local_classes=local_classes,
                )
                body = _peel_call_func(inner_func.body)
                if isinstance(body, ast.Call):
                    gname = _getattr_static_name(
                        body, getattr_aliases=frozenset(getattr_aliases)
                    )
                    if gname is not None and body.args:
                        body = ast.Attribute(
                            value=body.args[0], attr=gname, ctx=ast.Load()
                        )
                if isinstance(body, (ast.Attribute, ast.Name, ast.Subscript)):
                    _follow_local_callee(
                        ast.Call(
                            func=body,
                            args=list(call.args),
                            keywords=list(call.keywords),
                        ),
                        path=path,
                        index=index,
                        env=env,
                        visited_fns=visited_fns,
                        local_fns=local_fns,
                        local_classes=local_classes,
                    )
                    return
            # ``object.__getattribute__(Mut, "make")()``.
            fpeeled = _peel_call_func(func.func)
            if (
                isinstance(fpeeled, ast.Attribute)
                and fpeeled.attr == "__getattribute__"
                and len(func.args) >= 2
            ):
                attr = _static_str(func.args[1])
                if attr is not None:
                    _follow_local_callee(
                        ast.Call(
                            func=ast.Attribute(
                                value=func.args[0], attr=attr, ctx=ast.Load()
                            ),
                            args=list(call.args),
                            keywords=list(call.keywords),
                        ),
                        path=path,
                        index=index,
                        env=env,
                        visited_fns=visited_fns,
                        local_fns=local_fns,
                        local_classes=local_classes,
                    )
                    return
        if isinstance(func, ast.Lambda):
            # Follow lambda bodies for *args/**kwargs/pos-only/kw-only, and
            # apply defaults at the call site (default-to-call). Skipping the
            # body for vararg shapes false-PASSes ``lambda *a: poison(); f()``
            # and ``lambda x=(lambda: poison()): x(); f()`` (#173).
            call_env = _copy_env(env)
            pos_params = [a.arg for a in func.args.posonlyargs] + [
                a.arg for a in func.args.args
            ]
            kwonly_params = [a.arg for a in func.args.kwonlyargs]
            defaults = list(func.args.defaults)
            num_no_default = len(pos_params) - len(defaults)
            bound_pos: set[int] = set()
            # Defaults that are lambdas must be followable when the body calls
            # the formal (``lambda x=(lambda: poison()): x(); f()``).
            saved_lambda_bindings: dict[str, ast.Lambda | None] = {}
            # Expand ``*[type.__call__]`` so star-applied lambdas seed formals
            # (``(lambda f: f(Mut))(*[type.__call__])`` — Unknown > false PASS).
            expanded_args: list[ast.AST] = []
            for arg in call.args:
                if isinstance(arg, ast.Starred):
                    elems = _iter_elements(arg.value)
                    if elems is None:
                        _escape_if_tracked(
                            _eval_expr(arg.value, env, path=path)
                        )
                        continue
                    expanded_args.extend(elems)
                else:
                    expanded_args.append(arg)
            for i, arg in enumerate(expanded_args):
                if i < len(pos_params):
                    call_env[pos_params[i]] = _eval_expr(arg, env, path=path)
                    bound_pos.add(i)
                    # ``(lambda f: f(Mut))(type.__call__)`` — seed protocol
                    # aliases on formals from actuals (Unknown > false PASS).
                    _note_protocol_alias_from_value(pos_params[i], arg)
                    if isinstance(arg, ast.Lambda):
                        saved_lambda_bindings.setdefault(
                            pos_params[i], lambda_bindings.get(pos_params[i])
                        )
                        lambda_bindings[pos_params[i]] = arg
                else:
                    _escape_if_tracked(_eval_expr(arg, env, path=path))
            for i, name in enumerate(pos_params):
                if i in bound_pos:
                    continue
                default_idx = i - num_no_default
                if 0 <= default_idx < len(defaults):
                    default_expr = defaults[default_idx]
                    call_env[name] = _eval_expr(default_expr, env, path=path)
                    # ``(lambda f=type.__call__: f(Mut))()`` — seed defaults.
                    _note_protocol_alias_from_value(name, default_expr)
                    if isinstance(default_expr, ast.Lambda):
                        saved_lambda_bindings.setdefault(
                            name, lambda_bindings.get(name)
                        )
                        lambda_bindings[name] = default_expr
                else:
                    call_env[name] = _IdentityPointsTo.unknown_only()
            provided_kw: set[str] = set()
            # ``**{"f": type.__call__}`` — peel mapping items into formals /
            # ``**kwargs`` pack (Unknown > false PASS).
            kwarg_pack_items: list[tuple[ast.AST | None, ast.AST | None]] = []
            for kw in call.keywords:
                if kw.arg is None:
                    items = _mapping_items(kw.value)
                    if items is None:
                        _escape_if_tracked(_eval_expr(kw.value, env, path=path))
                        continue
                    for map_key, map_val in items:
                        if map_val is None:
                            continue
                        if (
                            isinstance(map_key, ast.Constant)
                            and isinstance(map_key.value, str)
                        ):
                            provided_kw.add(map_key.value)
                            if (
                                map_key.value in pos_params
                                or map_key.value in kwonly_params
                            ):
                                call_env[map_key.value] = _eval_expr(
                                    map_val, env, path=path
                                )
                                _note_protocol_alias_from_value(
                                    map_key.value, map_val
                                )
                            else:
                                kwarg_pack_items.append((map_key, map_val))
                        else:
                            kwarg_pack_items.append((map_key, map_val))
                    continue
                provided_kw.add(kw.arg)
                if kw.arg in pos_params or kw.arg in kwonly_params:
                    call_env[kw.arg] = _eval_expr(kw.value, env, path=path)
                    _note_protocol_alias_from_value(kw.arg, kw.value)
                    if isinstance(kw.value, ast.Lambda):
                        saved_lambda_bindings.setdefault(
                            kw.arg, lambda_bindings.get(kw.arg)
                        )
                        lambda_bindings[kw.arg] = kw.value
                else:
                    kwarg_pack_items.append(
                        (ast.Constant(value=kw.arg), kw.value)
                    )
            for name, default in zip(kwonly_params, func.args.kw_defaults):
                if name in provided_kw:
                    continue
                if default is not None:
                    call_env[name] = _eval_expr(default, env, path=path)
                    _note_protocol_alias_from_value(name, default)
                    if isinstance(default, ast.Lambda):
                        saved_lambda_bindings.setdefault(
                            name, lambda_bindings.get(name)
                        )
                        lambda_bindings[name] = default
                else:
                    call_env[name] = _IdentityPointsTo.unknown_only()
            if func.args.vararg is not None:
                var_name = func.args.vararg.arg
                call_env[var_name] = _IdentityPointsTo.unknown_only()
                # ``(lambda *a: a[0](Mut))(*[type.__call__])`` — seed *args pack
                # from expanded star actuals (shared with **kwargs peels).
                excess = [
                    arg
                    for i, arg in enumerate(expanded_args)
                    if i >= len(pos_params)
                ]
                if not excess and not pos_params:
                    excess = list(expanded_args)
                if excess:
                    pack = {
                        i: tuple(_packed_names_deep(arg))
                        for i, arg in enumerate(excess)
                        if _packed_names_deep(arg)
                    }
                    # Also keep flat None-slot for ``a[0]`` int projections.
                    flat = [n for arg in excess for n in _packed_names_deep(arg)]
                    if flat:
                        pack[None] = tuple(dict.fromkeys(flat))
                        for i, arg in enumerate(excess):
                            names = _packed_names_deep(arg)
                            if names:
                                pack[i] = tuple(dict.fromkeys(names))
                        container_packs[var_name] = pack
                        sequence_view_aliases[var_name] = ast.List(
                            elts=list(excess), ctx=ast.Load()
                        )
                        for i, arg in enumerate(excess):
                            _note_protocol_alias_from_value(
                                f"{var_name}@{i}", arg
                            )
            if func.args.kwarg is not None:
                kw_name = func.args.kwarg.arg
                call_env[kw_name] = _IdentityPointsTo.unknown_only()
                if kwarg_pack_items:
                    # Seed ``**k`` pack so ``list(k.values())[0](Mut)`` peels.
                    pack = _pack_from_items(kwarg_pack_items)
                    if pack:
                        container_packs[kw_name] = pack
                        sequence_view_aliases[kw_name] = ast.Dict(
                            keys=[k for k, _ in kwarg_pack_items],
                            values=[
                                v if v is not None else ast.Constant(value=None)
                                for _, v in kwarg_pack_items
                            ],
                        )
            try:
                if isinstance(func.body, ast.Call):
                    _scan_call(
                        func.body,
                        path=path,
                        index=index,
                        env=call_env,
                        visited_fns=visited_fns,
                        local_fns=local_fns,
                        local_classes=local_classes,
                    )
                else:
                    _escape_if_tracked(_eval_expr(func.body, call_env, path=path))
            finally:
                for name, previous in saved_lambda_bindings.items():
                    if previous is None:
                        lambda_bindings.pop(name, None)
                    else:
                        lambda_bindings[name] = previous
            return
        # Name-bound lambda: ``poison = lambda: setattr(...); poison()``.
        if isinstance(func, ast.Name) and func.id in lambda_bindings:
            bound = lambda_bindings[func.id]
            synthetic = ast.Call(
                func=bound,
                args=list(call.args),
                keywords=list(call.keywords),
            )
            _follow_local_callee(
                synthetic,
                path=path,
                index=index,
                env=env,
                visited_fns=visited_fns,
                local_fns=local_fns,
                local_classes=local_classes,
            )
            return
        # Bound method alias: ``p = Mut().poison; p()`` / ``mk = Mut.make; mk()`` /
        # ``for p in [m.poke]: p()`` via bound_callee_exprs Attribute peel.
        if isinstance(func, ast.Name) and (
            func.id in method_bindings or func.id in bound_callee_exprs
        ):
            method_node = method_bindings.get(func.id)
            bound_expr = bound_callee_exprs.get(func.id)
            method_attr: ast.Attribute | None = None
            if isinstance(bound_expr, ast.Attribute):
                method_attr = bound_expr
                if method_attr.attr in {"__call__", "__func__"}:
                    peeled = (
                        _peel_call_func(method_attr.value)
                        if method_attr.attr == "__func__"
                        else _peel_transparent_callee(method_attr)
                    )
                    if isinstance(peeled, ast.Attribute):
                        method_attr = peeled
                if method_node is None:
                    method_node = _resolve_attribute_method(
                        method_attr, local_classes=local_classes
                    )
            if method_node is not None:
                scan_classes = dict(local_classes or {})
                # Classmethod Name binds must seed ``cls`` from the Attribute
                # receiver (``mk = Mut.make; mk()`` ≡ ``Mut.make()``).
                if _method_has_decorator(method_node, frozenset({"classmethod"})):
                    owner = None
                    if method_attr is not None:
                        owner = _resolve_receiver_class(
                            method_attr.value, local_classes=local_classes
                        )
                    if owner is None:
                        for class_node in (local_classes or class_registry).values():
                            if (
                                _class_method_by_name(class_node, method_node.name)
                                is method_node
                            ):
                                owner = class_node
                                break
                    if owner is not None and method_node.args.args:
                        scan_classes[method_node.args.args[0].arg] = owner
                _scan_fn_body(
                    method_node,
                    path=path,
                    index=index,
                    env=env,
                    visited_fns=visited_fns,
                    local_fns=local_fns,
                    local_classes=scan_classes,
                    formals=_formal_bindings_for_call(
                        call, method_node, env, path=path
                    ),
                )
                return
        def _resolve_nested_or_local_class(name: str, holder: ast.ClassDef | None) -> ast.ClassDef | None:
            if holder is not None:
                for item in holder.body:
                    if isinstance(item, ast.ClassDef) and item.name == name:
                        return item
                    if isinstance(item, ast.Assign) and any(
                        isinstance(t, ast.Name) and t.id == name for t in item.targets
                    ):
                        for packed in _packed_names(item.value):
                            nested = _lookup_class(packed, local_classes)
                            if nested is not None:
                                return nested
            return _lookup_class(name, local_classes)

        def _observe_classes_from_names(names: Sequence[str]) -> bool:
            observed = False
            for name in names:
                cls_node = _lookup_class(name, local_classes)
                if cls_node is None:
                    continue
                _observe_class_construction(
                    cls_node,
                    call,
                    path=path,
                    index=index,
                    env=env,
                    visited_fns=visited_fns,
                    local_fns=local_fns,
                    local_classes=local_classes,
                )
                observed = True
            return observed

        def _follow_accounted_module_attr(
            receiver: ast.AST, attr: str
        ) -> bool:
            """Follow ``n.install`` / ``getattr(n, \"install\")`` export bodies."""

            points = _eval_expr(receiver, env, path=path)
            module_paths = [
                atom.path for atom in points.known if isinstance(atom, ModuleObject)
            ]
            if (
                len(module_paths) != 1
                or points.unknown
                or any(
                    isinstance(a, (ModuleNamespace, CallableObject))
                    for a in points.known
                )
            ):
                return False
            mod_path = module_paths[0]
            binding = bindings_by_path.get(mod_path, {}).get(attr)
            if (
                binding is None
                or binding.kind != "function"
                or binding.function_node is None
            ):
                return False
            _scan_fn_body(
                binding.function_node,
                path=mod_path,
                index=index,
                env=env,
                visited_fns=visited_fns,
                local_fns=None,
                local_classes=None,
                formals=_formal_bindings_for_call(
                    call, binding.function_node, env, path=path
                ),
            )
            return True

        def _follow_callable_points(points: _IdentityPointsTo) -> bool:
            """Follow a unique accounted CallableObject points-to set."""

            callables = [a for a in points.known if isinstance(a, CallableObject)]
            if (
                len(callables) != 1
                or points.unknown
                or any(
                    isinstance(a, (ModuleObject, ModuleNamespace))
                    for a in points.known
                )
            ):
                return False
            atom = callables[0]
            binding = bindings_by_path.get(atom.defining_path, {}).get(
                atom.export_name
            )
            if (
                binding is None
                or binding.kind != "function"
                or binding.function_node is None
            ):
                return False
            _scan_fn_body(
                binding.function_node,
                path=atom.defining_path,
                index=index,
                env=env,
                visited_fns=visited_fns,
                local_fns=None,
                local_classes=None,
                formals=_formal_bindings_for_call(
                    call, binding.function_node, env, path=path
                ),
            )
            return True

        def _observe_type_new_from_args() -> bool:
            """Observe ``type.__new__(type, name, bases, dict)``-shaped args."""

            bases_expr: ast.AST | None = None
            if len(call.args) >= 3:
                bases_expr = call.args[2]
            for kw in call.keywords:
                if kw.arg == "bases":
                    bases_expr = kw.value
            if bases_expr is None:
                accum.unsupported = True
                return True
            base_names = _packed_names(bases_expr)
            if isinstance(bases_expr, (ast.Tuple, ast.List)):
                base_names = []
                for elt in bases_expr.elts:
                    nested = elt.value if isinstance(elt, ast.Starred) else elt
                    base_names.extend(_packed_names(nested))
            observed = False
            for name in base_names:
                base_cls = _lookup_class(name, local_classes)
                if base_cls is not None:
                    if _scan_named_methods_on_class(
                        base_cls,
                        frozenset({"__init_subclass__"}),
                        path=path,
                        index=index,
                        env=env,
                        visited_fns=visited_fns,
                        local_fns=local_fns,
                        local_classes=local_classes,
                    ):
                        observed = True
                else:
                    accum.unsupported = True
            if not observed:
                accum.unsupported = True
            return True

        def _receiver_is_type_builtin(recv: ast.AST) -> bool:
            for name in _packed_names(recv):
                if (
                    name == _TYPE_BUILTIN_NAME
                    or name in type_aliases
                    or name == "object"
                ):
                    return True
            peeled = _peel_call_func(recv)
            if isinstance(peeled, ast.Attribute) and peeled.attr in {
                "__class__",
                _TYPE_BUILTIN_NAME,
            }:
                return True
            return False

        def _observe_name_bound_factory_product(product_name: str) -> bool:
            """Apply Name-bound attrgetter/itemgetter/methodcaller/partial product."""

            product = projection_factory_products.get(product_name)
            if product is None:
                return False
            kind, static = product
            if kind == "attrgetter" and static is not None:
                if static == "__call__" and call.args:
                    if _observe_classes_from_names(_packed_names(call.args[0])):
                        return True
                holder_cls = None
                if call.args and isinstance(call.args[0], ast.Name):
                    holder_cls = _lookup_class(call.args[0].id, local_classes)
                nested = _resolve_nested_or_local_class(static, holder_cls)
                if nested is not None:
                    _observe_class_construction(
                        nested,
                        call,
                        path=path,
                        index=index,
                        env=env,
                        visited_fns=visited_fns,
                        local_fns=local_fns,
                        local_classes=local_classes,
                    )
                    return True
                if _observe_classes_from_names([static]):
                    return True
                accum.unsupported = True
                return True
            if kind == "itemgetter" and static is not None:
                if _observe_classes_from_names([static]):
                    return True
                accum.unsupported = True
                return True
            if kind == "methodcaller" and static is not None:
                if static == "__call__" and call.args:
                    if _observe_classes_from_names(_packed_names(call.args[0])):
                        return True
                if _follow_methods_named(
                    static,
                    call,
                    path=path,
                    index=index,
                    env=env,
                    visited_fns=visited_fns,
                    local_fns=local_fns,
                    local_classes=local_classes,
                ):
                    return True
                accum.unsupported = True
                return True
            if kind == "partial":
                names = partial_product_names.get(product_name, [])
                if _observe_classes_from_names(names):
                    return True
                accum.unsupported = True
                return True
            return False

        def _follow_accounted_candidates(callee: ast.AST) -> bool:
            """Follow accounted ``module.export`` bodies reachable from ``callee``.

            One shared peel for ``getattr(n, "install")(…)``,
            ``n.install.__call__(…)``, ``getattr(n, "install").__call__(…)``,
            ``[n.install][0](…)`` and ``next(iter([n.install]))(…)``.
            """

            followed = False
            for cand in _callee_candidate_exprs(callee):
                for recv, attr in _accounted_attr_refs(cand):
                    if _follow_accounted_module_attr(recv, attr):
                        followed = True
            return followed

        def _follow_packed_key_applicator(callee: ast.AST) -> bool:
            """Rewrite packed/getattr key applicators onto the shared Name path.

            Covers ``[getattr(builtins,"sorted")][0](…, key=)``,
            ``next(iter([getattr(builtins,"sorted")]))(…, key=)``,
            ``[s][0]`` / ``(False or s)`` / ``s.__call__`` /
            ``s.__call__.__call__`` / ``getattr(builtins,"sorted").__call__`` /
            ``list.sort.__call__`` import-as packs,
            ``[list.sort][0]`` / ``getattr(list,"sort")`` /
            ``[getattr(xs,"sort")][0]`` / ``from builtins import list as L;
            L.sort`` / ``methodcaller("sort", key=…)(xs)``
            (Unknown > false PASS).
            """

            for cand in _callee_candidate_exprs(callee):
                cand = _peel_transparent_callee(cand)
                key_name: str | None = None
                bound_recv: ast.AST | None = None
                if isinstance(cand, ast.Name):
                    key_name = operator_projection_aliases.get(cand.id, cand.id)
                    if cand.id in dict_view_products:
                        key_name = dict_view_products[cand.id]
                        if key_name == "sort":
                            recv_name = bound_view_receivers.get(cand.id)
                            if recv_name is not None:
                                bound_recv = ast.Name(
                                    id=recv_name, ctx=ast.Load()
                                )
                elif isinstance(cand, ast.Attribute):
                    if cand.attr in _KEY_APPLICATOR_NAMES | {"sort", "starmap"}:
                        if cand.attr == "sort":
                            if _is_unbound_list_recv(cand.value):
                                key_name = "list.sort"
                            else:
                                key_name = "sort"
                                bound_recv = cand.value
                        else:
                            key_name = cand.attr
                elif isinstance(cand, ast.Call):
                    gname = _getattr_static_name(
                        cand, getattr_aliases=frozenset(getattr_aliases)
                    )
                    if gname in _KEY_APPLICATOR_NAMES | {"starmap", "sort"}:
                        if gname == "sort":
                            # Bound ``getattr(xs,"sort")`` vs unbound
                            # ``getattr(list,"sort")``.
                            recv = cand.args[0] if cand.args else None
                            if recv is not None and _is_unbound_list_recv(recv):
                                key_name = "list.sort"
                            else:
                                key_name = "sort"
                                bound_recv = cand.args[0] if cand.args else None
                        else:
                            key_name = gname
                    elif gname == "__get__" and cand.args:
                        # ``getattr(list.sort, "__get__")(None, list)``.
                        sort_desc = _peel_call_func(cand.args[0])
                        if (
                            isinstance(sort_desc, ast.Attribute)
                            and sort_desc.attr == "sort"
                            and _is_unbound_list_recv(sort_desc.value)
                        ):
                            key_name = "list.sort"
                    elif _is_partial_factory(
                        cand,
                        partial_aliases=frozenset(partial_aliases),
                        getattr_aliases=frozenset(getattr_aliases),
                    ) and cand.args:
                        # ``[partial(L.sort, xs)][0](key=…)`` /
                        # ``(0 or partial(list.sort, xs))(key=…)``.
                        bound0 = _peel_call_func(cand.args[0])
                        sort_kind: str | None = None
                        sort_bound: ast.AST | None = None
                        if isinstance(bound0, ast.Attribute) and bound0.attr == "sort":
                            if _is_unbound_list_recv(bound0.value):
                                sort_kind = "list.sort"
                            else:
                                sort_kind = "sort"
                                sort_bound = bound0.value
                        elif isinstance(bound0, ast.Call):
                            sg = _getattr_static_name(
                                bound0,
                                getattr_aliases=frozenset(getattr_aliases),
                            )
                            if sg == "sort" and bound0.args:
                                if _is_unbound_list_recv(bound0.args[0]):
                                    sort_kind = "list.sort"
                                else:
                                    sort_kind = "sort"
                                    sort_bound = bound0.args[0]
                        if sort_kind is not None:
                            syn_keywords = list(call.keywords)
                            if len(cand.args) >= 2 and sort_kind == "list.sort":
                                # ``partial(list.sort|L.sort, xs)(key=…)``.
                                _follow_local_callee(
                                    ast.Call(
                                        func=ast.Attribute(
                                            value=ast.Name(
                                                id="list", ctx=ast.Load()
                                            ),
                                            attr="sort",
                                            ctx=ast.Load(),
                                        ),
                                        args=[cand.args[1], *call.args],
                                        keywords=syn_keywords,
                                    ),
                                    path=path,
                                    index=index,
                                    env=env,
                                    visited_fns=visited_fns,
                                    local_fns=local_fns,
                                    local_classes=local_classes,
                                )
                                return True
                            if sort_kind == "sort" and (
                                sort_bound is not None or len(cand.args) >= 2
                            ):
                                # Bound ``partial(xs.sort)(key=…)`` /
                                # ``partial(xs.sort, …)``.
                                recv = (
                                    sort_bound
                                    if sort_bound is not None
                                    else cand.args[1]
                                )
                                _follow_local_callee(
                                    ast.Call(
                                        func=ast.Attribute(
                                            value=recv,
                                            attr="sort",
                                            ctx=ast.Load(),
                                        ),
                                        args=list(call.args),
                                        keywords=syn_keywords,
                                    ),
                                    path=path,
                                    index=index,
                                    env=env,
                                    visited_fns=visited_fns,
                                    local_fns=local_fns,
                                    local_classes=local_classes,
                                )
                                return True
                            key_name = sort_kind
                            bound_recv = sort_bound
                    else:
                        # ``methodcaller("sort", key=…)`` applied later.
                        mc = _methodcaller_static_name(
                            cand,
                            projection_aliases=operator_projection_aliases,
                            getattr_aliases=frozenset(getattr_aliases),
                        )
                        if mc == "sort":
                            key_name = "sort"
                            # Bound args after method name may include key=.
                            # Receiver is the applied call arg.
                            if call.args:
                                bound_recv = call.args[0]
                                # methodcaller('sort', key=…)(xs) — key from
                                # factory keywords / bound args.
                                syn_keywords = list(call.keywords)
                                for kw in cand.keywords:
                                    if kw.arg == "key" and not any(
                                        k.arg == "key" for k in syn_keywords
                                    ):
                                        syn_keywords.append(kw)
                                # Prefer synthesizing xs.sort(key=…).
                                _follow_local_callee(
                                    ast.Call(
                                        func=ast.Attribute(
                                            value=bound_recv,
                                            attr="sort",
                                            ctx=ast.Load(),
                                        ),
                                        args=[],
                                        keywords=syn_keywords,
                                    ),
                                    path=path,
                                    index=index,
                                    env=env,
                                    visited_fns=visited_fns,
                                    local_fns=local_fns,
                                    local_classes=local_classes,
                                )
                                return True
                        # Applied ``attrgetter("sort")(L)`` inside packing.
                        if cand.args and key_name is None:
                            ag_applied: str | None = None
                            for ag_cand in [
                                cand.func,
                                *_callee_candidate_exprs(cand.func),
                            ]:
                                ag_cand = _peel_call_func(ag_cand)
                                if isinstance(ag_cand, ast.Call):
                                    ag_applied = _attrgetter_static_name(
                                        ag_cand,
                                        projection_aliases=(
                                            operator_projection_aliases
                                        ),
                                        getattr_aliases=frozenset(
                                            getattr_aliases
                                        ),
                                    )
                                elif isinstance(ag_cand, ast.Name):
                                    product = projection_factory_products.get(
                                        ag_cand.id
                                    )
                                    if (
                                        product is not None
                                        and product[0] == "attrgetter"
                                    ):
                                        ag_applied = product[1]
                                if ag_applied == "sort":
                                    sort_recv = _peel_call_func(cand.args[0])
                                    if _is_unbound_list_recv(sort_recv):
                                        key_name = "list.sort"
                                    else:
                                        key_name = "sort"
                                        bound_recv = sort_recv
                                    break
                                ag_applied = None
                        # ``list.sort.__get__(None, list)`` as callee peel.
                        get_func = _peel_call_func(cand.func)
                        if (
                            key_name is None
                            and isinstance(get_func, ast.Attribute)
                            and get_func.attr == "__get__"
                        ):
                            desc = _peel_call_func(get_func.value)
                            if (
                                isinstance(desc, ast.Attribute)
                                and desc.attr == "sort"
                                and _is_unbound_list_recv(desc.value)
                            ):
                                key_name = "list.sort"
                            elif (
                                isinstance(desc, ast.Subscript)
                                and _resolve_static_str(desc.slice) == "sort"
                            ):
                                key_name = "list.sort"
                if key_name in _KEY_APPLICATOR_NAMES | {
                    "starmap",
                    "list.sort",
                    "sort",
                }:
                    if key_name in {"list.sort", "sort"}:
                        if key_name == "sort" and bound_recv is not None:
                            syn_func = ast.Attribute(
                                value=bound_recv,
                                attr="sort",
                                ctx=ast.Load(),
                            )
                            syn_args: list[ast.AST] = []
                        elif key_name == "list.sort":
                            syn_func = ast.Attribute(
                                value=ast.Name(id="list", ctx=ast.Load()),
                                attr="sort",
                                ctx=ast.Load(),
                            )
                            syn_args = list(call.args)
                        else:
                            syn_func = (
                                cand
                                if isinstance(cand, ast.Attribute)
                                else ast.Name(id=key_name, ctx=ast.Load())
                            )
                            syn_args = list(call.args)
                    else:
                        syn_func = ast.Name(id=key_name, ctx=ast.Load())
                        syn_args = list(call.args)
                    _follow_local_callee(
                        ast.Call(
                            func=syn_func,
                            args=syn_args,
                            keywords=list(call.keywords),
                        ),
                        path=path,
                        index=index,
                        env=env,
                        visited_fns=visited_fns,
                        local_fns=local_fns,
                        local_classes=local_classes,
                    )
                    return True
            return False

        # Module Attribute via bound_callee_exprs before benign Name fallthrough.
        if isinstance(func, ast.Name) and func.id in bound_callee_exprs:
            if _follow_accounted_candidates(func):
                return

        if isinstance(func, ast.Call):
            # ``getattr(n, "install")(evil)`` / ``next(iter([n.install]))(evil)``
            # — follow accounted export body before generic Call.func fallthrough.
            if _follow_accounted_candidates(func):
                return
            # Packed Attribute methods as Call.func:
            # ``next(iter(packs.values()))()`` / ``getattr(Mut, "make")()``.
            for cand in _callee_candidate_exprs(func):
                method_attr = cand
                if isinstance(method_attr, ast.Attribute) and method_attr.attr in {
                    "__call__",
                    "__func__",
                }:
                    peeled = (
                        _peel_call_func(method_attr.value)
                        if method_attr.attr == "__func__"
                        else _peel_transparent_callee(method_attr)
                    )
                    if isinstance(peeled, ast.Attribute):
                        method_attr = peeled
                if not isinstance(method_attr, ast.Attribute):
                    continue
                packed_method = _resolve_attribute_method(
                    method_attr, local_classes=local_classes
                )
                if packed_method is None:
                    continue
                scan_classes = dict(local_classes or {})
                if _method_has_decorator(
                    packed_method, frozenset({"classmethod"})
                ):
                    owner = _resolve_receiver_class(
                        method_attr.value, local_classes=local_classes
                    )
                    if owner is None:
                        for class_node in (
                            local_classes or class_registry
                        ).values():
                            if (
                                _class_method_by_name(
                                    class_node, packed_method.name
                                )
                                is packed_method
                            ):
                                owner = class_node
                                break
                    if owner is not None and packed_method.args.args:
                        scan_classes[packed_method.args.args[0].arg] = owner
                _scan_fn_body(
                    packed_method,
                    path=path,
                    index=index,
                    env=env,
                    visited_fns=visited_fns,
                    local_fns=local_fns,
                    local_classes=scan_classes,
                    formals=_formal_bindings_for_call(
                        call, packed_method, env, path=path
                    ),
                )
                return
            packed_func_names = _packed_names(func)
            # Name-bound factory products packed through ``next(iter([mc]))`` /
            # ``next(reversed([p]))`` / ``operator.concat([mc],[])[0]`` —
            # share the Subscript ``[mc][0]`` observe path (Unknown > false PASS).
            for pname in packed_func_names:
                if pname in projection_factory_products:
                    if _observe_name_bound_factory_product(pname):
                        return
            # Shared packing/projection peel: .get/.pop/getattr/attrgetter/
            # itemgetter/getitem/methodcaller/partial/next(iter)/…
            if _observe_classes_from_names(packed_func_names):
                for arg in call.args:
                    _escape_if_tracked(_eval_expr(arg, env, path=path))
                for kw in call.keywords:
                    _escape_if_tracked(_eval_expr(kw.value, env, path=path))
                return
            # Packed Name-bound type protocol: ``[tn][0](...)`` /
            # ``next(iter([tn]))`` / methodcaller packs.
            for pname in packed_func_names:
                tproto = type_protocol_products.get(pname)
                if tproto == "__new__":
                    for arg in call.args:
                        _eval_expr(arg, env, path=path)
                    for kw in call.keywords:
                        _eval_expr(kw.value, env, path=path)
                    _observe_type_new_from_args()
                    return
                if tproto == "__call__":
                    observed = False
                    for arg in call.args:
                        if _observe_classes_from_names(_packed_names(arg)):
                            observed = True
                    if not observed:
                        accum.unsupported = True
                    return
            # Packed ``type.__call__`` / ``type.__new__`` Attribute peels.
            if "__new__" in packed_func_names:
                for arg in call.args:
                    _eval_expr(arg, env, path=path)
                for kw in call.keywords:
                    _eval_expr(kw.value, env, path=path)
                _observe_type_new_from_args()
                return
            if "__call__" in packed_func_names:
                observed = False
                for arg in call.args:
                    if _observe_classes_from_names(_packed_names(arg)):
                        observed = True
                if call.args and not observed:
                    accum.unsupported = True
                if call.args:
                    return
            # Bound/unbound dict view: ``g = {}.get; g("missing", Mut)()`` /
            # ``g = dict.get; g({}, "missing", Mut)()``.
            fpeeled = _peel_call_func(func.func)
            if isinstance(fpeeled, ast.Name) and fpeeled.id in dict_view_products:
                view_exprs, view_keys = _dict_view_applied_parts(
                    dict_view_products[fpeeled.id], func.args
                )
                names: list[str] = list(view_keys)
                for view_expr in view_exprs:
                    names.extend(_packed_names_deep(view_expr))
                if _observe_classes_from_names(names):
                    return
                if names:
                    accum.unsupported = True
                    return
            # getattr(obj, "poison")() — follow the named method when static.
            getattr_name = _getattr_static_name(
                func, getattr_aliases=frozenset(getattr_aliases)
            )
            if getattr_name is not None:
                # ``getattr(Mut, "__call__")()`` constructs Mut.
                if getattr_name == "__call__" and func.args:
                    if _observe_classes_from_names(_packed_names(func.args[0])):
                        return
                    # ``getattr(p, "__call__")()`` when p is a factory product.
                    for recv_name in _packed_names(func.args[0]):
                        if _observe_name_bound_factory_product(recv_name):
                            return
                        if recv_name in class_projection_products:
                            if _observe_classes_from_names(
                                class_projection_products[recv_name]
                            ):
                                return
                    # ``getattr(type, "__call__")(Mut)``.
                    if _receiver_is_type_builtin(func.args[0]):
                        for arg in call.args:
                            if _observe_classes_from_names(_packed_names(arg)):
                                return
                        accum.unsupported = True
                        return
                # ``getattr(type, "__new__")(type, name, bases, dict)``.
                if getattr_name == "__new__" and func.args:
                    if _receiver_is_type_builtin(func.args[0]):
                        for arg in call.args:
                            _eval_expr(arg, env, path=path)
                        for kw in call.keywords:
                            _eval_expr(kw.value, env, path=path)
                        _observe_type_new_from_args()
                        return
                # ``getattr(Holder, "Mut")()`` nested / local class construction.
                holder_cls: ast.ClassDef | None = None
                if func.args:
                    recv = func.args[0]
                    if isinstance(recv, ast.Name):
                        holder_cls = _lookup_class(recv.id, local_classes)
                nested_via_getattr = _resolve_nested_or_local_class(
                    getattr_name, holder_cls
                )
                if nested_via_getattr is not None and (
                    holder_cls is not None
                    or _lookup_class(getattr_name, local_classes) is not None
                ):
                    # Prefer construction when the name denotes a class.
                    if _lookup_class(getattr_name, local_classes) is not None or (
                        holder_cls is not None
                        and any(
                            isinstance(item, ast.ClassDef) and item.name == getattr_name
                            for item in holder_cls.body
                        )
                    ):
                        _observe_class_construction(
                            nested_via_getattr,
                            call,
                            path=path,
                            index=index,
                            env=env,
                            visited_fns=visited_fns,
                            local_fns=local_fns,
                            local_classes=local_classes,
                        )
                        return
                if _follow_methods_named(
                    getattr_name,
                    call,
                    path=path,
                    index=index,
                    env=env,
                    visited_fns=visited_fns,
                    local_fns=local_fns,
                    local_classes=local_classes,
                ):
                    return
            # Name-bound factory product applied: ``ag(Holder)()`` where
            # ``ag = attrgetter("Mut")`` — func.func is the product Name.
            if isinstance(func.func, ast.Name) and _observe_name_bound_factory_product(
                func.func.id
            ):
                return
            # ``operator.attrgetter("Mut")(Holder)()`` / ``ag("Mut")(Holder)()``.
            if isinstance(func.func, ast.Call):
                ag = _attrgetter_static_name(
                    func.func, projection_aliases=operator_projection_aliases
                )
                if ag is not None:
                    if ag == "__call__" and func.args:
                        if _observe_classes_from_names(_packed_names(func.args[0])):
                            return
                    holder_cls = None
                    if func.args and isinstance(func.args[0], ast.Name):
                        holder_cls = _lookup_class(func.args[0].id, local_classes)
                    nested = _resolve_nested_or_local_class(ag, holder_cls)
                    if nested is not None:
                        _observe_class_construction(
                            nested,
                            call,
                            path=path,
                            index=index,
                            env=env,
                            visited_fns=visited_fns,
                            local_fns=local_fns,
                            local_classes=local_classes,
                        )
                        return
                    if _observe_classes_from_names([ag]):
                        return
                mc = _methodcaller_static_name(
                    func.func, projection_aliases=operator_projection_aliases
                )
                if mc == "__call__" and func.args:
                    if _observe_classes_from_names(_packed_names(func.args[0])):
                        return
                ig = _itemgetter_static_key(
                    func.func, projection_aliases=operator_projection_aliases
                )
                if ig is not None:
                    if _observe_classes_from_names([ig]):
                        return
                    accum.unsupported = True
                    return
            # ``functools.partial(Mut)()`` / renamed partial.
            if _is_partial_factory(
                func, partial_aliases=frozenset(partial_aliases)
            ) and func.args:
                if _observe_classes_from_names(_packed_names(func.args[0])):
                    return
                accum.unsupported = True
                return
            # ``operator.getitem({"Mut": Mut}, "Mut")()``.
            if (
                _projection_factory_name(
                    func, projection_aliases=operator_projection_aliases
                )
                == "getitem"
            ):
                if _observe_classes_from_names(_packed_names(func)):
                    return
                accum.unsupported = True
                return
            # operator.methodcaller("poison")(obj) / itemgetter class projection.
            methodcaller_name = _methodcaller_static_name(
                func, projection_aliases=operator_projection_aliases
            )
            if methodcaller_name is not None:
                if methodcaller_name == "__call__" and call.args:
                    if _observe_classes_from_names(_packed_names(call.args[0])):
                        return
                if _follow_methods_named(
                    methodcaller_name,
                    call,
                    path=path,
                    index=index,
                    env=env,
                    visited_fns=visited_fns,
                    local_fns=local_fns,
                    local_classes=local_classes,
                ):
                    return
            itemgetter_key = _itemgetter_static_key(
                func, projection_aliases=operator_projection_aliases
            )
            if itemgetter_key is not None:
                projected = _lookup_class(itemgetter_key, local_classes)
                if projected is not None:
                    _observe_class_construction(
                        projected,
                        call,
                        path=path,
                        index=index,
                        env=env,
                        visited_fns=visited_fns,
                        local_fns=local_fns,
                        local_classes=local_classes,
                    )
                    return
                # Dynamic itemgetter projection of a class — fail closed.
                accum.unsupported = True
                for arg in call.args:
                    _escape_if_tracked(_eval_expr(arg, env, path=path))
                return
            # Packed key applicators as Call.func (``next(iter([getattr(
            # builtins,"sorted")]))(…, key=)``) before chained-call fallthrough.
            if _follow_packed_key_applicator(func):
                return
            # Chained call ``make()()`` / ``factory()()`` returning a class:
            # evaluate the outer call, then observe construction when the
            # outer local helper returns a class Name (Unknown > false PASS).
            _scan_call(
                func,
                path=path,
                index=index,
                env=env,
                visited_fns=visited_fns,
                local_fns=local_fns,
                local_classes=local_classes,
            )
            returned_classes: list[ast.ClassDef] = []
            if isinstance(func.func, ast.Name):
                outer_fn: ast.FunctionDef | ast.AsyncFunctionDef | None = None
                if local_fns is not None and func.func.id in local_fns:
                    outer_fn = local_fns[func.func.id]
                if outer_fn is not None:
                    for stmt in outer_fn.body:
                        if isinstance(stmt, ast.Return) and stmt.value is not None:
                            for name in _packed_names(stmt.value):
                                cls_node = _lookup_class(name, local_classes)
                                if cls_node is not None:
                                    returned_classes.append(cls_node)
            for cls_node in returned_classes:
                _observe_class_construction(
                    cls_node,
                    call,
                    path=path,
                    index=index,
                    env=env,
                    visited_fns=visited_fns,
                    local_fns=local_fns,
                    local_classes=local_classes,
                )
            if not returned_classes:
                # Unresolved chained construction may still run __init__ —
                # fail closed rather than authorize (Unknown > false PASS).
                for name in _packed_names(func):
                    if _lookup_class(name, local_classes) is not None:
                        accum.unsupported = True
                        break
                # Projection Call.func that still looks dynamic — fail closed.
                if isinstance(func.func, (ast.Call, ast.Attribute, ast.Subscript)):
                    accum.unsupported = True
            for arg in call.args:
                _escape_if_tracked(_eval_expr(arg, env, path=path))
            for kw in call.keywords:
                _escape_if_tracked(_eval_expr(kw.value, env, path=path))
            return
        if isinstance(func, ast.Attribute):
            # ``functools.reduce`` / ``itertools.starmap`` / getattr Attribute peels.
            adapter = _itertools_adapter_name(
                func,
                projection_aliases=operator_projection_aliases,
                getattr_aliases=frozenset(getattr_aliases),
            )
            if (func.attr == "reduce" or adapter == "reduce") and len(call.args) >= 2:
                elems = _iter_elements(call.args[1]) or []
                _observe_lambda_apply(
                    call.args[0],
                    elems,
                    path=path,
                    index=index,
                    env=env,
                    visited_fns=visited_fns,
                    local_fns=local_fns,
                    local_classes=local_classes,
                    skip_first_formal=True,
                )
                for arg in call.args:
                    _eval_expr(arg, env, path=path)
                return
            if (func.attr == "starmap" or adapter == "starmap") and len(
                call.args
            ) >= 2:
                elems = _iter_elements(call.args[1]) or []
                _observe_lambda_apply(
                    call.args[0],
                    elems,
                    path=path,
                    index=index,
                    env=env,
                    visited_fns=visited_fns,
                    local_fns=local_fns,
                    local_classes=local_classes,
                    starmap=True,
                )
                for arg in call.args:
                    _eval_expr(arg, env, path=path)
                return
            # ``builtins.max|sorted|min(..., key=…)`` Attribute peels.
            if func.attr in {"sorted", "max", "min"}:
                key_expr: ast.AST | None = None
                for kw in call.keywords:
                    if kw.arg == "key":
                        key_expr = kw.value
                iterable = call.args[0] if call.args else None
                if key_expr is not None and iterable is not None:
                    _eval_expr(iterable, env, path=path)
                    elems = _iter_elements(iterable) or []
                    _observe_lambda_apply(
                        key_expr,
                        elems,
                        path=path,
                        index=index,
                        env=env,
                        visited_fns=visited_fns,
                        local_fns=local_fns,
                        local_classes=local_classes,
                    )
                    for kw in call.keywords:
                        _eval_expr(kw.value, env, path=path)
                    return
            # ``xs.sort(key=…)`` / unbound ``list.sort(xs, key=…)`` /
            # ``from builtins import list as L; L.sort(xs, key=…)``.
            if func.attr == "sort":
                key_expr = None
                for kw in call.keywords:
                    if kw.arg == "key":
                        key_expr = kw.value
                if key_expr is not None:
                    unbound = _is_unbound_list_recv(func.value)
                    if unbound and call.args:
                        elems = _iter_elements(call.args[0]) or []
                    else:
                        elems = _iter_elements(func.value) or []
                    _observe_lambda_apply(
                        key_expr,
                        elems,
                        path=path,
                        index=index,
                        env=env,
                        visited_fns=visited_fns,
                        local_fns=local_fns,
                        local_classes=local_classes,
                    )
                    for kw in call.keywords:
                        _eval_expr(kw.value, env, path=path)
                    if unbound:
                        for arg in call.args:
                            _eval_expr(arg, env, path=path)
                    else:
                        _eval_expr(func.value, env, path=path)
                    return
            # Nested class construction: ``Holder.Mut()``.
            if isinstance(func.value, ast.Name):
                holder = _lookup_class(func.value.id, local_classes)
                nested_cls = _resolve_nested_or_local_class(func.attr, holder)
                if nested_cls is not None and holder is not None:
                    # Only treat as construction when attr names a nested/local class.
                    if any(
                        isinstance(item, ast.ClassDef) and item.name == func.attr
                        for item in holder.body
                    ) or _lookup_class(func.attr, local_classes) is not None:
                        _observe_class_construction(
                            nested_cls,
                            call,
                            path=path,
                            index=index,
                            env=env,
                            visited_fns=visited_fns,
                            local_fns=local_fns,
                            local_classes=local_classes,
                        )
                        return
            # ``type.__new__(type, name, bases, dict)`` /
            # ``object.__class__.__new__(...)`` — observe bases / fail closed.
            if func.attr == "__new__":
                type_new_recv = False
                recv = func.value
                if isinstance(recv, ast.Name) and (
                    recv.id == _TYPE_BUILTIN_NAME
                    or recv.id in type_aliases
                    or recv.id == "object"
                ):
                    type_new_recv = True
                elif isinstance(recv, ast.Attribute) and recv.attr in {
                    "__class__",
                    _TYPE_BUILTIN_NAME,
                }:
                    type_new_recv = True
                if type_new_recv:
                    for arg in call.args:
                        _eval_expr(arg, env, path=path)
                    for kw in call.keywords:
                        _eval_expr(kw.value, env, path=path)
                    bases_expr: ast.AST | None = None
                    if len(call.args) >= 3:
                        bases_expr = call.args[2]
                    for kw in call.keywords:
                        if kw.arg == "bases":
                            bases_expr = kw.value
                    if bases_expr is None:
                        accum.unsupported = True
                        return
                    base_names = _packed_names(bases_expr)
                    if isinstance(bases_expr, (ast.Tuple, ast.List)):
                        base_names = []
                        for elt in bases_expr.elts:
                            nested = elt.value if isinstance(elt, ast.Starred) else elt
                            base_names.extend(_packed_names(nested))
                    observed = False
                    for name in base_names:
                        base_cls = _lookup_class(name, local_classes)
                        if base_cls is not None:
                            if _scan_named_methods_on_class(
                                base_cls,
                                frozenset({"__init_subclass__"}),
                                path=path,
                                index=index,
                                env=env,
                                visited_fns=visited_fns,
                                local_fns=local_fns,
                                local_classes=local_classes,
                            ):
                                observed = True
                        else:
                            accum.unsupported = True
                    if not observed:
                        accum.unsupported = True
                    return
            # ``Mut.__call__()`` / ``type.__call__(Mut)`` /
            # ``object.__class__.__call__(Mut)`` construct instances.
            if func.attr == "__call__":
                type_call_recv = False
                # Trailing ``.__call__`` / ``.__call__.__call__`` on key
                # applicators: ``getattr(builtins,"sorted").__call__`` /
                # ``s.__call__.__call__`` / ``list.sort.__call__`` share the
                # packed key-applicator peel (Unknown > false PASS).
                if _follow_packed_key_applicator(func):
                    return
                # ``s.__call__([Mut], key=…)`` when ``s`` is sorted/max/min/reduce.
                recv_peel = _peel_transparent_callee(func.value)
                if isinstance(recv_peel, ast.Name):
                    key_name = operator_projection_aliases.get(
                        recv_peel.id, recv_peel.id
                    )
                    if key_name in _KEY_APPLICATOR_NAMES | {"starmap", "list.sort", "sort"}:
                        _follow_local_callee(
                            ast.Call(
                                func=recv_peel,
                                args=list(call.args),
                                keywords=list(call.keywords),
                            ),
                            path=path,
                            index=index,
                            env=env,
                            visited_fns=visited_fns,
                            local_fns=local_fns,
                            local_classes=local_classes,
                        )
                        return
                # ``n.install.__call__(evil)`` / ``getattr(n, "install").__call__(evil)``
                # / ``[n.install][0].__call__(evil)`` — follow the accounted export
                # before any registry-wide ``__call__`` may-follow can mask it.
                if _follow_accounted_candidates(func):
                    return
                # ``getattr(type, "__new__").__call__(…)`` / protocol products on
                # the ``__call__`` receiver expression (shared peel).
                tproto_on_recv = _type_protocol_attr_from_value(
                    func.value,
                    getattr_aliases=frozenset(getattr_aliases),
                    protocol_products=type_protocol_products,
                    type_aliases=frozenset(type_aliases),
                )
                if tproto_on_recv == "__new__":
                    for arg in call.args:
                        _eval_expr(arg, env, path=path)
                    for kw in call.keywords:
                        _eval_expr(kw.value, env, path=path)
                    _observe_type_new_from_args()
                    return
                if tproto_on_recv == "__call__":
                    type_call_recv = True
                # Walrus product bind: ``(p := pf(Mut)).__call__()``.
                if isinstance(func.value, ast.NamedExpr) and isinstance(
                    func.value.target, ast.Name
                ):
                    _note_protocol_alias_from_value(
                        func.value.target.id, func.value.value
                    )
                    if _observe_name_bound_factory_product(func.value.target.id):
                        return
                recv = _peel_call_func(func.value)
                if isinstance(recv, ast.Call) and _is_partial_factory(
                    recv,
                    partial_aliases=frozenset(partial_aliases),
                    getattr_aliases=frozenset(getattr_aliases),
                ):
                    if recv.args and _observe_classes_from_names(
                        _packed_names(recv.args[0])
                    ):
                        return
                    accum.unsupported = True
                    return
                if isinstance(recv, ast.Name):
                    # ``p = partial(Mut); p.__call__()`` / factory products.
                    if _observe_name_bound_factory_product(recv.id):
                        return
                    # ``f = n.install; f.__call__(evil)`` — Name-bound export.
                    points = env.get(recv.id)
                    if points is not None and _follow_callable_points(points):
                        return
                    if recv.id in class_projection_products:
                        if _observe_classes_from_names(
                            class_projection_products[recv.id]
                        ):
                            return
                        accum.unsupported = True
                        return
                    # ``tc = type.__call__; tc.__call__(Mut)`` /
                    # ``tn = type.__new__; tn.__call__(…)``.
                    tproto_recv = type_protocol_products.get(recv.id)
                    if tproto_recv == "__new__":
                        for arg in call.args:
                            _eval_expr(arg, env, path=path)
                        for kw in call.keywords:
                            _eval_expr(kw.value, env, path=path)
                        _observe_type_new_from_args()
                        return
                    if tproto_recv == "__call__":
                        type_call_recv = True
                    elif (
                        recv.id == _TYPE_BUILTIN_NAME
                        or recv.id in type_aliases
                    ):
                        type_call_recv = True
                    else:
                        cls_node = _lookup_class(recv.id, local_classes)
                        if cls_node is not None:
                            _observe_class_construction(
                                cls_node,
                                call,
                                path=path,
                                index=index,
                                env=env,
                                visited_fns=visited_fns,
                                local_fns=local_fns,
                                local_classes=local_classes,
                            )
                            return
                # Peel walrus so ``(tc := type.__call__).__call__(Mut)`` uses
                # the Attribute receiver, not the NamedExpr wrapper.
                elif isinstance(recv, ast.Attribute) and recv.attr in {
                    "__class__",
                    _TYPE_BUILTIN_NAME,
                    "__call__",
                }:
                    if recv.attr == "__call__":
                        # ``Mut.__call__.__call__()`` / ``tc.__call__.__call__(Mut)`` /
                        # ``rest["c"].__call__.__call__()`` — peel through one
                        # transparent layer then share packed observation.
                        if _observe_classes_from_names(
                            _packed_names_deep(recv.value)
                        ):
                            return
                        if _receiver_is_type_builtin(recv.value):
                            type_call_recv = True
                        else:
                            nested = _peel_transparent_callee(recv.value)
                            packed_nested = _packed_names_deep(recv.value)
                            if isinstance(nested, ast.Name):
                                tproto_nested = type_protocol_products.get(
                                    nested.id
                                )
                                if tproto_nested == "__new__":
                                    for arg in call.args:
                                        _eval_expr(arg, env, path=path)
                                    for kw in call.keywords:
                                        _eval_expr(kw.value, env, path=path)
                                    _observe_type_new_from_args()
                                    return
                                if tproto_nested == "__call__" or (
                                    nested.id == _TYPE_BUILTIN_NAME
                                    or nested.id in type_aliases
                                ):
                                    type_call_recv = True
                            for packed_recv in packed_nested:
                                tproto_packed = type_protocol_products.get(
                                    packed_recv
                                )
                                if tproto_packed == "__new__":
                                    for arg in call.args:
                                        _eval_expr(arg, env, path=path)
                                    for kw in call.keywords:
                                        _eval_expr(kw.value, env, path=path)
                                    _observe_type_new_from_args()
                                    return
                                if (
                                    tproto_packed == "__call__"
                                    or packed_recv == _TYPE_BUILTIN_NAME
                                    or packed_recv in type_aliases
                                ):
                                    type_call_recv = True
                    else:
                        type_call_recv = True
                elif isinstance(func.value, ast.Attribute) and func.value.attr in {
                    "__class__",
                    _TYPE_BUILTIN_NAME,
                    "__call__",
                }:
                    # ``object.__class__.__call__(Mut)`` / ``x.type.__call__(…)`` /
                    # ``type.__call__.__call__(Mut)`` / ``Mut.__call__.__call__()`` /
                    # ``rest["c"].__call__.__call__()``.
                    if func.value.attr == "__call__":
                        nested_recv = _peel_transparent_callee(func.value.value)
                        packed_nested = _packed_names_deep(func.value.value)
                        if _observe_classes_from_names(packed_nested):
                            return
                        if isinstance(nested_recv, ast.Name) and (
                            nested_recv.id in type_protocol_products
                            or nested_recv.id == _TYPE_BUILTIN_NAME
                            or nested_recv.id in type_aliases
                        ):
                            tproto_nested = type_protocol_products.get(
                                nested_recv.id
                            )
                            if tproto_nested == "__new__":
                                for arg in call.args:
                                    _eval_expr(arg, env, path=path)
                                for kw in call.keywords:
                                    _eval_expr(kw.value, env, path=path)
                                _observe_type_new_from_args()
                                return
                            type_call_recv = True
                        else:
                            for packed_recv in packed_nested:
                                tproto_packed = type_protocol_products.get(
                                    packed_recv
                                )
                                if tproto_packed == "__new__":
                                    for arg in call.args:
                                        _eval_expr(arg, env, path=path)
                                    for kw in call.keywords:
                                        _eval_expr(kw.value, env, path=path)
                                    _observe_type_new_from_args()
                                    return
                                if (
                                    tproto_packed == "__call__"
                                    or packed_recv == _TYPE_BUILTIN_NAME
                                    or packed_recv in type_aliases
                                ):
                                    type_call_recv = True
                            if not type_call_recv:
                                type_call_recv = _receiver_is_type_builtin(
                                    func.value.value
                                )
                    else:
                        type_call_recv = True
                else:
                    # Shared peel for adapter / getattr / pack receivers:
                    # ``next(iter([tc])).__call__(Mut)`` /
                    # ``next(iter([getattr(type,"__new__")])).__call__(…)`` /
                    # ``getattr(tn, "__call__").__call__(…)`` /
                    # ``rest["c"].__call__()`` / ``(Mut if x else int).__call__()``.
                    packed_recv_names = _packed_names_deep(func.value)
                    if _observe_classes_from_names(packed_recv_names):
                        return
                    # Name-bound CallableObject: ``f = n.install; f.__call__(evil)``.
                    if isinstance(recv, ast.Name):
                        points = env.get(recv.id)
                        if points is not None and _follow_callable_points(points):
                            return
                    # Inline packed protocol attrs (parity with Call.func packs).
                    if "__new__" in packed_recv_names:
                        for arg in call.args:
                            _eval_expr(arg, env, path=path)
                        for kw in call.keywords:
                            _eval_expr(kw.value, env, path=path)
                        _observe_type_new_from_args()
                        return
                    if "__call__" in packed_recv_names:
                        type_call_recv = True
                    for packed_recv in packed_recv_names:
                        tproto_packed = type_protocol_products.get(packed_recv)
                        if tproto_packed == "__new__":
                            for arg in call.args:
                                _eval_expr(arg, env, path=path)
                            for kw in call.keywords:
                                _eval_expr(kw.value, env, path=path)
                            _observe_type_new_from_args()
                            return
                        if (
                            tproto_packed == "__call__"
                            or packed_recv == _TYPE_BUILTIN_NAME
                            or packed_recv in type_aliases
                        ):
                            type_call_recv = True
                if type_call_recv:
                    observed = False
                    for arg in call.args:
                        for name in _packed_names(arg):
                            cls_node = _lookup_class(name, local_classes)
                            if cls_node is not None:
                                _observe_class_construction(
                                    cls_node,
                                    call,
                                    path=path,
                                    index=index,
                                    env=env,
                                    visited_fns=visited_fns,
                                    local_fns=local_fns,
                                    local_classes=local_classes,
                                )
                                observed = True
                    if call.args:
                        if not observed:
                            accum.unsupported = True
                        return
            # Method calls: Mut().poison() / Mut.poison() / instance.poison().
            # After peeling trailing ``__call__``, re-dispatch Attribute methods
            # so ``Mut.make.__call__()`` ≡ ``Mut.make()`` /
            # ``next(iter([Mut.make])).__call__()`` / ``rest["m"].__call__()``.
            def _follow_resolved_method(
                method_node: ast.FunctionDef | ast.AsyncFunctionDef,
                attr_node: ast.Attribute,
            ) -> None:
                scan_classes = dict(local_classes or {})
                if _method_has_decorator(method_node, frozenset({"classmethod"})):
                    owner = _resolve_receiver_class(
                        attr_node.value, local_classes=local_classes
                    )
                    if owner is not None and method_node.args.args:
                        scan_classes[method_node.args.args[0].arg] = owner
                _scan_fn_body(
                    method_node,
                    path=path,
                    index=index,
                    env=env,
                    visited_fns=visited_fns,
                    local_fns=local_fns,
                    local_classes=scan_classes,
                    formals=_formal_bindings_for_call(
                        call, method_node, env, path=path
                    ),
                )

            def _peel_method_attr(node: ast.AST) -> ast.Attribute | None:
                """Peel ``__call__`` / ``__func__`` / Name-bound method attrs."""

                cur = _peel_call_func(node)
                while True:
                    if isinstance(cur, ast.Attribute) and cur.attr == "__call__":
                        cur = _peel_call_func(cur.value)
                        continue
                    if isinstance(cur, ast.Attribute) and cur.attr == "__func__":
                        cur = _peel_call_func(cur.value)
                        continue
                    if isinstance(cur, ast.Name) and cur.id in bound_callee_exprs:
                        cur = _peel_call_func(bound_callee_exprs[cur.id])
                        continue
                    break
                return cur if isinstance(cur, ast.Attribute) else None

            method_attr = func
            if func.attr == "__call__":
                peeled_method = _peel_transparent_callee(func)
                peeled_attr = _peel_method_attr(peeled_method)
                if peeled_attr is not None:
                    method_attr = peeled_attr
                elif isinstance(peeled_method, ast.Call):
                    # ``getattr(Mut, "make").__call__()`` /
                    # ``object.__getattribute__(Mut, "make").__call__()``.
                    gname = _getattr_static_name(
                        peeled_method,
                        getattr_aliases=frozenset(getattr_aliases),
                    )
                    if gname is None and peeled_method.args:
                        # ``object.__getattribute__(recv, "make")``.
                        fpeeled = _peel_call_func(peeled_method.func)
                        if (
                            isinstance(fpeeled, ast.Attribute)
                            and fpeeled.attr == "__getattribute__"
                            and len(peeled_method.args) >= 2
                        ):
                            gname = _static_str(peeled_method.args[1])
                        elif (
                            isinstance(fpeeled, ast.Name)
                            and fpeeled.id == "__getattribute__"
                            and len(peeled_method.args) >= 2
                        ):
                            gname = _static_str(peeled_method.args[1])
                    if gname is not None and gname != "__call__" and peeled_method.args:
                        method_attr = ast.Attribute(
                            value=peeled_method.args[0],
                            attr=gname,
                            ctx=ast.Load(),
                        )
            elif func.attr == "__func__":
                # ``Mut.make.__func__(Mut)`` / ``mk.__func__(Mut)`` /
                # ``Mut.smake.__func__()``.
                peeled_attr = _peel_method_attr(func.value)
                if peeled_attr is not None:
                    method_attr = peeled_attr
            method = (
                _resolve_attribute_method(
                    method_attr, local_classes=local_classes
                )
                if isinstance(method_attr, ast.Attribute)
                else None
            )
            if method is not None and isinstance(method_attr, ast.Attribute):
                _follow_resolved_method(method, method_attr)
                return
            # Packed Attribute methods under ``__call__`` /
            # ``next(iter([Mut.make])).__call__()`` / ``rest["m"].__call__()`` /
            # ``getattr(Mut, "make").__call__()`` /
            # ``SimpleNamespace(m=Mut.make).m()`` / ``ns.m()`` /
            # ``SimpleNamespace(e=n.install).e(evil)``.
            for cand in _callee_candidate_exprs(func):
                cand_attr = cand
                if isinstance(cand_attr, ast.Attribute) and cand_attr.attr in {
                    "__call__",
                    "__func__",
                }:
                    peeled = _peel_method_attr(cand_attr)
                    if peeled is not None:
                        cand_attr = peeled
                if not isinstance(cand_attr, ast.Attribute):
                    continue
                packed_method = _resolve_attribute_method(
                    cand_attr, local_classes=local_classes
                )
                if packed_method is not None:
                    _follow_resolved_method(packed_method, cand_attr)
                    return
                # Cross-module accounted: ``n.install`` packed under NS / dict.
                if _follow_accounted_module_attr(cand_attr.value, cand_attr.attr):
                    return
            # Packed class / exec Names under NS/dict attrs: ``ns.m()`` when
            # ``vars(ns)["m"]=Mut`` / ``ns.m=Mut`` /
            # ``(SimpleNamespace(e=exec) if True else None).e(...)``
            # (Unknown > false PASS).
            def _is_exec_name(name: str) -> bool:
                return (
                    name in _EXEC_EVAL_COMPILE_NAMES
                    or name in exec_eval_compile_aliases
                )

            for cand in _callee_candidate_exprs(func):
                if isinstance(cand, ast.Name):
                    if _is_exec_name(cand.id):
                        accum.unsupported = True
                        for arg in call.args:
                            _escape_if_tracked(_eval_expr(arg, env, path=path))
                        for kw in call.keywords:
                            _escape_if_tracked(
                                _eval_expr(kw.value, env, path=path)
                            )
                        return
                    cls_node = _lookup_class(cand.id, local_classes)
                    if cls_node is not None:
                        _observe_class_construction(
                            cls_node,
                            call,
                            path=path,
                            index=index,
                            env=env,
                            visited_fns=visited_fns,
                            local_fns=local_fns,
                            local_classes=local_classes,
                        )
                        return
            for pname in _packed_names(func):
                if _is_exec_name(pname):
                    accum.unsupported = True
                    for arg in call.args:
                        _escape_if_tracked(_eval_expr(arg, env, path=path))
                    for kw in call.keywords:
                        _escape_if_tracked(
                            _eval_expr(kw.value, env, path=path)
                        )
                    return
                cls_node = _lookup_class(pname, local_classes)
                if cls_node is not None:
                    _observe_class_construction(
                        cls_node,
                        call,
                        path=path,
                        index=index,
                        env=env,
                        visited_fns=visited_fns,
                        local_fns=local_fns,
                        local_classes=local_classes,
                    )
                    return
            # Factory / opaque receivers: may-execute every registered method
            # with this name (Unknown > false PASS).
            dispatch_attr = (
                method_attr.attr
                if isinstance(method_attr, ast.Attribute)
                else func.attr
            )
            if _follow_methods_named(
                dispatch_attr,
                call,
                path=path,
                index=index,
                env=env,
                visited_fns=visited_fns,
                local_fns=local_fns,
                local_classes=local_classes,
            ):
                return
            # Cross-module accounted calls: ``n.install(evil)`` /
            # ``n.install.__call__(evil)`` must follow the export body.
            if func.attr == "__call__" and isinstance(func.value, ast.Attribute):
                if _follow_accounted_module_attr(func.value.value, func.value.attr):
                    return
            if isinstance(method_attr, ast.Attribute):
                if _follow_accounted_module_attr(
                    method_attr.value, method_attr.attr
                ):
                    return
            receiver = _eval_expr(func.value, env, path=path)
            # ModuleNamespace method receivers (e.g. d.get) escape; ModuleObject
            # receivers of ordinary calls do not (unless followed above).
            if any(isinstance(a, ModuleNamespace) for a in receiver.known):
                _escape_identity(receiver)
            for arg in call.args:
                points = _eval_expr(arg, env, path=path)
                if any(
                    isinstance(a, (ModuleObject, CallableObject, ModuleNamespace))
                    for a in points.known
                ):
                    _escape_identity(points)
            for kw in call.keywords:
                points = _eval_expr(kw.value, env, path=path)
                if any(
                    isinstance(a, (ModuleObject, CallableObject, ModuleNamespace))
                    for a in points.known
                ):
                    _escape_identity(points)
            return
        if not isinstance(func, ast.Name):
            # ``getattr(n, "install")(evil)`` / ``[n.install][0](evil)`` /
            # ``next(iter([n.install]))(evil)`` — shared candidate peel.
            if _follow_accounted_candidates(func):
                return
            # Packed key applicators: ``[getattr(builtins,"sorted")][0](…, key=)``
            # / ``next(iter([getattr…]))`` / ``[s][0]`` / ``(False or s)`` /
            # ``s.__call__`` / ``[list.sort][0]`` / ``getattr(list,"sort")``.
            if _follow_packed_key_applicator(func):
                return
            # Packed Attribute methods: ``next(iter(packs.values()))()`` /
            # ``[m.poke][0]()`` / ``getattr(Mut, "make")()`` (parity with
            # ``.….__call__()`` Attribute path — Unknown > false PASS).
            for cand in _callee_candidate_exprs(func):
                method_attr = cand
                if isinstance(method_attr, ast.Attribute) and method_attr.attr in {
                    "__call__",
                    "__func__",
                }:
                    peeled = (
                        _peel_call_func(method_attr.value)
                        if method_attr.attr == "__func__"
                        else _peel_transparent_callee(method_attr)
                    )
                    if isinstance(peeled, ast.Attribute):
                        method_attr = peeled
                if not isinstance(method_attr, ast.Attribute):
                    continue
                packed_method = _resolve_attribute_method(
                    method_attr, local_classes=local_classes
                )
                if packed_method is None:
                    continue
                scan_classes = dict(local_classes or {})
                if _method_has_decorator(
                    packed_method, frozenset({"classmethod"})
                ):
                    owner = _resolve_receiver_class(
                        method_attr.value, local_classes=local_classes
                    )
                    if owner is None:
                        for class_node in (
                            local_classes or class_registry
                        ).values():
                            if (
                                _class_method_by_name(
                                    class_node, packed_method.name
                                )
                                is packed_method
                            ):
                                owner = class_node
                                break
                    if owner is not None and packed_method.args.args:
                        scan_classes[packed_method.args.args[0].arg] = owner
                _scan_fn_body(
                    packed_method,
                    path=path,
                    index=index,
                    env=env,
                    visited_fns=visited_fns,
                    local_fns=local_fns,
                    local_classes=scan_classes,
                    formals=_formal_bindings_for_call(
                        call, packed_method, env, path=path
                    ),
                )
                return
            if isinstance(func, ast.Subscript):
                # Packed Attribute / Name callable: ``[n.install][0]``.
                if _follow_callable_points(_eval_expr(func, env, path=path)):
                    return
            # BoolOp/IfExp/NamedExpr/Subscript/List/Dict packing as callee must
            # still execute (``(poison() or len)("x")``, ``[lambda: poison()][0]()``,
            # ``(Mut if True else int)()``).
            _eval_expr(func, env, path=path)
            packed_lambdas = list(_lambdas_packed_as_callee(func))
            if isinstance(func, ast.NamedExpr) and isinstance(func.target, ast.Name):
                bound = lambda_bindings.get(func.target.id)
                if bound is not None and bound not in packed_lambdas:
                    packed_lambdas.append(bound)
            for packed in packed_lambdas:
                synthetic = ast.Call(
                    func=packed,
                    args=list(call.args),
                    keywords=list(call.keywords),
                )
                _follow_local_callee(
                    synthetic,
                    path=path,
                    index=index,
                    env=env,
                    visited_fns=visited_fns,
                    local_fns=local_fns,
                    local_classes=local_classes,
                )
            # Packed class construction: ``(Mut if True else int)()``.
            for name in _packed_names(func):
                cls_node = _lookup_class(name, local_classes)
                if cls_node is not None:
                    _observe_class_construction(
                        cls_node,
                        call,
                        path=path,
                        index=index,
                        env=env,
                        visited_fns=visited_fns,
                        local_fns=local_fns,
                        local_classes=local_classes,
                    )
                # Name-bound factory product packed into Call.func.
                if name in projection_factory_products:
                    if _observe_name_bound_factory_product(name):
                        return
                # Packed Name-bound type protocol: ``[tn][0](...)``.
                tproto = type_protocol_products.get(name)
                if tproto == "__new__":
                    for arg in call.args:
                        _eval_expr(arg, env, path=path)
                    for kw in call.keywords:
                        _eval_expr(kw.value, env, path=path)
                    _observe_type_new_from_args()
                    return
                if tproto == "__call__":
                    observed = False
                    for arg in call.args:
                        if _observe_classes_from_names(_packed_names(arg)):
                            observed = True
                    if not observed:
                        accum.unsupported = True
                    return
            # Packed ``getattr(type, "__new__")`` / ``__call__`` protocol.
            packed_func_names = _packed_names(func)
            if "__new__" in packed_func_names:
                for arg in call.args:
                    _eval_expr(arg, env, path=path)
                for kw in call.keywords:
                    _eval_expr(kw.value, env, path=path)
                _observe_type_new_from_args()
                return
            if "__call__" in packed_func_names:
                observed = False
                for arg in call.args:
                    if _observe_classes_from_names(_packed_names(arg)):
                        observed = True
                for name in packed_func_names:
                    if _observe_classes_from_names([name]):
                        observed = True
                if not observed:
                    accum.unsupported = True
                return
            # ``vars(Holder)["Mut"]()`` / ``globals()["Mut"]()`` key projection.
            if isinstance(func, ast.Subscript):
                key = _static_str(func.slice)
                if key is not None:
                    cls_node = _lookup_class(key, local_classes)
                    if cls_node is not None:
                        _observe_class_construction(
                            cls_node,
                            call,
                            path=path,
                            index=index,
                            env=env,
                            visited_fns=visited_fns,
                            local_fns=local_fns,
                            local_classes=local_classes,
                        )
                    else:
                        base = func.value
                        if (
                            isinstance(base, ast.Call)
                            and isinstance(base.func, ast.Name)
                            and base.func.id in {"vars", "globals", "locals"}
                        ) or (
                            isinstance(base, ast.Attribute) and base.attr == "__dict__"
                        ):
                            # Dynamic namespace class projection — fail closed.
                            accum.unsupported = True
            # Unmodeled callee receiving identity-bearing actuals → escape.
            for arg in call.args:
                points = _eval_expr(arg, env, path=path)
                if any(
                    isinstance(a, (ModuleObject, CallableObject, ModuleNamespace))
                    for a in points.known
                ):
                    _escape_identity(points)
            for kw in call.keywords:
                points = _eval_expr(kw.value, env, path=path)
                if any(
                    isinstance(a, (ModuleObject, CallableObject, ModuleNamespace))
                    for a in points.known
                ):
                    _escape_identity(points)
            return
        # ``f = n.install; f(evil)`` / ``for f in [n.install]: f(evil)`` —
        # Name-bound Attribute callees via shared candidate peel.
        if _follow_accounted_candidates(func):
            return
        # Name-bound factory product: ``p = partial(Mut); p()`` /
        # ``mc = methodcaller("poison"); mc(obj)``.
        if _observe_name_bound_factory_product(func.id):
            return
        # Name-bound type protocol: ``tn = type.__new__; tn(...)`` /
        # ``tc = getattr(type, "__call__); tc(Mut)``.
        tproto = type_protocol_products.get(func.id)
        if tproto == "__new__":
            for arg in call.args:
                _eval_expr(arg, env, path=path)
            for kw in call.keywords:
                _eval_expr(kw.value, env, path=path)
            _observe_type_new_from_args()
            return
        if tproto == "__call__":
            observed = False
            for arg in call.args:
                if _observe_classes_from_names(_packed_names(arg)):
                    observed = True
            if not observed:
                accum.unsupported = True
            return
        # Intermediate class projection: ``m = gi({"Mut": Mut}, "Mut"); m()``.
        if func.id in class_projection_products:
            if _observe_classes_from_names(class_projection_products[func.id]):
                return
            accum.unsupported = True
            return
        # Bound dict view applied then called: ``g = {}.get; g("missing", Mut)()``
        # is handled when Call.func is itself that Call (below). Bare ``g(...)``
        # peels defaults into class_projection_products via assign.
        proj_name = operator_projection_aliases.get(func.id, func.id)
        if (
            func.id in _BENIGN_BUILTINS
            or func.id == _TYPE_BUILTIN_NAME
            or func.id in type_aliases
            or proj_name
            in _KEY_APPLICATOR_NAMES
            | {"starmap", "list.sort", "sort"}
            | _ITERTOOLS_ADAPTER_NAMES
            or dict_view_products.get(func.id) in {"list.sort", "sort"}
        ):
            # Container / higher-order builtins must still evaluate arguments so
            # ``list(genexp)``, ``map(fn, …)`` cannot hide request-time mutations.
            # ``functools.reduce`` / ``itertools.starmap`` Name peels.
            if proj_name == "reduce" and len(call.args) >= 2:
                elems = _iter_elements(call.args[1]) or []
                _observe_lambda_apply(
                    call.args[0],
                    elems,
                    path=path,
                    index=index,
                    env=env,
                    visited_fns=visited_fns,
                    local_fns=local_fns,
                    local_classes=local_classes,
                    skip_first_formal=True,
                )
                for arg in call.args:
                    _eval_expr(arg, env, path=path)
                return
            if proj_name == "starmap" and len(call.args) >= 2:
                elems = _iter_elements(call.args[1]) or []
                _observe_lambda_apply(
                    call.args[0],
                    elems,
                    path=path,
                    index=index,
                    env=env,
                    visited_fns=visited_fns,
                    local_fns=local_fns,
                    local_classes=local_classes,
                    starmap=True,
                )
                for arg in call.args:
                    _eval_expr(arg, env, path=path)
                return
            if func.id in {"map", "filter"} and call.args:
                first = call.args[0]
                # ``map(exec, [...])`` / packed exec — fail closed.
                for name in _packed_names(first):
                    if (
                        name in _EXEC_EVAL_COMPILE_NAMES
                        or name in exec_eval_compile_aliases
                    ):
                        accum.unsupported = True
                        break
                # ``map(lambda f: f(Mut), [tc])`` / ``filter(lambda f: f(Mut)…)``
                # — shared per-element apply (Unknown > false PASS).
                for arg in call.args[1:]:
                    _eval_expr(arg, env, path=path)
                    elems = _iter_elements(arg) or []
                    if _observe_lambda_apply(
                        first,
                        elems,
                        path=path,
                        index=index,
                        env=env,
                        visited_fns=visited_fns,
                        local_fns=local_fns,
                        local_classes=local_classes,
                    ):
                        pass
                    for name in _packed_names(arg):
                        cls_node = _lookup_class(name, local_classes)
                        if cls_node is not None:
                            _observe_class_construction(
                                cls_node,
                                call,
                                path=path,
                                index=index,
                                env=env,
                                visited_fns=visited_fns,
                                local_fns=local_fns,
                                local_classes=local_classes,
                            )
                if not isinstance(_peel_call_func(first), ast.Lambda):
                    synthetic = ast.Call(
                        func=first,
                        args=list(call.args[1:]),
                        keywords=list(call.keywords),
                    )
                    _follow_local_callee(
                        synthetic,
                        path=path,
                        index=index,
                        env=env,
                        visited_fns=visited_fns,
                        local_fns=local_fns,
                        local_classes=local_classes,
                    )
                return
            # ``any/all/sum(genexp)`` — apply generator element bodies.
            if func.id in {"any", "all", "sum"} and call.args:
                first = call.args[0]
                if isinstance(first, (ast.GeneratorExp, ast.ListComp)):
                    _eval_expr(first, env, path=path)
                    return
            # ``sorted|max|min(..., key=…)`` / import-as ``s([Mut], key=…)``.
            proj_key = operator_projection_aliases.get(func.id, func.id)
            if proj_key in {"sorted", "max", "min"}:
                key_expr: ast.AST | None = None
                for kw in call.keywords:
                    if kw.arg == "key":
                        key_expr = kw.value
                iterable = call.args[0] if call.args else None
                if key_expr is not None and iterable is not None:
                    _eval_expr(iterable, env, path=path)
                    elems = _iter_elements(iterable) or []
                    _observe_lambda_apply(
                        key_expr,
                        elems,
                        path=path,
                        index=index,
                        env=env,
                        visited_fns=visited_fns,
                        local_fns=local_fns,
                        local_classes=local_classes,
                    )
                    for kw in call.keywords:
                        _eval_expr(kw.value, env, path=path)
                    return
            # Name-bound ``g = list.sort; g(xs, key=…)`` /
            # ``g = xs.sort; g(key=…)``.
            sort_kind = dict_view_products.get(func.id) or operator_projection_aliases.get(
                func.id
            )
            if sort_kind in {"list.sort", "sort"}:
                key_expr = None
                for kw in call.keywords:
                    if kw.arg == "key":
                        key_expr = kw.value
                if key_expr is not None:
                    if sort_kind == "list.sort" and call.args:
                        elems = _iter_elements(call.args[0]) or []
                    else:
                        recv_name = bound_view_receivers.get(func.id)
                        expr_recv = bound_view_expr_receivers.get(func.id)
                        recv_ast: ast.AST | None = (
                            ast.Name(id=recv_name, ctx=ast.Load())
                            if recv_name is not None
                            else expr_recv
                        )
                        elems = (
                            _iter_elements(recv_ast) or []
                            if recv_ast is not None
                            else []
                        )
                    _observe_lambda_apply(
                        key_expr,
                        elems,
                        path=path,
                        index=index,
                        env=env,
                        visited_fns=visited_fns,
                        local_fns=local_fns,
                        local_classes=local_classes,
                    )
                    for arg in call.args:
                        _eval_expr(arg, env, path=path)
                    for kw in call.keywords:
                        _eval_expr(kw.value, env, path=path)
                    return
            # ``type(Cls)`` single-arg construction ≡ ``type.__call__(Cls)``.
            if (
                func.id == _TYPE_BUILTIN_NAME or func.id in type_aliases
            ) and len(call.args) == 1:
                if _observe_classes_from_names(_packed_names(call.args[0])):
                    return
                accum.unsupported = True
                return
            # ``type(...)`` construction is handled in ``_scan_call`` via
            # ``_call_targets_type_constructor`` (aliases / keywords / packing).
            for arg in call.args:
                _eval_expr(arg, env, path=path)
            for kw in call.keywords:
                _eval_expr(kw.value, env, path=path)
            return
        # Resolve local function from nested scan map / module final bindings.
        fn_node: ast.FunctionDef | ast.AsyncFunctionDef | None = None
        if local_fns is not None and func.id in local_fns:
            fn_node = local_fns[func.id]
        if fn_node is None:
            binding = bindings_by_path.get(path, {}).get(func.id)
            if (
                binding is not None
                and binding.kind == "function"
                and binding.function_node is not None
            ):
                fn_node = binding.function_node
        # ``from pkg.nested import install; install(evil)`` — follow the
        # imported CallableObject body (shared with Attribute peels).
        if fn_node is None:
            points = env.get(func.id)
            if points is not None and not points.unknown:
                callables = [
                    a for a in points.known if isinstance(a, CallableObject)
                ]
                if len(callables) == 1 and len(points.known) == 1:
                    atom = callables[0]
                    binding = bindings_by_path.get(atom.defining_path, {}).get(
                        atom.export_name
                    )
                    if (
                        binding is not None
                        and binding.kind == "function"
                        and binding.function_node is not None
                    ):
                        _scan_fn_body(
                            binding.function_node,
                            path=atom.defining_path,
                            index=index,
                            env=env,
                            visited_fns=visited_fns,
                            local_fns=None,
                            local_classes=None,
                            formals=_formal_bindings_for_call(
                                call, binding.function_node, env, path=path
                            ),
                        )
                        return
        if fn_node is None:
            # Local class construction: ``Mut()`` / ``Child()`` runs
            # ``__new__`` / ``__init__`` including inherited bodies (#173).
            cls_node = _lookup_class(func.id, local_classes)
            if cls_node is not None:
                _observe_class_construction(
                    cls_node,
                    call,
                    path=path,
                    index=index,
                    env=env,
                    visited_fns=visited_fns,
                    local_fns=local_fns,
                    local_classes=local_classes,
                )
                return
            # Unresolved / imported callee: still evaluate *all* actuals so
            # keyword / **kwargs side effects cannot hide identity mutations
            # (``TypeVar('T', bound=poison())``, ``OrderedDict(a=poison())``).
            for arg in call.args:
                arg_points = _eval_expr(arg, env, path=path)
                for atom in arg_points.known:
                    if isinstance(atom, ModuleObject):
                        _note_export(atom.path, "*")
                    elif isinstance(atom, ModuleNamespace):
                        _note_export(atom.module_path, "*")
                    elif isinstance(atom, CallableObject):
                        accum.behavior_mutations.add(
                            (atom.defining_path, atom.export_name)
                        )
            for kw in call.keywords:
                kw_points = _eval_expr(kw.value, env, path=path)
                for atom in kw_points.known:
                    if isinstance(atom, ModuleObject):
                        _note_export(atom.path, "*")
                    elif isinstance(atom, ModuleNamespace):
                        _note_export(atom.module_path, "*")
                    elif isinstance(atom, CallableObject):
                        accum.behavior_mutations.add(
                            (atom.defining_path, atom.export_name)
                        )
            return
        _scan_fn_body(
            fn_node,
            path=path,
            index=index,
            env=env,
            visited_fns=visited_fns,
            local_fns=local_fns,
            local_classes=local_classes,
            formals=_formal_bindings_for_call(call, fn_node, env, path=path),
        )

    def _scan_named_methods_on_class(
        class_node: ast.ClassDef,
        method_names: frozenset[str],
        *,
        path: str,
        index: int,
        env: dict[str, _IdentityPointsTo],
        visited_fns: set[int],
        local_fns: Mapping[str, ast.FunctionDef | ast.AsyncFunctionDef] | None,
        local_classes: Mapping[str, ast.ClassDef] | None,
        walk_bases: bool = False,
    ) -> bool:
        """Scan matching method bodies on ``class_node``. Return True if any ran.

        When ``walk_bases`` is set (class construction), also observe inherited
        ``__init__`` / ``__new__`` on Name bases (``class Child(Mut): …; Child()``).
        """

        observed = False
        for item in class_node.body:
            if (
                isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
                and item.name in method_names
            ):
                _scan_fn_body(
                    item,
                    path=path,
                    index=index,
                    env=env,
                    visited_fns=visited_fns,
                    local_fns=local_fns,
                    local_classes=local_classes,
                )
                observed = True
        if walk_bases:
            for base in class_node.bases:
                if isinstance(base, ast.Name):
                    base_cls = _lookup_class(base.id, local_classes)
                    if base_cls is not None:
                        if _scan_named_methods_on_class(
                            base_cls,
                            method_names,
                            path=path,
                            index=index,
                            env=env,
                            visited_fns=visited_fns,
                            local_fns=local_fns,
                            local_classes=local_classes,
                            walk_bases=True,
                        ):
                            observed = True
                    elif base.id in env:
                        # Dynamic/aliased base construction — fail closed.
                        accum.unsupported = True
                else:
                    accum.unsupported = True
        return observed

    def _observe_class_construction(
        cls_node: ast.ClassDef,
        call: ast.Call,
        *,
        path: str,
        index: int,
        env: dict[str, _IdentityPointsTo],
        visited_fns: set[int],
        local_fns: Mapping[str, ast.FunctionDef | ast.AsyncFunctionDef] | None,
        local_classes: Mapping[str, ast.ClassDef] | None,
    ) -> None:
        """Observe ``__new__`` / ``__init__`` (incl. inherited) for ``Cls()``."""

        for arg in call.args:
            _eval_expr(arg, env, path=path)
        for kw in call.keywords:
            _eval_expr(kw.value, env, path=path)
        _scan_named_methods_on_class(
            cls_node,
            frozenset({"__new__", "__init__"}),
            path=path,
            index=index,
            env=env,
            visited_fns=visited_fns,
            local_fns=local_fns,
            local_classes=local_classes,
            walk_bases=True,
        )

    def _observe_class_creation_protocols(
        stmt: ast.ClassDef,
        *,
        path: str,
        index: int,
        env: dict[str, _IdentityPointsTo],
        visited_fns: set[int],
        local_fns: Mapping[str, ast.FunctionDef | ast.AsyncFunctionDef] | None,
        local_classes: Mapping[str, ast.ClassDef] | None,
    ) -> None:
        """Observe metaclass ``__prepare__``/``__new__`` and base ``__init_subclass__``.

        Prefer compact fail-closed treatment over full class-creation semantics.
        Unknown local metaclasses / dynamic bases poison identity (#173).
        """

        observed_any = False
        for kw in stmt.keywords:
            if kw.arg != "metaclass":
                continue
            if isinstance(kw.value, ast.Name):
                meta = _lookup_class(kw.value.id, local_classes)
                if meta is not None:
                    if _scan_named_methods_on_class(
                        meta,
                        frozenset({"__prepare__", "__new__", "__call__"}),
                        path=path,
                        index=index,
                        env=env,
                        visited_fns=visited_fns,
                        local_fns=local_fns,
                        local_classes=local_classes,
                    ):
                        observed_any = True
                    else:
                        accum.unsupported = True
                else:
                    # Session-local Name that is not a registered class, or
                    # unresolved metaclass — fail closed.
                    points = _eval_expr(kw.value, env, path=path)
                    if points.unknown or points.known:
                        accum.unsupported = True
            else:
                # Dynamic metaclass expression already evaluated; fail closed.
                accum.unsupported = True
        for base in stmt.bases:
            if isinstance(base, ast.Name):
                base_cls = _lookup_class(base.id, local_classes)
                if base_cls is not None:
                    if _scan_named_methods_on_class(
                        base_cls,
                        frozenset({"__init_subclass__"}),
                        path=path,
                        index=index,
                        env=env,
                        visited_fns=visited_fns,
                        local_fns=local_fns,
                        local_classes=local_classes,
                    ):
                        observed_any = True
                elif base.id in env:
                    # Locally bound alias (``Alias = Base`` / unknown) may still
                    # run ``__init_subclass__`` — fail closed. Bare builtins
                    # like ``object`` are not env-bound.
                    accum.unsupported = True
            else:
                # Dynamic base may run ``__init_subclass__`` — fail closed.
                accum.unsupported = True
        del observed_any

    def _scan_call(
        call: ast.Call,
        *,
        path: str,
        index: int,
        env: dict[str, _IdentityPointsTo],
        visited_fns: set[int] | None = None,
        local_fns: Mapping[str, ast.FunctionDef | ast.AsyncFunctionDef] | None = None,
        local_classes: Mapping[str, ast.ClassDef] | None = None,
    ) -> None:
        if visited_fns is None:
            visited_fns = set()
        # ``d.update(e=exec)`` / ``d.setdefault("e", exec)`` / ``xs.append(exec)``
        # grow the Name-bound pack before any later peel (shared mutation seed).
        _note_container_mutation(call)

        def _name_is_exec_eval_compile(name: str) -> bool:
            if name in _EXEC_EVAL_COMPILE_NAMES or name in exec_eval_compile_aliases:
                return True
            binding = bindings_by_path.get(path, {}).get(name)
            if (
                binding is not None
                and binding.kind == "import_name"
                and binding.imported_name in _EXEC_EVAL_COMPILE_NAMES
            ):
                return True
            return any(
                isinstance(atom, CallableObject)
                and atom.export_name in _EXEC_EVAL_COMPILE_NAMES
                for atom in _lookup_name(name, env, path=path).known
            )

        def _name_is_types_new_class(name: str) -> bool:
            if name == _TYPES_NEW_CLASS_NAME or name in new_class_aliases:
                return True
            binding = bindings_by_path.get(path, {}).get(name)
            if (
                binding is not None
                and binding.kind == "import_name"
                and binding.imported_name == _TYPES_NEW_CLASS_NAME
            ):
                return True
            return any(
                isinstance(atom, CallableObject)
                and atom.export_name == _TYPES_NEW_CLASS_NAME
                for atom in _lookup_name(name, env, path=path).known
            )

        def _name_is_type_builtin(name: str) -> bool:
            if name == _TYPE_BUILTIN_NAME or name in type_aliases:
                return True
            binding = bindings_by_path.get(path, {}).get(name)
            return (
                binding is not None
                and binding.kind == "import_name"
                and binding.imported_name == _TYPE_BUILTIN_NAME
            )

        def _call_targets_exec_eval_compile() -> bool:
            func = call.func
            # Shared peel: packing + .get/.pop/getattr/attrgetter/itemgetter/
            # next(iter)/partial/Subscript key tokens / IfExp/BoolOp/walrus.
            for name in _packed_names(func):
                if _name_is_exec_eval_compile(name):
                    return True
            # ``operator.call(exec, ...)`` / Name aliases / packed ``[oc][0]`` /
            # ``next(iter([oc]))`` MUST be checked before bare-Name short-circuit.
            if _is_operator_call_factory(
                call,
                projection_aliases=operator_projection_aliases,
                getattr_aliases=frozenset(getattr_aliases),
                partial_aliases=frozenset(partial_aliases),
                adapter_aliases=frozenset(adapter_aliases),
                container_packs=container_packs,
                factory_products=projection_factory_products,
                dict_view_products=dict_view_products,
            ):
                if call.args:
                    for name in _packed_names(call.args[0]):
                        if _name_is_exec_eval_compile(name):
                            return True
                return True
            # ``methodcaller("__call__", exec, "…")(oc)`` binds exec into __call__.
            bound = _methodcaller_call_bound_args(
                call, projection_aliases=operator_projection_aliases
            )
            if bound is not None:
                for arg in bound:
                    for name in _packed_names(arg):
                        if _name_is_exec_eval_compile(name):
                            return True
            peeled = _peel_call_func(func)
            if isinstance(peeled, ast.Name):
                return _name_is_exec_eval_compile(peeled.id)
            if isinstance(peeled, ast.Attribute) and peeled.attr in _EXEC_EVAL_COMPILE_NAMES:
                return True
            # Fail-closed namespace projections including MappingProxy wrappers:
            # ``vars(builtins)["exec"]``, ``MappingProxyType(vars(builtins))["exec"]``.
            if isinstance(peeled, ast.Subscript):
                key = _static_str(peeled.slice)
                if key in _EXEC_EVAL_COMPILE_NAMES:
                    base = peeled.value
                    if isinstance(base, ast.Attribute) and base.attr == "__dict__":
                        return True
                    if isinstance(base, ast.Call):
                        base_names = _packed_names(base)
                        if any(
                            n in {"vars", "globals", "locals", "MappingProxyType"}
                            or n in adapter_aliases
                            or n in ns_projection_aliases
                            for n in base_names
                        ):
                            return True
                        if isinstance(base.func, ast.Name) and (
                            base.func.id in {"vars", "globals", "locals"}
                            or base.func.id in ns_projection_aliases
                            or base.func.id in _CALLEE_ADAPTER_NAMES
                            or base.func.id in adapter_aliases
                        ):
                            return True
                        if (
                            isinstance(base.func, ast.Attribute)
                            and base.func.attr
                            in {"vars", "globals", "locals", "MappingProxyType"}
                        ):
                            return True
                    return True
            # IfExp/BoolOp Call.func with an operator.call arm.
            if isinstance(peeled, (ast.IfExp, ast.BoolOp)):
                for name in _packed_names(peeled):
                    if name == "call" or operator_projection_aliases.get(name) == "call":
                        return True
            return False

        def _call_targets_types_new_class() -> bool:
            func = call.func
            for name in _packed_names(func):
                if _name_is_types_new_class(name):
                    return True
            if isinstance(func, ast.Name):
                return _name_is_types_new_class(func.id)
            if isinstance(func, ast.Attribute) and func.attr == _TYPES_NEW_CLASS_NAME:
                return True
            if isinstance(func, ast.Call):
                attr = _getattr_static_name(
                    func, getattr_aliases=frozenset(getattr_aliases)
                )
                if attr == _TYPES_NEW_CLASS_NAME:
                    return True
            return False

        def _call_targets_type_constructor() -> bool:
            """``type(...)`` / ``T=type; T(...)`` / ``builtins.type(...)`` / packed."""

            func = call.func
            for name in _packed_names(func):
                if _name_is_type_builtin(name):
                    return True
            # ``operator.call(type, name, bases, dict)`` / packed call aliases.
            if _is_operator_call_factory(
                call,
                projection_aliases=operator_projection_aliases,
                getattr_aliases=frozenset(getattr_aliases),
                partial_aliases=frozenset(partial_aliases),
                adapter_aliases=frozenset(adapter_aliases),
                container_packs=container_packs,
                factory_products=projection_factory_products,
                dict_view_products=dict_view_products,
            ):
                if call.args:
                    for name in _packed_names(call.args[0]):
                        if _name_is_type_builtin(name):
                            return True
            bound = _methodcaller_call_bound_args(
                call, projection_aliases=operator_projection_aliases
            )
            if bound is not None:
                for arg in bound:
                    for name in _packed_names(arg):
                        if _name_is_type_builtin(name):
                            return True
            if isinstance(func, ast.Name):
                return _name_is_type_builtin(func.id)
            if isinstance(func, ast.Attribute) and func.attr == _TYPE_BUILTIN_NAME:
                return True
            if isinstance(func, ast.Call):
                attr = _getattr_static_name(
                    func, getattr_aliases=frozenset(getattr_aliases)
                )
                if attr == _TYPE_BUILTIN_NAME:
                    return True
            return False

        def _observe_type_constructor_call() -> None:
            """Observe ``type(name, bases, dict)`` incl. keyword-only bases."""

            for arg in call.args:
                _eval_expr(arg, env, path=path)
            for kw in call.keywords:
                _eval_expr(kw.value, env, path=path)
            bases_expr: ast.AST | None = None
            if len(call.args) >= 2:
                bases_expr = call.args[1]
            for kw in call.keywords:
                if kw.arg == "bases":
                    bases_expr = kw.value
            if bases_expr is None:
                # Dynamic / incomplete type() form — fail closed.
                if len(call.args) >= 1 or call.keywords:
                    accum.unsupported = True
                return
            base_names = _packed_names(bases_expr)
            if isinstance(bases_expr, (ast.Tuple, ast.List)):
                base_names = []
                for elt in bases_expr.elts:
                    nested = elt.value if isinstance(elt, ast.Starred) else elt
                    base_names.extend(_packed_names(nested))
            observed = False
            for name in base_names:
                base_cls = _lookup_class(name, local_classes)
                if base_cls is not None:
                    if _scan_named_methods_on_class(
                        base_cls,
                        frozenset({"__init_subclass__"}),
                        path=path,
                        index=index,
                        env=env,
                        visited_fns=visited_fns,
                        local_fns=local_fns,
                        local_classes=local_classes,
                    ):
                        observed = True
                elif name in env:
                    accum.unsupported = True
            if not observed and base_names:
                accum.unsupported = True
            if not base_names:
                accum.unsupported = True

        # Request-time exec/eval/compile of string/code can mutate helpers —
        # fail closed (bare Name, builtins.exec, import alias, getattr, packing).
        if _call_targets_exec_eval_compile():
            for arg in call.args:
                _eval_expr(arg, env, path=path)
            for kw in call.keywords:
                _eval_expr(kw.value, env, path=path)
            accum.unsupported = True
            return
        if _call_targets_types_new_class():
            # types.new_class(..., exec_body=body) — observe exec_body or fail closed.
            for arg in call.args:
                _eval_expr(arg, env, path=path)
            exec_body = None
            if len(call.args) >= 4:
                exec_body = call.args[3]
            for kw in call.keywords:
                _eval_expr(kw.value, env, path=path)
                if kw.arg == "exec_body":
                    exec_body = kw.value
            if exec_body is not None:
                synthetic = ast.Call(
                    func=exec_body,
                    args=[ast.Dict(keys=[], values=[])],
                    keywords=[],
                )
                _follow_local_callee(
                    synthetic,
                    path=path,
                    index=index,
                    env=env,
                    visited_fns=visited_fns,
                    local_fns=local_fns,
                    local_classes=local_classes,
                )
            else:
                accum.unsupported = True
            return
        if _call_targets_type_constructor() and (
            len(call.args) >= 2
            or any(kw.arg in {"bases", "dict", "name"} for kw in call.keywords)
        ):
            _observe_type_constructor_call()
            return
        setattr_parts = _setattr_target_and_name(
            call,
            setattr_aliases=frozenset(setattr_aliases),
            getattr_aliases=frozenset(getattr_aliases),
        )
        if setattr_parts is not None:
            obj, name_expr = setattr_parts
            attr = _static_str(name_expr)
            # Name expression may itself execute (``setattr(o, poison(), v)``).
            _eval_expr(name_expr, env, path=path)
            _mutate_through_expr(
                obj,
                export_name=attr,
                behavior=True,
                env=env,
                path=path,
                index=index,
            )
            # Value executes after name resolution; identity mutators in the
            # value must still poison before a later trusted helper write.
            value_expr: ast.AST | None = None
            func_peel = _peel_call_func(call.func)
            _sa = frozenset(setattr_aliases)
            _ga = frozenset(getattr_aliases)
            if (
                isinstance(func_peel, ast.Name) and func_peel.id in setattr_aliases
            ) or _setattr_func_kind(
                func_peel, setattr_aliases=_sa, getattr_aliases=_ga
            ) == "setattr":
                if len(call.args) >= 3:
                    value_expr = call.args[2]
                    _eval_expr(value_expr, env, path=path)
            elif isinstance(func_peel, ast.Attribute) and func_peel.attr == "__setattr__":
                if (
                    isinstance(func_peel.value, ast.Name)
                    and func_peel.value.id == "object"
                ):
                    if len(call.args) >= 3:
                        value_expr = call.args[2]
                        _eval_expr(value_expr, env, path=path)
                elif len(call.args) >= 2:
                    value_expr = call.args[1]
                    _eval_expr(value_expr, env, path=path)
            elif _is_setattr_call(
                call, setattr_aliases=_sa, getattr_aliases=_ga
            ) and len(call.args) >= 3:
                # Packed / BoolOp / import-as setattr — same arg layout.
                value_expr = call.args[2]
                _eval_expr(value_expr, env, path=path)
            # ``setattr(ns, "m", Mut.make)`` grows the NS pack (shared seed).
            if attr is not None and value_expr is not None:
                ns_name = _ns_dict_carrier_name(obj)
                if ns_name is not None:
                    grown = _pack_union(
                        container_packs.get(ns_name),
                        _pack_from_items(
                            [(ast.Constant(value=attr), value_expr)]
                        ),
                    )
                    if grown:
                        container_packs[ns_name] = grown
                    # Preserve Attribute callees for later ``ns.m()`` peels.
                    if isinstance(value_expr, ast.Attribute):
                        bound_callee_exprs[f"{ns_name}.{attr}"] = value_expr
            return
        # Packed / BoolOp / IfExp / slice / next ``partial(setattr|…)`` /
        # ``partial(object.__setattr__, …)`` — parity with packed
        # partial(setitem) (Unknown > false PASS).
        _sa_pack = frozenset(setattr_aliases)
        _ga_pack = frozenset(getattr_aliases)
        for cand in _callee_candidate_exprs(call.func):
            cand = _peel_call_func(cand)
            partial_call: ast.Call | None = None
            if (
                isinstance(cand, ast.Call)
                and _is_partial_factory(
                    cand,
                    partial_aliases=frozenset(partial_aliases),
                    getattr_aliases=_ga_pack,
                )
                and cand.args
            ):
                partial_call = cand
            elif isinstance(cand, ast.Name):
                product = projection_factory_products.get(cand.id)
                if product is not None and product[0] == "partial":
                    bound_expr = None
                    if cand.id in bound_callee_exprs:
                        bound_expr = _peel_call_func(bound_callee_exprs[cand.id])
                    if (
                        isinstance(bound_expr, ast.Call)
                        and _is_partial_factory(
                            bound_expr,
                            partial_aliases=frozenset(partial_aliases),
                            getattr_aliases=_ga_pack,
                        )
                        and bound_expr.args
                    ):
                        partial_call = bound_expr
            if partial_call is None or not partial_call.args:
                continue
            bound0 = _peel_call_func(partial_call.args[0])
            is_sa = False
            is_obj_sa = False
            mc_sa_factory: ast.Call | None = None
            if isinstance(bound0, ast.Name) and bound0.id in _sa_pack:
                is_sa = True
            elif isinstance(bound0, ast.Attribute) and bound0.attr == "setattr":
                is_sa = True
            elif isinstance(bound0, ast.Attribute) and bound0.attr == "__setattr__":
                if (
                    isinstance(_peel_call_func(bound0.value), ast.Name)
                    and _peel_call_func(bound0.value).id == "object"  # type: ignore[union-attr]
                ):
                    is_obj_sa = True
                else:
                    is_sa = True
            elif isinstance(bound0, ast.Call):
                gname = _getattr_static_name(bound0, getattr_aliases=_ga_pack)
                if gname == "setattr":
                    is_sa = True
                elif gname == "__setattr__":
                    is_obj_sa = True
                elif (
                    _methodcaller_static_name(
                        bound0,
                        projection_aliases=operator_projection_aliases,
                        getattr_aliases=_ga_pack,
                    )
                    == "__setattr__"
                    and len(bound0.args) >= 3
                ):
                    # ``partial(methodcaller("__setattr__", "e", exec))(ns)``.
                    mc_sa_factory = bound0
            if mc_sa_factory is not None and call.args:
                obj = call.args[0]
                name_expr = mc_sa_factory.args[1]
                value_expr = mc_sa_factory.args[2]
                attr = _static_str(name_expr)
                _eval_expr(name_expr, env, path=path)
                _mutate_through_expr(
                    obj,
                    export_name=attr,
                    behavior=True,
                    env=env,
                    path=path,
                    index=index,
                )
                _eval_expr(value_expr, env, path=path)
                if attr is not None:
                    ns_name = _ns_dict_carrier_name(obj)
                    if ns_name is not None:
                        grown = _pack_union(
                            container_packs.get(ns_name),
                            _pack_from_items(
                                [(ast.Constant(value=attr), value_expr)]
                            ),
                        )
                        if grown:
                            container_packs[ns_name] = grown
                        if isinstance(value_expr, ast.Attribute):
                            bound_callee_exprs[f"{ns_name}.{attr}"] = value_expr
                return
            if not (is_sa or is_obj_sa) or not call.args:
                continue
            if len(partial_call.args) < 3:
                continue
            obj = partial_call.args[1]
            name_expr = partial_call.args[2]
            value_expr = call.args[0]
            attr = _static_str(name_expr)
            _eval_expr(name_expr, env, path=path)
            _mutate_through_expr(
                obj,
                export_name=attr,
                behavior=True,
                env=env,
                path=path,
                index=index,
            )
            _eval_expr(value_expr, env, path=path)
            if attr is not None:
                ns_name = _ns_dict_carrier_name(obj)
                if ns_name is not None:
                    grown = _pack_union(
                        container_packs.get(ns_name),
                        _pack_from_items(
                            [(ast.Constant(value=attr), value_expr)]
                        ),
                    )
                    if grown:
                        container_packs[ns_name] = grown
                    if isinstance(value_expr, ast.Attribute):
                        bound_callee_exprs[f"{ns_name}.{attr}"] = value_expr
            return
        # ``methodcaller("__setattr__", "m", Mut.make)(ns)`` /
        # ``mc=operator.methodcaller; mc("__setattr__", …)(ns)`` /
        # packed forms — share setattr NS pack growth (Unknown > false PASS).
        mc_setattr_factory: ast.Call | None = None
        func_peel_mc = _peel_transparent_callee(call.func)
        if isinstance(func_peel_mc, ast.Call):
            if (
                _methodcaller_static_name(
                    func_peel_mc,
                    projection_aliases=operator_projection_aliases,
                    getattr_aliases=frozenset(getattr_aliases),
                )
                == "__setattr__"
            ):
                mc_setattr_factory = func_peel_mc
        if mc_setattr_factory is None:
            for cand in _callee_candidate_exprs(call.func):
                cand = _peel_call_func(cand)
                if isinstance(cand, ast.Call) and (
                    _methodcaller_static_name(
                        cand,
                        projection_aliases=operator_projection_aliases,
                        getattr_aliases=frozenset(getattr_aliases),
                    )
                    == "__setattr__"
                ):
                    mc_setattr_factory = cand
                    break
        if (
            mc_setattr_factory is not None
            and call.args
            and len(mc_setattr_factory.args) >= 3
        ):
            obj = call.args[0]
            name_expr = mc_setattr_factory.args[1]
            value_expr = mc_setattr_factory.args[2]
            attr = _static_str(name_expr)
            _eval_expr(name_expr, env, path=path)
            _mutate_through_expr(
                obj,
                export_name=attr,
                behavior=True,
                env=env,
                path=path,
                index=index,
            )
            _eval_expr(value_expr, env, path=path)
            if attr is not None:
                ns_name = _ns_dict_carrier_name(obj)
                if ns_name is not None:
                    grown = _pack_union(
                        container_packs.get(ns_name),
                        _pack_from_items(
                            [(ast.Constant(value=attr), value_expr)]
                        ),
                    )
                    if grown:
                        container_packs[ns_name] = grown
                    if isinstance(value_expr, ast.Attribute):
                        bound_callee_exprs[f"{ns_name}.{attr}"] = value_expr
            return
        delattr_parts = _delattr_target_and_name(call)
        if delattr_parts is not None:
            obj, name_expr = delattr_parts
            attr = _static_str(name_expr)
            _eval_expr(name_expr, env, path=path)
            _mutate_through_expr(
                obj,
                export_name=attr,
                behavior=True,
                env=env,
                path=path,
                index=index,
            )
            return
        # operator.attrsetter("write_state")(helpers, evil)
        if (
            isinstance(call.func, ast.Call)
            and len(call.args) >= 2
        ):
            setter_attr = _attrsetter_static_name(call.func)
            if setter_attr is not None:
                _mutate_through_expr(
                    call.args[0],
                    export_name=setter_attr,
                    behavior=True,
                    env=env,
                    path=path,
                    index=index,
                )
                # Remaining actuals still execute.
                for arg in call.args[1:]:
                    _eval_expr(arg, env, path=path)
                for kw in call.keywords:
                    _eval_expr(kw.value, env, path=path)
                return

        func = call.func
        if (
            isinstance(func, ast.Attribute)
            and func.attr
            in {"update", "setdefault", "pop", "clear", "__setitem__"}
        ):
            base_points = _eval_expr(func.value, env, path=path)
            # module namespace dict methods → export poison
            for atom in base_points.known:
                if isinstance(atom, ModuleNamespace):
                    _note_export(atom.module_path, "*")
                elif isinstance(atom, ModuleObject):
                    _note_export(atom.path, "*")
                elif isinstance(atom, CallableObject):
                    _note_behavior(
                        (atom.defining_path, atom.export_name),
                        mutation_path=path,
                        mutation_index=index,
                    )
            # callable.__globals__.update(...)
            if isinstance(func.value, ast.Attribute):
                owner = _eval_expr(func.value.value, env, path=path)
                _poison_atoms(
                    owner,
                    export_name=None,
                    behavior=True,
                    mutation_path=path,
                    mutation_index=index,
                )
            # Method actuals still execute (``d.update(a=poison())``).
            for arg in call.args:
                _eval_expr(arg, env, path=path)
            for kw in call.keywords:
                _eval_expr(kw.value, env, path=path)
            return

        _follow_local_callee(
            call,
            path=path,
            index=index,
            env=env,
            visited_fns=visited_fns,
            local_fns=local_fns,
            local_classes=local_classes,
        )

    def _scan_stmts(
        stmts: Sequence[ast.stmt],
        *,
        path: str,
        index: int,
        env: dict[str, _IdentityPointsTo],
        visited_fns: set[int],
        local_fns: Mapping[str, ast.FunctionDef | ast.AsyncFunctionDef] | None = None,
        local_classes: Mapping[str, ast.ClassDef] | None = None,
        declared_globals: set[str] | None = None,
    ) -> None:
        # Mutable nested-def / class maps for this statement sequence.
        active_fns: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = dict(
            local_fns or {}
        )
        active_classes: dict[str, ast.ClassDef] = dict(local_classes or {})
        active_globals: set[str] = set(declared_globals or ())
        for stmt in stmts:
            _scan_ctx["index"] = index
            _scan_ctx["visited_fns"] = visited_fns
            _scan_ctx["local_fns"] = active_fns
            _scan_ctx["local_classes"] = active_classes
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                active_fns[stmt.name] = stmt
                # Defaults evaluate at definition time — container packing escapes.
                for default in stmt.args.defaults:
                    _eval_expr(default, env, path=path)
                for default in stmt.args.kw_defaults:
                    if default is not None:
                        _eval_expr(default, env, path=path)
                # PEP 695 type parameter bounds/defaults execute at definition.
                _eval_type_params(getattr(stmt, "type_params", ()) or (), env, path=path)
                # Parameter / return annotations evaluate at definition unless
                # postponed; omitting them false-PASSes identity (#173).
                for arg in (
                    *stmt.args.posonlyargs,
                    *stmt.args.args,
                    *stmt.args.kwonlyargs,
                ):
                    if arg.annotation is not None:
                        _eval_expr(arg.annotation, env, path=path)
                if stmt.args.vararg is not None and stmt.args.vararg.annotation is not None:
                    _eval_expr(stmt.args.vararg.annotation, env, path=path)
                if stmt.args.kwarg is not None and stmt.args.kwarg.annotation is not None:
                    _eval_expr(stmt.args.kwarg.annotation, env, path=path)
                if stmt.returns is not None:
                    _eval_expr(stmt.returns, env, path=path)
                # Decorators execute at definition: @deco / @deco(...) may mutate.
                for deco in stmt.decorator_list:
                    if isinstance(deco, ast.Call):
                        _scan_call(
                            deco,
                            path=path,
                            index=index,
                            env=env,
                            visited_fns=visited_fns,
                            local_fns=active_fns,
                            local_classes=active_classes,
                        )
                    else:
                        synthetic = ast.Call(
                            func=deco,
                            args=[ast.Name(id=stmt.name, ctx=ast.Load())],
                            keywords=[],
                        )
                        _scan_call(
                            synthetic,
                            path=path,
                            index=index,
                            env=env,
                            visited_fns=visited_fns,
                            local_fns=active_fns,
                            local_classes=active_classes,
                        )
                _apply_import_identities(stmt, env, path=path)
                continue
            if isinstance(stmt, ast.ClassDef):
                active_classes[stmt.name] = stmt
                class_registry[stmt.name] = stmt
                for deco in stmt.decorator_list:
                    # Decorator application executes at class definition
                    # (``@poison`` / ``@poison()``). Name-only form must be
                    # followed as a call, matching FunctionDef (#173).
                    if isinstance(deco, ast.Call):
                        _scan_call(
                            deco,
                            path=path,
                            index=index,
                            env=env,
                            visited_fns=visited_fns,
                            local_fns=active_fns,
                            local_classes=active_classes,
                        )
                    else:
                        synthetic = ast.Call(
                            func=deco,
                            args=[ast.Name(id=stmt.name, ctx=ast.Load())],
                            keywords=[],
                        )
                        _scan_call(
                            synthetic,
                            path=path,
                            index=index,
                            env=env,
                            visited_fns=visited_fns,
                            local_fns=active_fns,
                            local_classes=active_classes,
                        )
                # Bases and keywords execute at definition (``class C(poison())``,
                # ``metaclass=poison()``, starred bases). Unknown > false PASS.
                _eval_type_params(getattr(stmt, "type_params", ()) or (), env, path=path)
                for base in stmt.bases:
                    _eval_expr(base, env, path=path)
                for kw in stmt.keywords:
                    _eval_expr(kw.value, env, path=path)
                # Local metaclass / base __init_subclass__: observe protocol
                # bodies or fail closed (no full metaclass simulation) (#173).
                _observe_class_creation_protocols(
                    stmt,
                    path=path,
                    index=index,
                    env=env,
                    visited_fns=visited_fns,
                    local_fns=active_fns,
                    local_classes=active_classes,
                )
                # Class body executes at definition time.
                class_env = _copy_env(env)
                _scan_stmts(
                    stmt.body,
                    path=path,
                    index=index,
                    env=class_env,
                    visited_fns=visited_fns,
                    local_fns=active_fns,
                    local_classes=active_classes,
                    declared_globals=active_globals,
                )
                # Descriptor ``__set_name__`` runs after class body for each
                # attribute assignment (``x = Desc()`` / deferred ``x = d``)
                # — observe or fail closed.
                for item in stmt.body:
                    if not isinstance(item, (ast.Assign, ast.AnnAssign)):
                        continue
                    value = item.value if isinstance(item, ast.AnnAssign) else item.value
                    if value is None:
                        continue
                    # ``Desc()`` construction / ``d = Desc(); x = d`` may define
                    # ``__set_name__``. Packed Names resolve via instance_class_of.
                    desc_cls: ast.ClassDef | None = None
                    for name in _packed_names(value):
                        desc_cls = _lookup_class(name, active_classes)
                        if desc_cls is None and name in instance_class_of:
                            desc_cls = _lookup_class(
                                instance_class_of[name], active_classes
                            )
                        if desc_cls is not None:
                            break
                    if isinstance(value, ast.Call) and isinstance(value.func, ast.Name):
                        desc_cls = desc_cls or _lookup_class(
                            value.func.id, active_classes
                        )
                    if desc_cls is None:
                        # Unknown descriptor value in class body — fail closed.
                        if isinstance(value, (ast.Name, ast.Call, ast.Attribute)):
                            accum.unsupported = True
                        continue
                    if not _scan_named_methods_on_class(
                        desc_cls,
                        frozenset({"__set_name__"}),
                        path=path,
                        index=index,
                        env=env,
                        visited_fns=visited_fns,
                        local_fns=active_fns,
                        local_classes=active_classes,
                    ):
                        # Descriptor instance without modeled ``__set_name__``
                        # is a no-op; keep precise when absent.
                        pass
                _apply_import_identities(stmt, env, path=path)
                continue
            if isinstance(stmt, (ast.Import, ast.ImportFrom)):
                _apply_import_identities(stmt, env, path=path)
                continue
            if isinstance(stmt, ast.Global):
                active_globals.update(stmt.names)
                continue
            if isinstance(stmt, ast.Assign):
                value_points = _eval_expr(stmt.value, env, path=path)
                # Chained targets share the same RHS identity (#165).
                for target in stmt.targets:
                    _scan_assign_target(
                        target,
                        path=path,
                        index=index,
                        env=env,
                        value_points=value_points,
                    )
                    # ``global write_state; write_state = fn`` — accounted export
                    # rebind on the defining module path (Unknown > false PASS).
                    if (
                        isinstance(target, ast.Name)
                        and target.id in active_globals
                    ):
                        _note_export(path, target.id)
                    # Name-bound lambdas / bound methods followed on later calls.
                    if isinstance(target, ast.Name):
                        _note_protocol_alias_from_value(target.id, stmt.value)
                        # ``C = next(iter({Mut:1}))`` / ``C = next(iter(k()))``
                        # seed class/protocol from yielded elements.
                        _seed_assign_unpack_aliases(
                            target, stmt.value, active_classes=active_classes
                        )
                        if isinstance(stmt.value, ast.Lambda):
                            lambda_bindings[target.id] = stmt.value
                            method_bindings.pop(target.id, None)
                            instance_class_of.pop(target.id, None)
                        elif isinstance(stmt.value, ast.Attribute):
                            lambda_bindings.pop(target.id, None)
                            instance_class_of.pop(target.id, None)
                            # ``m = Mut.make.__call__`` / ``m = Mut.make.__func__``.
                            method_attr = stmt.value
                            if method_attr.attr in {"__call__", "__func__"}:
                                peeled = _peel_transparent_callee(method_attr)
                                if method_attr.attr == "__func__":
                                    peeled = _peel_call_func(method_attr.value)
                                if isinstance(peeled, ast.Attribute):
                                    method_attr = peeled
                            method = _resolve_attribute_method(
                                method_attr, local_classes=active_classes
                            )
                            if method is not None:
                                method_bindings[target.id] = method
                            else:
                                method_bindings.pop(target.id, None)
                        elif isinstance(stmt.value, ast.Call):
                            lambda_bindings.pop(target.id, None)
                            # ``m = Mut()`` / ``m = Mut.__new__(Mut)`` instance alias.
                            inst_cls: str | None = None
                            fpeeled = _peel_call_func(stmt.value.func)
                            if isinstance(fpeeled, ast.Name) and _lookup_class(
                                fpeeled.id, active_classes
                            ) is not None:
                                inst_cls = fpeeled.id
                            elif (
                                isinstance(fpeeled, ast.Attribute)
                                and fpeeled.attr == "__new__"
                            ):
                                recv = _peel_call_func(fpeeled.value)
                                if isinstance(recv, ast.Name) and _lookup_class(
                                    recv.id, active_classes
                                ) is not None:
                                    inst_cls = recv.id
                                elif stmt.value.args:
                                    for pname in _packed_names(stmt.value.args[0]):
                                        if (
                                            _lookup_class(pname, active_classes)
                                            is not None
                                        ):
                                            inst_cls = pname
                                            break
                            if inst_cls is not None:
                                method_bindings.pop(target.id, None)
                                instance_class_of[target.id] = inst_cls
                            else:
                                instance_class_of.pop(target.id, None)
                                # ``c = getattr(Mut, "make")`` /
                                # ``c = object.__getattribute__(Mut, "make")``.
                                gname = _getattr_static_name(
                                    stmt.value,
                                    getattr_aliases=frozenset(getattr_aliases),
                                )
                                recv: ast.AST | None = (
                                    stmt.value.args[0] if stmt.value.args else None
                                )
                                if gname is None and stmt.value.args:
                                    fpeeled = _peel_call_func(stmt.value.func)
                                    if (
                                        isinstance(fpeeled, ast.Attribute)
                                        and fpeeled.attr == "__getattribute__"
                                        and len(stmt.value.args) >= 2
                                    ):
                                        gname = _static_str(stmt.value.args[1])
                                        recv = stmt.value.args[0]
                                if gname is not None and recv is not None:
                                    method_attr = ast.Attribute(
                                        value=recv, attr=gname, ctx=ast.Load()
                                    )
                                    method = _resolve_attribute_method(
                                        method_attr, local_classes=active_classes
                                    )
                                    if method is not None:
                                        method_bindings[target.id] = method
                                        bound_callee_exprs[target.id] = method_attr
                                    else:
                                        method_bindings.pop(target.id, None)
                                else:
                                    method_bindings.pop(target.id, None)
                        elif isinstance(stmt.value, ast.Name):
                            # ``Alias = Base`` so ``class C(Alias)`` observes
                            # ``Base.__init_subclass__`` (Unknown > false PASS).
                            # Double instance alias: ``b = Box(); c = b``.
                            lambda_bindings.pop(target.id, None)
                            method_bindings.pop(target.id, None)
                            if stmt.value.id in instance_class_of:
                                instance_class_of[target.id] = instance_class_of[
                                    stmt.value.id
                                ]
                            else:
                                instance_class_of.pop(target.id, None)
                            src_cls = _lookup_class(stmt.value.id, active_classes)
                            if src_cls is not None:
                                active_classes[target.id] = src_cls
                                class_registry[target.id] = src_cls
                        else:
                            lambda_bindings.pop(target.id, None)
                            method_bindings.pop(target.id, None)
                            instance_class_of.pop(target.id, None)
                            # Packed class/protocol peels: ``C = [Cls][0]``.
                            for cname in _packed_names(stmt.value):
                                src_cls = _lookup_class(cname, active_classes)
                                if src_cls is not None:
                                    active_classes[target.id] = src_cls
                                    class_registry[target.id] = src_cls
                                    break
                    elif isinstance(target, (ast.Tuple, ast.List)):
                        # ``C, = [Cls]`` / ``[C] = {Cls: 1}.keys()`` / ``*xs, = [Mut]``.
                        _seed_assign_unpack_aliases(
                            target, stmt.value, active_classes=active_classes
                        )
                    elif isinstance(target, ast.Subscript):
                        # ``d["e"] = exec`` / ``cm.maps[0]["e"] = exec`` /
                        # ``vars(ns)["e"] = exec`` / ``ns.__dict__["e"] = exec``.
                        base = _peel_call_func(target.value)
                        base_name = _chainmap_carrier_name(base)
                        if base_name is None:
                            base_name = _ns_dict_carrier_name(base)
                        if base_name is not None:
                            grown = _pack_union(
                                container_packs.get(base_name),
                                _pack_from_items([(target.slice, stmt.value)]),
                            )
                            if grown:
                                container_packs[base_name] = grown
                                # Preserve Attribute / Name values for later peels.
                                items = _mapping_items(
                                    ast.Name(id=base_name, ctx=ast.Load())
                                ) or []
                                items = list(items) + [(target.slice, stmt.value)]
                                sequence_view_aliases[base_name] = ast.Dict(
                                    keys=[k for k, _ in items],
                                    values=[
                                        v if v is not None else ast.Constant(value=None)
                                        for _, v in items
                                    ],
                                )
                    elif isinstance(target, ast.Attribute):
                        # ``ns.e = exec`` / SimpleNamespace attr assign grows pack.
                        recv = _peel_call_func(target.value)
                        if isinstance(recv, ast.Name):
                            grown = _pack_union(
                                container_packs.get(recv.id),
                                _pack_from_items(
                                    [(ast.Constant(value=target.attr), stmt.value)]
                                ),
                            )
                            if grown:
                                container_packs[recv.id] = grown
                            if isinstance(stmt.value, ast.Attribute):
                                bound_callee_exprs[stmt.value.attr] = stmt.value
                                bound_callee_exprs[
                                    f"{recv.id}.{target.attr}"
                                ] = stmt.value
                            # Keep attr→value for Name-bound NS peels.
                            prev = sequence_view_aliases.get(recv.id)
                            prev_items = _mapping_items(prev) if prev else None
                            items = list(prev_items or [])
                            items.append(
                                (ast.Constant(value=target.attr), stmt.value)
                            )
                            sequence_view_aliases[recv.id] = ast.Dict(
                                keys=[k for k, _ in items],
                                values=[
                                    v if v is not None else ast.Constant(value=None)
                                    for _, v in items
                                ],
                            )
                # Walrus bindings inside RHS are applied by _eval_expr (#173).
                continue
            if isinstance(stmt, ast.AnnAssign):
                _eval_expr(stmt.annotation, env, path=path)
                value_points = (
                    _eval_expr(stmt.value, env, path=path)
                    if stmt.value is not None
                    else _IdentityPointsTo.unknown_only()
                )
                _scan_assign_target(
                    stmt.target,
                    path=path,
                    index=index,
                    env=env,
                    value_points=value_points,
                )
                if isinstance(stmt.target, ast.Name) and stmt.value is not None:
                    _note_protocol_alias_from_value(stmt.target.id, stmt.value)
                    if isinstance(stmt.value, ast.Lambda):
                        lambda_bindings[stmt.target.id] = stmt.value
                    else:
                        lambda_bindings.pop(stmt.target.id, None)
                    # Class / instance alias through AnnAssign (parity with Assign).
                    if isinstance(stmt.value, ast.Name):
                        if stmt.value.id in instance_class_of:
                            instance_class_of[stmt.target.id] = instance_class_of[
                                stmt.value.id
                            ]
                        src_cls = _lookup_class(stmt.value.id, active_classes)
                        if src_cls is not None:
                            active_classes[stmt.target.id] = src_cls
                            class_registry[stmt.target.id] = src_cls
                    elif (
                        isinstance(stmt.value, ast.Call)
                        and isinstance(stmt.value.func, ast.Name)
                        and _lookup_class(stmt.value.func.id, active_classes)
                        is not None
                    ):
                        instance_class_of[stmt.target.id] = stmt.value.func.id
                elif (
                    isinstance(stmt.target, ast.Attribute)
                    and stmt.value is not None
                ):
                    # ``ns.e: object = exec`` — AnnAssign attr grows NS pack.
                    recv = _peel_call_func(stmt.target.value)
                    if isinstance(recv, ast.Name):
                        grown = _pack_union(
                            container_packs.get(recv.id),
                            _pack_from_items(
                                [
                                    (
                                        ast.Constant(value=stmt.target.attr),
                                        stmt.value,
                                    )
                                ]
                            ),
                        )
                        if grown:
                            container_packs[recv.id] = grown
                        prev = sequence_view_aliases.get(recv.id)
                        prev_items = _mapping_items(prev) if prev else None
                        items = list(prev_items or [])
                        items.append(
                            (
                                ast.Constant(value=stmt.target.attr),
                                stmt.value,
                            )
                        )
                        sequence_view_aliases[recv.id] = ast.Dict(
                            keys=[k for k, _ in items],
                            values=[
                                v if v is not None else ast.Constant(value=None)
                                for _, v in items
                            ],
                        )
                elif (
                    isinstance(stmt.target, ast.Subscript)
                    and stmt.value is not None
                ):
                    base = _peel_call_func(stmt.target.value)
                    base_name = _chainmap_carrier_name(base)
                    if base_name is None:
                        base_name = _ns_dict_carrier_name(base)
                    if base_name is not None:
                        grown = _pack_union(
                            container_packs.get(base_name),
                            _pack_from_items([(stmt.target.slice, stmt.value)]),
                        )
                        if grown:
                            container_packs[base_name] = grown
                continue
            if isinstance(stmt, ast.AugAssign):
                # RHS executes (``x += poison()``) before the store.
                _eval_expr(stmt.value, env, path=path)
                if isinstance(stmt.target, ast.Name):
                    # ``d |= {"e": exec}`` merges mapping packs (shared peel).
                    # Do NOT reseed from RHS alone — that drops left key packs
                    # (``d = {Mut: 1}; d |= {}; C, = d.keys()``).
                    if isinstance(stmt.op, (ast.BitOr, ast.Add)):
                        # ``d |= {…}`` / ``xs += [exec]`` merge packs (do not
                        # sever left key packs — Unknown > false PASS).
                        left = _container_pack_from_expr(
                            ast.Name(id=stmt.target.id, ctx=ast.Load())
                        ) or container_packs.get(stmt.target.id) or {}
                        right = _container_pack_from_expr(stmt.value) or {}
                        merged = _pack_union(left, right)
                        if merged:
                            container_packs[stmt.target.id] = merged
                        # ``d=vars(ns); d|={"m": Mut.make}`` must also grow the
                        # owning namespace pack (shared with operator.ior(vars)).
                        root = ns_dict_alias_roots.get(stmt.target.id)
                        if root is not None and root != stmt.target.id:
                            _merge_inplace_pack(
                                ast.Name(id=root, ctx=ast.Load()),
                                stmt.value,
                            )
                        # Preserve sequence/view aliases on the left name.
                        # Merge class/protocol products from RHS without clearing
                        # left-only key packs already stored above.
                        saved_pack = container_packs.get(stmt.target.id)
                        saved_seq = sequence_view_aliases.get(stmt.target.id)
                        _note_protocol_alias_from_value(
                            stmt.target.id, stmt.value
                        )
                        if saved_pack:
                            container_packs[stmt.target.id] = _pack_union(
                                saved_pack, container_packs.get(stmt.target.id)
                            )
                        # Merge Attribute-preserving RHS mapping into seq alias
                        # (``d=dict(); d|={'e': n.install}; d['e'](evil)``).
                        # Also merge List carriers for ``xs += [partial(...)]`` /
                        # ``views += [n.install]`` (Unknown > false PASS).
                        rhs_items = _mapping_items(stmt.value)
                        left_items = (
                            list(_mapping_items(saved_seq) or [])
                            if saved_seq is not None
                            else []
                        )
                        rhs_elts = _iter_elements(stmt.value)
                        left_elts: list[ast.AST] | None = None
                        if isinstance(saved_seq, (ast.List, ast.Tuple)):
                            left_elts = list(saved_seq.elts)
                        elif saved_seq is not None and rhs_items is None:
                            left_elts = list(_iter_elements(saved_seq) or []) or None
                        if (
                            isinstance(stmt.op, ast.Add)
                            and (rhs_elts is not None or left_elts is not None)
                            and rhs_items is None
                        ):
                            merged_elts = [
                                *(left_elts or []),
                                *(rhs_elts or []),
                            ]
                            sequence_view_aliases[stmt.target.id] = ast.List(
                                elts=merged_elts, ctx=ast.Load()
                            )
                            for index, elt in enumerate(merged_elts):
                                grown = container_packs.get(stmt.target.id, {})
                                _pack_add(
                                    grown, index, _packed_names_deep(elt)
                                )
                                if grown:
                                    container_packs[stmt.target.id] = grown
                        elif rhs_items is not None or left_items:
                            by_key: dict[object, ast.AST] = {}
                            for k, v in left_items:
                                if isinstance(k, ast.Constant) and v is not None:
                                    by_key[k.value] = v
                            for k, v in rhs_items or []:
                                if isinstance(k, ast.Constant) and v is not None:
                                    by_key[k.value] = v
                            if by_key:
                                sequence_view_aliases[stmt.target.id] = ast.Dict(
                                    keys=[ast.Constant(value=k) for k in by_key],
                                    values=list(by_key.values()),
                                )
                            elif saved_seq is not None:
                                sequence_view_aliases[stmt.target.id] = saved_seq
                            else:
                                sequence_view_aliases.pop(stmt.target.id, None)
                        elif saved_seq is not None:
                            sequence_view_aliases[stmt.target.id] = saved_seq
                        else:
                            # RHS ``{}`` must not install an empty sequence alias
                            # that shadows left key packs
                            # (``e=copy.copy(d); e|={}; e.keys()``).
                            sequence_view_aliases.pop(stmt.target.id, None)
                    else:
                        # Name += rebinds / replaces the local; treat as severed
                        # bottom so a later attr write does not spelling-poison.
                        env[stmt.target.id] = _IdentityPointsTo.bottom()
                        container_packs.pop(stmt.target.id, None)
                        sequence_view_aliases.pop(stmt.target.id, None)
                elif isinstance(stmt.op, (ast.BitOr, ast.Add)) and isinstance(
                    stmt.target, (ast.Attribute, ast.Subscript)
                ):
                    # ``cm.maps += [{…}]`` / ``cm.maps[0] |= {…}``.
                    _merge_inplace_pack(stmt.target, stmt.value)
                else:
                    _scan_assign_target(
                        stmt.target,
                        path=path,
                        index=index,
                        env=env,
                        value_points=_IdentityPointsTo.unknown_only(),
                    )
                continue
            if isinstance(stmt, ast.Delete):
                for target in stmt.targets:
                    if isinstance(target, ast.Name):
                        env[target.id] = _IdentityPointsTo.unknown_only()
                    else:
                        # Subscript/attribute deletes still execute index/name
                        # expressions (``del d[poison()]``).
                        if isinstance(target, ast.Subscript):
                            _eval_expr(target.slice, env, path=path)
                        _scan_assign_target(
                            target,
                            path=path,
                            index=index,
                            env=env,
                            value_points=None,
                        )
                continue
            # ast.TypeAlias is 3.12+; gate so 3.10 import-time walk stays valid.
            type_alias_cls = getattr(ast, "TypeAlias", None)
            if type_alias_cls is not None and isinstance(stmt, type_alias_cls):
                # ``type X = poison()`` / ``type X[T: poison()] = ...`` execute
                # type_params and the value at definition (#173).
                _eval_type_params(getattr(stmt, "type_params", ()) or (), env, path=path)
                _eval_expr(stmt.value, env, path=path)
                if isinstance(stmt.name, ast.Name):
                    env[stmt.name.id] = _IdentityPointsTo.unknown_only()
                continue
            if isinstance(stmt, ast.Expr):
                # Any executed expression position — not only bare Call (#173).
                _eval_expr(stmt.value, env, path=path)
                continue
            if isinstance(stmt, ast.Assert):
                # Assert.test executes; msg may execute on failure (conservative).
                _eval_expr(stmt.test, env, path=path)
                if stmt.msg is not None:
                    _eval_expr(stmt.msg, env, path=path)
                continue
            if isinstance(stmt, ast.If):
                # Test executes before branch selection (#173).
                _eval_expr(stmt.test, env, path=path)
                env_body = _copy_env(env)
                _scan_stmts(
                    stmt.body,
                    path=path,
                    index=index,
                    env=env_body,
                    visited_fns=visited_fns,
                    local_fns=active_fns,
                    local_classes=active_classes,
                    declared_globals=active_globals,
                )
                env_else = _copy_env(env)
                _scan_stmts(
                    stmt.orelse,
                    path=path,
                    index=index,
                    env=env_else,
                    visited_fns=visited_fns,
                    local_fns=active_fns,
                    local_classes=active_classes,
                    declared_globals=active_globals,
                )
                joined = _join_envs(env_body, env_else)
                env.clear()
                env.update(joined)
                continue
            if isinstance(stmt, (ast.For, ast.AsyncFor)):
                # Evaluate iter for container escape / call effects; loop target
                # is unmodeled for Name binds, but Attribute/subscript targets
                # mutate exports (``for helpers.write_state in [evil]``) (#173).
                # Iterable always executes before zero-iteration join. For-else
                # walks from the pre-loop env (like while/else) so body-mutated
                # aliases cannot drop else effects.
                _eval_expr(stmt.iter, env, path=path)
                # Class/protocol seeds from iter peels (list/dict views/map/
                # comps/Name packs) so ``for C in …: C()`` observes construction.
                _seed_for_iter_class_aliases(
                    stmt.target, stmt.iter, active_classes=active_classes
                )
                env_pre = _copy_env(env)
                _scan_assign_target(
                    stmt.target,
                    path=path,
                    index=index,
                    env=env,
                    value_points=_IdentityPointsTo.unknown_only(),
                )
                env_body = _copy_env(env)
                _scan_stmts(
                    stmt.body,
                    path=path,
                    index=index,
                    env=env_body,
                    visited_fns=visited_fns,
                    local_fns=active_fns,
                    local_classes=active_classes,
                    declared_globals=active_globals,
                )
                env_else = _copy_env(env_pre)
                _scan_stmts(
                    stmt.orelse,
                    path=path,
                    index=index,
                    env=env_else,
                    visited_fns=visited_fns,
                    local_fns=active_fns,
                    local_classes=active_classes,
                    declared_globals=active_globals,
                )
                joined = _join_envs(env_pre, _join_envs(env_body, env_else))
                env.clear()
                env.update(joined)
                continue
            if isinstance(stmt, ast.While):
                # Test executes (at least once) before body / zero-iteration
                # join; nested short-circuit may-effects are conservative via
                # _eval_expr BoolOp / IfExp joins (#173). Else from pre-test env.
                _eval_expr(stmt.test, env, path=path)
                env_pre = _copy_env(env)
                env_body = _copy_env(env)
                _scan_stmts(
                    stmt.body,
                    path=path,
                    index=index,
                    env=env_body,
                    visited_fns=visited_fns,
                    local_fns=active_fns,
                    local_classes=active_classes,
                    declared_globals=active_globals,
                )
                env_else = _copy_env(env_pre)
                _scan_stmts(
                    stmt.orelse,
                    path=path,
                    index=index,
                    env=env_else,
                    visited_fns=visited_fns,
                    local_fns=active_fns,
                    local_classes=active_classes,
                    declared_globals=active_globals,
                )
                joined = _join_envs(env_pre, _join_envs(env_body, env_else))
                env.clear()
                env.update(joined)
                continue
            if isinstance(stmt, (ast.With, ast.AsyncWith)):
                bound_as: set[str] = set()
                for item in stmt.items:
                    subject = _eval_expr(item.context_expr, env, path=path)
                    if item.optional_vars is not None:
                        # Unmodeled context-manager projection: escape subject
                        # identity and bind Name targets as unknown. Attribute
                        # / subscript as-targets mutate exports
                        # (``with CM() as helpers.write_state``) (#173).
                        _escape_if_tracked(subject)
                        names = _collect_store_names(item.optional_vars)
                        bound_as.update(names)
                        _scan_assign_target(
                            item.optional_vars,
                            path=path,
                            index=index,
                            env=env,
                            value_points=_IdentityPointsTo.unknown_only(),
                        )
                        # Seed class/protocol packs from the context expression
                        # (``with ({Mut:1}.keys()) as ks`` / items carriers) so
                        # later unpack observes construction (Unknown > false PASS).
                        seed_expr = item.context_expr
                        # ``with CM() as x`` — peel local ``__enter__`` returns when
                        # the enter body is a trivial return of a view/pack.
                        if (
                            isinstance(seed_expr, ast.Call)
                            and isinstance(seed_expr.func, ast.Name)
                        ):
                            enter_cls = _lookup_class(
                                seed_expr.func.id, active_classes
                            )
                            if enter_cls is not None:
                                for body_stmt in enter_cls.body:
                                    if (
                                        isinstance(
                                            body_stmt,
                                            (ast.FunctionDef, ast.AsyncFunctionDef),
                                        )
                                        and body_stmt.name == "__enter__"
                                    ):
                                        for ent in body_stmt.body:
                                            if (
                                                isinstance(ent, ast.Return)
                                                and ent.value is not None
                                            ):
                                                seed_expr = ent.value
                                                break
                        if isinstance(item.optional_vars, ast.Name):
                            _note_protocol_alias_from_value(
                                item.optional_vars.id, seed_expr
                            )
                            # Name-bound ``with k() as ks`` when ``k = d.keys`` —
                            # reconstruct ``d.keys()`` so later unpack shares the
                            # Attribute view path (Unknown > false PASS).
                            seed_call = _peel_call_func(seed_expr)
                            as_name = item.optional_vars.id
                            # ``with nullcontext(n.install) as f`` /
                            # ``contextlib.nullcontext(...)`` — enter returns the
                            # argument (Unknown > false PASS).
                            nc_arg = _nullcontext_enter_arg(
                                seed_expr,
                                getattr_aliases=frozenset(getattr_aliases),
                            )
                            if nc_arg is not None:
                                seed_expr = nc_arg
                                seed_call = _peel_call_func(seed_expr)
                                _note_protocol_alias_from_value(as_name, seed_expr)
                            if isinstance(seed_call, ast.Call):
                                view = _view_call_parts(seed_call)
                                reconstructed: ast.AST | None = None
                                if (
                                    view is not None
                                    and view[0] in _DICT_ITER_VIEW_ATTRS
                                ):
                                    reconstructed = ast.Call(
                                        func=ast.Attribute(
                                            value=view[1],
                                            attr=view[0],
                                            ctx=ast.Load(),
                                        ),
                                        args=[],
                                        keywords=[],
                                    )
                                else:
                                    fbound = _peel_call_func(seed_call.func)
                                    if (
                                        isinstance(fbound, ast.Name)
                                        and fbound.id in dict_view_products
                                    ):
                                        vattr = dict_view_products[fbound.id].split(
                                            "."
                                        )[-1]
                                        recv_n = bound_view_receivers.get(fbound.id)
                                        if (
                                            vattr in _DICT_ITER_VIEW_ATTRS
                                            and recv_n is not None
                                        ):
                                            reconstructed = ast.Call(
                                                func=ast.Attribute(
                                                    value=ast.Name(
                                                        id=recv_n, ctx=ast.Load()
                                                    ),
                                                    attr=vattr,
                                                    ctx=ast.Load(),
                                                ),
                                                args=[],
                                                keywords=[],
                                            )
                                if reconstructed is not None:
                                    sequence_view_aliases[as_name] = reconstructed
                                    _note_protocol_alias_from_value(
                                        as_name, reconstructed
                                    )
                                    seed_expr = reconstructed
                            _seed_assign_unpack_aliases(
                                item.optional_vars,
                                seed_expr,
                                active_classes=active_classes,
                            )
                        elif isinstance(item.optional_vars, (ast.Tuple, ast.List)):
                            _seed_assign_unpack_aliases(
                                item.optional_vars,
                                seed_expr,
                                active_classes=active_classes,
                            )
                if bound_as and _with_as_targets_mutated(stmt.body, bound_as):
                    # Opaque with-as alias mutated — cannot prove export/callable
                    # identity remains (Unknown > false PASS).
                    accum.unsupported = True
                env_body = _copy_env(env)
                _scan_stmts(
                    stmt.body,
                    path=path,
                    index=index,
                    env=env_body,
                    visited_fns=visited_fns,
                    local_fns=active_fns,
                    local_classes=active_classes,
                    declared_globals=active_globals,
                )
                joined = _join_envs(env, env_body)
                env.clear()
                env.update(joined)
                continue
            if isinstance(stmt, ast.Try):
                env_pre = _copy_env(env)
                env_body = _copy_env(env)
                _scan_stmts(
                    stmt.body,
                    path=path,
                    index=index,
                    env=env_body,
                    visited_fns=visited_fns,
                    local_fns=active_fns,
                    local_classes=active_classes,
                    declared_globals=active_globals,
                )
                branch_envs = [env_body]
                if not stmt.handlers:
                    # No handler: exceptional exit still reaches finally —
                    # join the pre-body predecessor so finally effects are not
                    # dropped under a body-only join (#173).
                    branch_envs.append(env_pre)
                for handler in stmt.handlers:
                    env_h = _copy_env(env)
                    # except TYPE executes before the handler body
                    # (``except poison():``). Unknown > false PASS (#173).
                    if handler.type is not None:
                        _eval_expr(handler.type, env_h, path=path)
                    if handler.name:
                        env_h[handler.name] = _IdentityPointsTo.unknown_only()
                    _scan_stmts(
                        handler.body,
                        path=path,
                        index=index,
                        env=env_h,
                        visited_fns=visited_fns,
                        local_fns=active_fns,
                        local_classes=active_classes,
                    )
                    branch_envs.append(env_h)
                env_else = _copy_env(env_body)
                _scan_stmts(
                    stmt.orelse,
                    path=path,
                    index=index,
                    env=env_else,
                    visited_fns=visited_fns,
                    local_fns=active_fns,
                    local_classes=active_classes,
                    declared_globals=active_globals,
                )
                branch_envs.append(env_else)
                merged = branch_envs[0]
                for other in branch_envs[1:]:
                    merged = _join_envs(merged, other)
                env_final = _copy_env(merged)
                _scan_stmts(
                    stmt.finalbody,
                    path=path,
                    index=index,
                    env=env_final,
                    visited_fns=visited_fns,
                    local_fns=active_fns,
                    local_classes=active_classes,
                    declared_globals=active_globals,
                )
                env.clear()
                env.update(env_final)
                continue
            if isinstance(stmt, ast.Match):
                subject = _eval_expr(stmt.subject, env, path=path)
                branch_envs: list[dict[str, _IdentityPointsTo]] = []
                for case in stmt.cases:
                    env_c = _copy_env(env)
                    # MatchClass against local metaclasses / dynamic match
                    # protocols: fail closed rather than authorize (#173).
                    if isinstance(case.pattern, ast.MatchClass):
                        cls_expr = case.pattern.cls
                        if isinstance(cls_expr, ast.Name):
                            cls_node = _lookup_class(cls_expr.id, active_classes)
                            if cls_node is not None:
                                has_meta = any(
                                    kw.arg == "metaclass" for kw in cls_node.keywords
                                )
                                has_protocol = any(
                                    isinstance(
                                        item, (ast.FunctionDef, ast.AsyncFunctionDef)
                                    )
                                    and item.name
                                    in {
                                        "__instancecheck__",
                                        "__subclasscheck__",
                                        "__match_args__",
                                    }
                                    for item in cls_node.body
                                ) or any(
                                    isinstance(item, ast.Assign)
                                    and any(
                                        isinstance(t, ast.Name)
                                        and t.id == "__match_args__"
                                        for t in item.targets
                                    )
                                    for item in cls_node.body
                                )
                                if has_meta or has_protocol:
                                    accum.unsupported = True
                                    if has_meta or has_protocol:
                                        _scan_named_methods_on_class(
                                            cls_node,
                                            frozenset(
                                                {
                                                    "__instancecheck__",
                                                    "__subclasscheck__",
                                                }
                                            ),
                                            path=path,
                                            index=index,
                                            env=env_c,
                                            visited_fns=visited_fns,
                                            local_fns=active_fns,
                                            local_classes=active_classes,
                                        )
                        else:
                            accum.unsupported = True
                    pattern_names = _collect_match_pattern_names(case.pattern)
                    if pattern_names:
                        # Pattern bind is an unmodeled projection of subject.
                        _escape_if_tracked(subject)
                    for name in pattern_names:
                        env_c[name] = _IdentityPointsTo.unknown_only()
                    # Class / instance aliases through MatchAs and seq/map peels
                    # so ``match (Mut,): case (C,): C()`` observes construction.
                    def _env_class_alias(
                        bound_name: str, matched_name: ast.AST
                    ) -> None:
                        env_c[bound_name] = _eval_expr(
                            matched_name, env_c, path=path
                        )

                    # Shared Match seed (walrus / Name-bound / dict() subjects,
                    # ``**rest`` packs, star binders, protocol products).
                    _seed_match_binds(
                        case.pattern,
                        [stmt.subject],
                        active_classes=active_classes,
                        on_class_alias=_env_class_alias,
                    )
                    # Subject-capturing ``case x`` / ``case x if …`` keeps the
                    # subject points-to so ``match n: case x: x.install(…)``
                    # follows module exports (Unknown > false PASS).
                    if (
                        isinstance(case.pattern, ast.MatchAs)
                        and case.pattern.name
                        and case.pattern.pattern is None
                    ):
                        env_c[case.pattern.name] = subject
                    # MatchValue Attribute patterns: fail-closed export rebind
                    # (``match (evil,): case (helpers.write_state,):``).
                    for attr_target in _match_pattern_attribute_targets(case.pattern):
                        _scan_assign_target(
                            attr_target,
                            path=path,
                            index=index,
                            env=env_c,
                            value_points=subject,
                        )
                    if case.guard is not None:
                        # Guard executes on paths reaching this case (#173).
                        _eval_expr(case.guard, env_c, path=path)
                    _scan_stmts(
                        case.body,
                        path=path,
                        index=index,
                        env=env_c,
                        visited_fns=visited_fns,
                        local_fns=active_fns,
                        local_classes=active_classes,
                    )
                    branch_envs.append(env_c)
                if not branch_envs:
                    continue
                merged = branch_envs[0]
                for other in branch_envs[1:]:
                    merged = _join_envs(merged, other)
                # Retain no-match predecessor unless final case is an
                # unguarded irrefutable pattern (#171).
                if not _match_exhaustive(stmt):
                    merged = _join_envs(env, merged)
                env.clear()
                env.update(merged)
                continue
            if isinstance(stmt, ast.Raise):
                # raise exc from cause — both expressions execute.
                if stmt.exc is not None:
                    _eval_expr(stmt.exc, env, path=path)
                if stmt.cause is not None:
                    _eval_expr(stmt.cause, env, path=path)
                continue
            if isinstance(stmt, ast.Return) and stmt.value is not None:
                # return value executes (args before callee in nested calls).
                _eval_expr(stmt.value, env, path=path)
                continue

    def seed_env_for_path(path: str) -> dict[str, _IdentityPointsTo]:
        env: dict[str, _IdentityPointsTo] = {}
        for name in bindings_by_path.get(path, {}):
            env[name] = _identity_from_final_binding(
                name,
                path=path,
                bindings_by_path=bindings_by_path,
                available_paths=available_paths,
                import_roots=import_roots,
            )
        return env

    def local_fns_for_path(
        path: str,
    ) -> dict[str, ast.FunctionDef | ast.AsyncFunctionDef]:
        tree = trees.get(path)
        result: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
        if tree is None:
            return result
        for node in getattr(tree, "body", ()):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                result[node.name] = node
        return result

    def scan_module_init() -> None:
        # Top-level walk per module: statement-order identity environment (#165).
        for path, tree in trees.items():
            _register_module_classes(path)
            env: dict[str, _IdentityPointsTo] = {}
            body: Sequence[ast.stmt] = getattr(tree, "body", ())
            module_fns: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
            module_classes: dict[str, ast.ClassDef] = {}
            for node in body:
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    module_fns[node.name] = node
                elif isinstance(node, ast.ClassDef):
                    module_classes[node.name] = node
            for index, node in enumerate(body):
                _scan_stmts(
                    [node],
                    path=path,
                    index=index,
                    env=env,
                    visited_fns=set(),
                    local_fns=module_fns,
                    local_classes=module_classes,
                )

    def seed_class_registry() -> None:
        for path in trees:
            _register_module_classes(path)

    def seed_module_protocol_aliases(path: str) -> None:
        """Seed module-level ImportFrom/Assign/AnnAssign into protocol aliases.

        Request-time sessions previously only saw function-body binds, so
        ``from operator import call as oc`` / ``partial as p`` at module scope
        false-PASSed Name-alias peels (Unknown > false PASS).
        """

        tree = trees.get(path)
        if tree is None:
            return
        for node in getattr(tree, "body", ()):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                _apply_import_identities(node, {}, path=path)
            elif isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        _note_protocol_alias_from_value(target.id, node.value)
            elif isinstance(node, ast.AnnAssign):
                if isinstance(node.target, ast.Name) and node.value is not None:
                    _note_protocol_alias_from_value(node.target.id, node.value)
            elif isinstance(node, ast.Expr) and isinstance(node.value, ast.NamedExpr):
                if isinstance(node.value.target, ast.Name):
                    _note_protocol_alias_from_value(
                        node.value.target.id, node.value.value
                    )

    def observe_expr(
        expr: ast.AST,
        *,
        path: str,
        env: dict[str, _IdentityPointsTo],
        visited_fns: set[int],
        local_fns: Mapping[str, ast.FunctionDef | ast.AsyncFunctionDef] | None = None,
        local_classes: Mapping[str, ast.ClassDef] | None = None,
    ) -> None:
        """Evaluate one executed expression for identity side effects (#173)."""

        active_fns: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = dict(
            local_fns or {}
        )
        active_classes: dict[str, ast.ClassDef] = dict(local_classes or {})
        _scan_ctx["index"] = 0
        _scan_ctx["visited_fns"] = visited_fns
        _scan_ctx["local_fns"] = active_fns
        _scan_ctx["local_classes"] = active_classes
        _eval_expr(expr, env, path=path)

    def _enter_session_ctx(
        visited_fns: set[int],
        local_fns: Mapping[str, ast.FunctionDef | ast.AsyncFunctionDef] | None,
        local_classes: Mapping[str, ast.ClassDef] | None,
    ) -> dict[str, ast.ClassDef]:
        active_classes: dict[str, ast.ClassDef] = dict(local_classes or {})
        _scan_ctx["index"] = 0
        _scan_ctx["visited_fns"] = visited_fns
        _scan_ctx["local_fns"] = dict(local_fns or {})
        _scan_ctx["local_classes"] = active_classes
        return active_classes

    def seed_for_binding(
        target: ast.AST,
        iter_expr: ast.AST,
        *,
        path: str,
        env: dict[str, _IdentityPointsTo],
        visited_fns: set[int],
        local_fns: Mapping[str, ast.FunctionDef | ast.AsyncFunctionDef] | None = None,
        local_classes: Mapping[str, ast.ClassDef] | None = None,
    ) -> None:
        """Seed a For / AsyncFor target for CF walkers that own the loop.

        Same seed path as ``_scan_stmts`` For: the iterated element union flows
        through the shared resolver into class / protocol / container aliases,
        then the target severs precise identity (Unknown > false PASS).
        """

        active_classes = _enter_session_ctx(visited_fns, local_fns, local_classes)
        _seed_for_iter_class_aliases(target, iter_expr, active_classes=active_classes)
        _scan_assign_target(
            target,
            path=path,
            index=0,
            env=env,
            value_points=_IdentityPointsTo.unknown_only(),
        )

    def seed_match_binding(
        pattern: ast.AST,
        subject: ast.AST,
        *,
        path: str,
        env: dict[str, _IdentityPointsTo],
        visited_fns: set[int],
        local_fns: Mapping[str, ast.FunctionDef | ast.AsyncFunctionDef] | None = None,
        local_classes: Mapping[str, ast.ClassDef] | None = None,
    ) -> None:
        """Seed one Match case pattern for CF walkers that own the Match."""

        active_classes = _enter_session_ctx(visited_fns, local_fns, local_classes)

        def _env_class_alias(bound_name: str, matched_name: ast.AST) -> None:
            env[bound_name] = _eval_expr(matched_name, env, path=path)

        _seed_match_binds(
            pattern,
            [subject],
            active_classes=active_classes,
            on_class_alias=_env_class_alias,
        )
        # Subject-capturing ``case x`` / ``case x if …`` — keep subject
        # points-to for module.attr / install peels.
        if (
            isinstance(pattern, ast.MatchAs)
            and pattern.name
            and pattern.pattern is None
        ):
            env[pattern.name] = _eval_expr(subject, env, path=path)

    class _IdentityScanner:
        pass

    scanner = _IdentityScanner()
    scanner.seed_for_binding = seed_for_binding  # type: ignore[method-assign]
    scanner.seed_match_binding = seed_match_binding  # type: ignore[method-assign]
    scanner.scan_stmts = _scan_stmts  # type: ignore[method-assign]
    scanner.observe_expr = observe_expr  # type: ignore[method-assign]
    scanner.scan_module_init = scan_module_init  # type: ignore[method-assign]
    scanner.seed_env_for_path = seed_env_for_path  # type: ignore[method-assign]
    scanner.local_fns_for_path = local_fns_for_path  # type: ignore[method-assign]
    scanner.seed_class_registry = seed_class_registry  # type: ignore[method-assign]
    scanner.seed_module_protocol_aliases = seed_module_protocol_aliases  # type: ignore[method-assign]
    return scanner


def _collect_mutation_effects(
    trees: Mapping[str, ast.AST],
    bindings_by_path: Mapping[str, Mapping[str, FinalBinding]],
    *,
    available_paths: frozenset[str],
    import_roots: tuple[str, ...],
) -> _MutationEffects:
    """Collect module-export and callable-behavior mutations (#163 / #165).

    Walks module-level executable statements in order with a bounded
    object-alias identity environment. Mutation closure keys off object
    identity available at the mutation point; final bindings remain the
    authority for authorizing call resolution after effects are applied.
    Shared by bypass writer closure and interprocedural argument provenance.
    """

    accum = _MutationAccum.fresh()
    scanner = _build_identity_scanner(
        trees,
        bindings_by_path,
        available_paths=available_paths,
        import_roots=import_roots,
        accum=accum,
    )
    scanner.scan_module_init()
    return accum.as_effects()


def begin_request_time_identity_session(
    resolver: "CalleeResolver",
    *,
    path: str,
    fn: ast.FunctionDef | ast.AsyncFunctionDef,
) -> RequestTimeIdentitySession:
    """Start a phase-sensitive identity session for request-time execution (#167).

    Seeds the #166 identity environment from module final bindings (already
    closed under module-init mutation effects) and scans the selected function
    body incrementally so authorizing resolve sees program-point identity.
    """

    path_n = normalize_path(path)
    accum = _MutationAccum.fresh()
    scanner = _build_identity_scanner(
        resolver.trees,
        resolver.bindings_by_path,
        available_paths=resolver.available_paths,
        import_roots=resolver.import_roots,
        accum=accum,
    )
    scanner.seed_class_registry()
    scanner.seed_module_protocol_aliases(path_n)  # type: ignore[attr-defined]
    env = scanner.seed_env_for_path(path_n)
    local_fns = dict(scanner.local_fns_for_path(path_n))
    return RequestTimeIdentitySession(
        path=path_n,
        accum=accum,
        env=env,
        local_fns=local_fns,
        visited_fns=set(),
        _scan_stmts=scanner.scan_stmts,
        _observe_expr=scanner.observe_expr,
        _seed_for=scanner.seed_for_binding,  # type: ignore[attr-defined]
        _seed_match=scanner.seed_match_binding,  # type: ignore[attr-defined]
        _resolver=resolver,
        _reestablished_exports={},
        _reestablished_behaviors=set(),
    )



def _apply_mutation_effects(
    bindings_by_path: dict[str, dict[str, FinalBinding]],
    effects: _MutationEffects,
    *,
    available_paths: frozenset[str],
    import_roots: tuple[str, ...],
) -> dict[str, dict[str, FinalBinding]]:
    """Apply ModuleBindingIdentity and CallableBehaviorIdentity poisons."""

    result: dict[str, dict[str, FinalBinding]] = {
        path: dict(bindings) for path, bindings in bindings_by_path.items()
    }

    export_mutations = {
        path: set(names) for path, names in effects.export_mutations.items()
    }
    if effects.unsupported_module_mutation:
        for path in list(available_paths):
            export_mutations.setdefault(path, set()).add("*")

    for path, names in export_mutations.items():
        target = result.setdefault(path, {})
        if "*" in names:
            _mark_rebound(target, list(target))
            poison_names = set(target) | (names - {"*"})
        else:
            poison_names = set(names)
            for name in names:
                target[name] = FinalBinding(kind="rebound")
        for other_path, other_bindings in result.items():
            if other_path == path:
                continue
            for local, binding in list(other_bindings.items()):
                if binding.kind != "import_name" or binding.module_name is None:
                    continue
                candidates = module_candidates_in_manifest(
                    binding.module_name,
                    set(available_paths),
                    import_roots=import_roots,
                )
                if len(candidates) != 1 or candidates[0] != path:
                    continue
                if "*" in names or binding.imported_name in poison_names:
                    other_bindings[local] = FinalBinding(kind="rebound")

    for defining_path, export_name in effects.behavior_mutations:
        target = result.setdefault(defining_path, {})
        binding = target.get(export_name)
        if binding is not None and binding.kind == "function":
            target[export_name] = replace(binding, behavior_established=False)
        elif binding is not None:
            target[export_name] = replace(binding, behavior_established=False)
        else:
            target[export_name] = FinalBinding(
                kind="rebound",
                behavior_established=False,
            )
        for other_path, other_bindings in result.items():
            for local, other in list(other_bindings.items()):
                if other.kind != "import_name" or other.module_name is None:
                    continue
                if other.imported_name != export_name:
                    continue
                candidates = module_candidates_in_manifest(
                    other.module_name,
                    set(available_paths),
                    import_roots=import_roots,
                )
                if len(candidates) == 1 and candidates[0] == defining_path:
                    other_bindings[local] = replace(
                        other, behavior_established=False
                    )

    return result


@dataclass(frozen=True)
class CalleeResolver:
    """Caller-relative callee resolver over an authenticated Python file set."""

    trees: Mapping[str, ast.AST]
    bindings_by_path: Mapping[str, Mapping[str, FinalBinding]]
    available_paths: frozenset[str]
    import_roots: tuple[str, ...] = ()
    implementation_version: str = _IMPLEMENTATION_VERSION

    def resolve_call(
        self,
        func: ast.AST,
        *,
        caller_path: str,
        shadowed_names: frozenset[str] = frozenset(),
    ) -> CalleeResolveResult:
        """Resolve ``func`` of a Call relative to ``caller_path``."""

        caller = normalize_path(caller_path)
        if isinstance(func, ast.Name):
            if func.id in shadowed_names:
                return CalleeResolveResult(
                    callee=None,
                    reason="shadowed_local_binding",
                )
            return self._resolve_name(func.id, owner_path=caller)

        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            return self._resolve_module_attribute(
                module_alias=func.value.id,
                attr=func.attr,
                caller_path=caller,
                shadowed_names=shadowed_names,
            )

        return CalleeResolveResult(callee=None, reason="deferred_callee_form")

    def _resolve_name(
        self,
        name: str,
        *,
        owner_path: str,
        depth: int = 0,
    ) -> CalleeResolveResult:
        if depth > _MAX_IMPORT_FOLLOW_DEPTH:
            return CalleeResolveResult(callee=None, reason="import_follow_depth")

        owner = normalize_path(owner_path)
        bindings = self.bindings_by_path.get(owner)
        if bindings is None:
            return CalleeResolveResult(callee=None, reason="caller_module_absent")

        binding = bindings.get(name)
        if binding is None:
            return CalleeResolveResult(callee=None, reason="unbound_name")

        if not binding.behavior_established:
            return CalleeResolveResult(
                callee=None,
                reason="callable_behavior_unknown",
            )

        if binding.kind == "function":
            assert binding.function_node is not None
            return CalleeResolveResult(
                callee=ResolvedCallee(path=owner, node=binding.function_node),
            )

        if binding.kind == "rebound":
            return CalleeResolveResult(callee=None, reason="module_level_rebinding")

        if binding.kind == "import_name":
            assert binding.module_name is not None
            assert binding.imported_name is not None
            return self._resolve_from_module(
                binding.module_name,
                binding.imported_name,
                depth=depth + 1,
            )

        if binding.kind == "import_module":
            return CalleeResolveResult(callee=None, reason="module_alias_not_callable")

        return CalleeResolveResult(callee=None, reason="unresolved_binding")

    def _resolve_module_attribute(
        self,
        *,
        module_alias: str,
        attr: str,
        caller_path: str,
        shadowed_names: frozenset[str],
    ) -> CalleeResolveResult:
        if module_alias in shadowed_names:
            return CalleeResolveResult(
                callee=None,
                reason="shadowed_local_binding",
            )
        bindings = self.bindings_by_path.get(caller_path)
        if bindings is None:
            return CalleeResolveResult(callee=None, reason="caller_module_absent")
        binding = bindings.get(module_alias)
        if binding is None:
            return CalleeResolveResult(callee=None, reason="unbound_module_alias")
        if binding.kind != "import_module" or binding.module_name is None:
            return CalleeResolveResult(
                callee=None,
                reason="deferred_module_attribute",
            )
        return self._resolve_from_module(binding.module_name, attr, depth=0)

    def _resolve_from_module(
        self,
        module_name: str,
        attr: str,
        *,
        depth: int,
    ) -> CalleeResolveResult:
        candidates = module_candidates_in_manifest(
            module_name,
            set(self.available_paths),
            import_roots=self.import_roots,
        )
        if len(candidates) == 0:
            return CalleeResolveResult(callee=None, reason="external_import")
        if len(candidates) > 1:
            return CalleeResolveResult(callee=None, reason="ambiguous_manifest")
        target_path = candidates[0]
        return self._resolve_name(attr, owner_path=target_path, depth=depth)


def build_callee_resolver(
    trees: Mapping[str, ast.AST],
    *,
    import_roots: Sequence[str] = (),
) -> CalleeResolver:
    """Build a resolver over already-parsed module ASTs keyed by path."""

    roots = normalize_import_roots(import_roots)
    normalized: dict[str, ast.AST] = {
        normalize_path(path): tree for path, tree in trees.items()
    }
    available = frozenset(normalized)
    bindings = {
        path: module_final_bindings(tree, path=path)
        for path, tree in normalized.items()
    }
    effects = _collect_mutation_effects(
        normalized,
        bindings,
        available_paths=available,
        import_roots=roots,
    )
    if (
        effects.export_mutations
        or effects.behavior_mutations
        or effects.unsupported_module_mutation
    ):
        bindings = _apply_mutation_effects(
            bindings,
            effects,
            available_paths=available,
            import_roots=roots,
        )
    return CalleeResolver(
        trees=normalized,
        bindings_by_path=bindings,
        available_paths=available,
        import_roots=roots,
    )


def build_callee_resolver_from_sources(
    files: Mapping[str, str],
    *,
    import_roots: Sequence[str] = (),
) -> CalleeResolver:
    """Parse ``files`` and build a caller-relative callee resolver."""

    trees: dict[str, ast.AST] = {}
    for path, source in files.items():
        norm = normalize_path(path)
        trees[norm] = ast.parse(source, filename=path)
    return build_callee_resolver(trees, import_roots=import_roots)


def index_unique_module_functions(
    trees: Mapping[str, ast.AST],
) -> dict[str, ResolvedCallee]:
    """Map simple name → unique non-rebound module function, when unambiguous.

    Used only to select an analysis *target* by leaf name. Callsite matching
    must still go through :meth:`CalleeResolver.resolve_call`.
    """

    buckets: dict[str, list[ResolvedCallee]] = {}
    for path, tree in sorted(
        (normalize_path(p), t) for p, t in trees.items()
    ):
        bindings = module_final_bindings(tree, path=path)
        for name, binding in bindings.items():
            if binding.kind != "function" or binding.function_node is None:
                continue
            buckets.setdefault(name, []).append(
                ResolvedCallee(path=path, node=binding.function_node)
            )
    unique: dict[str, ResolvedCallee] = {}
    for name, items in buckets.items():
        if len(items) == 1:
            unique[name] = items[0]
    return unique
