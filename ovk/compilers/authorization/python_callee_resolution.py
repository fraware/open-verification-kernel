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
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from typing import Literal

from ovk.compilers.authorization.python_import_space import (
    module_candidates_in_manifest,
    normalize_import_roots,
    normalize_path,
)

_IMPLEMENTATION_VERSION = "0.23.0"
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


def _is_setattr_call(call: ast.Call) -> bool:
    func = call.func
    return (isinstance(func, ast.Name) and func.id == "setattr") or (
        isinstance(func, ast.Attribute) and func.attr == "__setattr__"
    )


def _is_delattr_call(call: ast.Call) -> bool:
    func = call.func
    return (isinstance(func, ast.Name) and func.id == "delattr") or (
        isinstance(func, ast.Attribute) and func.attr == "__delattr__"
    )


def _setattr_target_and_name(
    call: ast.Call,
) -> tuple[ast.AST, ast.AST] | None:
    """Return (target_obj, name_expr) for setattr-shaped calls."""

    if not _is_setattr_call(call) or len(call.args) < 2:
        return None
    func = call.func
    if isinstance(func, ast.Name) and func.id == "setattr":
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
    {"getitem", "itemgetter", "attrgetter", "methodcaller", "attrsetter", "call"}
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
    }
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
        "MappingProxyType",
    }
)


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


def _methodcaller_static_name(
    call: ast.Call,
    *,
    projection_aliases: Mapping[str, str] | None = None,
) -> str | None:
    """Return the static method name for ``operator.methodcaller("x")``."""

    aliases = projection_aliases or {}
    func = _peel_call_func(call.func)
    if isinstance(func, ast.Name) and call.args:
        if func.id == "methodcaller" or aliases.get(func.id) == "methodcaller":
            return _static_str(call.args[0])
    if (
        isinstance(func, ast.Attribute)
        and func.attr == "methodcaller"
        and call.args
    ):
        return _static_str(call.args[0])
    return None


def _itemgetter_static_key(
    call: ast.Call,
    *,
    projection_aliases: Mapping[str, str] | None = None,
) -> str | None:
    """Return the static key for ``operator.itemgetter("x")`` / aliases."""

    aliases = projection_aliases or {}
    func = _peel_call_func(call.func)
    if isinstance(func, ast.Name) and call.args:
        if func.id == "itemgetter" or aliases.get(func.id) == "itemgetter":
            return _static_str(call.args[0])
    if isinstance(func, ast.Attribute) and func.attr == "itemgetter" and call.args:
        return _static_str(call.args[0])
    return None


def _attrgetter_static_name(
    call: ast.Call,
    *,
    projection_aliases: Mapping[str, str] | None = None,
) -> str | None:
    """Return the static attribute name for ``operator.attrgetter("x")`` / aliases."""

    aliases = projection_aliases or {}
    func = _peel_call_func(call.func)
    if isinstance(func, ast.Name) and call.args:
        if func.id == "attrgetter" or aliases.get(func.id) == "attrgetter":
            return _static_str(call.args[0])
    if isinstance(func, ast.Attribute) and func.attr == "attrgetter" and call.args:
        return _static_str(call.args[0])
    return None


def _projection_factory_name(
    call: ast.Call,
    *,
    projection_aliases: Mapping[str, str] | None = None,
) -> str | None:
    """Canonical operator projection name for a factory Call, if any."""

    aliases = projection_aliases or {}
    func = _peel_call_func(call.func)
    if isinstance(func, ast.Name):
        if func.id in _OPERATOR_PROJECTION_NAMES:
            return func.id
        return aliases.get(func.id)
    if isinstance(func, ast.Attribute) and func.attr in _OPERATOR_PROJECTION_NAMES:
        return func.attr
    return None


def _is_partial_factory(
    call: ast.Call,
    *,
    partial_aliases: frozenset[str] | None = None,
) -> bool:
    """True for ``functools.partial(...)`` / ``partial(...)`` / aliases."""

    aliases = partial_aliases or frozenset({"partial"})
    func = _peel_call_func(call.func)
    if isinstance(func, ast.Name) and func.id in aliases:
        return True
    if isinstance(func, ast.Attribute) and func.attr == "partial":
        return True
    return False


def _is_operator_call_factory(
    call: ast.Call,
    *,
    projection_aliases: Mapping[str, str] | None = None,
    getattr_aliases: frozenset[str] | None = None,
) -> bool:
    """True for ``operator.call(...)`` / renamed ``call`` / getattr projections.

    Peels NamedExpr so ``(oc := operator.call)(...)`` and Name aliases of
    ``call`` (``from operator import call as oc``) are recognized before any
    bare-Name short-circuit (Unknown > false PASS).
    """

    aliases = projection_aliases or {}
    func = _peel_call_func(call.func)
    if isinstance(func, ast.Name):
        return func.id == "call" or aliases.get(func.id) == "call"
    if isinstance(func, ast.Attribute) and func.attr == "call":
        return True
    # ``getattr(operator, "call")`` / renamed getattr.
    if isinstance(func, ast.Call):
        return _getattr_static_name(func, getattr_aliases=getattr_aliases) == "call"
    return False


def _peel_call_func(func: ast.AST) -> ast.AST:
    """Unwrap NamedExpr / trivial Await layers from a Call.func expression."""

    func = _unwrap_await(func)
    while isinstance(func, ast.NamedExpr):
        func = _unwrap_await(func.value)
    return func


def _getattr_static_name(
    call: ast.Call,
    *,
    getattr_aliases: frozenset[str] | None = None,
) -> str | None:
    """Return the static attribute name for ``getattr(obj, "x")`` / aliases.

    Also accepts ``builtins.getattr`` / ``x.getattr`` Attribute forms so renamed
    module projections cannot skip protocol peels (Unknown > false PASS).
    """

    aliases = getattr_aliases or frozenset({"getattr"})
    func = _peel_call_func(call.func)
    is_getattr = (
        isinstance(func, ast.Name) and func.id in aliases
    ) or (isinstance(func, ast.Attribute) and func.attr == "getattr")
    if not is_getattr or len(call.args) < 2 or call.keywords:
        return None
    return _static_str(call.args[1])


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
) -> list[str]:
    """Name ids reachable as a packed/projected callee expression.

    Shared peel for Call.func forms (NamedExpr/IfExp/BoolOp/Subscript/containers)
    and Call peels (``.get``/``.pop``/``next(iter)``/``getattr``/``attrgetter``/
    ``itemgetter``/``getitem``/``methodcaller``/``operator.call``/``partial``).
    Used to observe ``(Mut if True else int)()`` / ``{\"e\": exec}.get(\"e\")(...)``
    / ``[getattr(builtins, \"exec\")][0](...)`` (Unknown > false PASS).
    """

    aliases = projection_aliases or {}
    g_aliases = getattr_aliases or frozenset({"getattr"})
    p_aliases = partial_aliases or frozenset({"partial"})
    a_aliases = adapter_aliases or frozenset()

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
        if isinstance(node, ast.Subscript):
            names = list(_peel(node.value))
            key = _static_str(node.slice)
            if key is not None and key not in names:
                names.append(key)
            return names
        if isinstance(node, ast.Attribute):
            return [node.attr]
        if isinstance(node, ast.Call):
            return _peel_call(node)
        return []

    def _peel_call(call: ast.Call) -> list[str]:
        func = call.func
        # Container views: ``{\"e\": exec}.get(\"e\")`` / ``[exec].pop()`` /
        # ``vars().get(\"exec\")`` / Name-bound ``d.get(\"Mut\")``.
        if isinstance(func, ast.Attribute) and func.attr in _CALLEE_VIEW_ATTRS:
            recv = func.value
            names: list[str] = []
            key: str | None = None
            if func.attr in {"get", "__getitem__"} and call.args:
                key = _static_str(call.args[0])
            elif func.attr == "pop" and call.args:
                key = _static_str(call.args[0])
            if key is not None and isinstance(recv, ast.Dict):
                matched = _dict_values_for_static_key(recv, key)
                if matched:
                    for value in matched:
                        names.extend(_peel(value))
                elif func.attr == "get" and len(call.args) >= 2:
                    names.extend(_peel(call.args[1]))
                else:
                    names.append(key)
            else:
                names.extend(_peel(recv))
                if key is not None:
                    names.append(key)
                if func.attr == "get" and len(call.args) >= 2:
                    names.extend(_peel(call.args[1]))
            return names
        # Unbound ``dict.get(packed, key)`` / ``dict.__getitem__(packed, key)``.
        if (
            isinstance(func, ast.Attribute)
            and isinstance(func.value, ast.Name)
            and func.value.id == "dict"
            and func.attr in {"get", "__getitem__", "pop"}
            and call.args
        ):
            names = list(_peel(call.args[0]))
            key = _static_str(call.args[1]) if len(call.args) >= 2 else None
            if key is not None:
                names.append(key)
            if func.attr == "get" and len(call.args) >= 3:
                names.extend(_peel(call.args[2]))
            return names
        # ``getattr(obj, \"exec\")`` / ``getattr(Mut, \"__call__\", default)``.
        gname = _getattr_static_name(call, getattr_aliases=g_aliases)
        if gname is not None:
            names = [gname]
            if len(call.args) >= 3:
                names.extend(_peel(call.args[2]))
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
                names.extend(_peel(nested))
            return names
        # ``operator.call(exec, ...)`` / renamed ``call``.
        if _is_operator_call_factory(call, projection_aliases=aliases):
            if call.args:
                return _peel(call.args[0])
            return []
        # ``functools.partial(Mut)`` / ``partial(exec)``.
        if _is_partial_factory(call, partial_aliases=p_aliases):
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
            # ``partial(Mut)()`` already handled when peeling partial Call; when
            # ``func`` itself is ``partial(Mut)``, peel the factory.
            if _is_partial_factory(func, partial_aliases=p_aliases):
                return _peel(func)
            if _is_operator_call_factory(func, projection_aliases=aliases):
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

    def _packed_names(expr: ast.AST) -> list[str]:
        """Shared packing/projection peel with live protocol aliases."""

        return _names_packed_as_callee(
            expr,
            projection_aliases=operator_projection_aliases,
            getattr_aliases=frozenset(getattr_aliases),
            partial_aliases=frozenset(partial_aliases),
            adapter_aliases=frozenset(adapter_aliases),
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
            elif isinstance(value, ast.Name):
                projection_factory_products.pop(name, None)
                partial_product_names.pop(name, None)
            return
        ag = _attrgetter_static_name(
            value, projection_aliases=operator_projection_aliases
        )
        if ag is not None:
            projection_factory_products[name] = ("attrgetter", ag)
            partial_product_names.pop(name, None)
            return
        ig = _itemgetter_static_key(
            value, projection_aliases=operator_projection_aliases
        )
        if ig is not None:
            projection_factory_products[name] = ("itemgetter", ig)
            partial_product_names.pop(name, None)
            return
        mc = _methodcaller_static_name(
            value, projection_aliases=operator_projection_aliases
        )
        if mc is not None:
            projection_factory_products[name] = ("methodcaller", mc)
            partial_product_names.pop(name, None)
            return
        if _is_partial_factory(value, partial_aliases=frozenset(partial_aliases)):
            packed = _packed_names(value.args[0]) if value.args else []
            projection_factory_products[name] = ("partial", None)
            partial_product_names[name] = packed
            return
        projection_factory_products.pop(name, None)
        partial_product_names.pop(name, None)

    def _note_adapter_from_subscript(name: str, value: ast.AST) -> None:
        """``Proxy = vars(types)["MappingProxyType"]`` / ``types.__dict__[…]``."""

        if not isinstance(value, ast.Subscript):
            return
        key = _static_str(value.slice)
        if key is None:
            return
        base = value.value
        ns_proj = False
        if isinstance(base, ast.Attribute) and base.attr == "__dict__":
            ns_proj = True
        elif isinstance(base, ast.Call):
            bfunc = _peel_call_func(base.func)
            if isinstance(bfunc, ast.Name) and bfunc.id in {
                "vars",
                "globals",
                "locals",
            }:
                ns_proj = True
            elif isinstance(bfunc, ast.Attribute) and bfunc.attr in {
                "vars",
                "globals",
                "locals",
            }:
                ns_proj = True
        if not ns_proj:
            return
        if key == "MappingProxyType":
            adapter_aliases.add(name)
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

    def _note_protocol_alias_from_value(name: str, value: ast.AST) -> None:
        """Install exec/new_class/type/getattr aliases from an Assign/walrus RHS."""

        value = _peel_call_func(value)
        if isinstance(value, ast.Name):
            if value.id in _EXEC_EVAL_COMPILE_NAMES or value.id in exec_eval_compile_aliases:
                exec_eval_compile_aliases.add(name)
            if value.id == _TYPES_NEW_CLASS_NAME or value.id in new_class_aliases:
                new_class_aliases.add(name)
            if value.id == _TYPE_BUILTIN_NAME or value.id in type_aliases:
                type_aliases.add(name)
            if value.id in getattr_aliases:
                getattr_aliases.add(name)
            if value.id in partial_aliases:
                partial_aliases.add(name)
            if value.id in _CALLEE_ADAPTER_NAMES or value.id in adapter_aliases:
                if value.id == "MappingProxyType" or value.id in adapter_aliases:
                    adapter_aliases.add(name)
            if value.id in _OPERATOR_PROJECTION_NAMES:
                operator_projection_aliases[name] = value.id
            elif value.id in operator_projection_aliases:
                operator_projection_aliases[name] = operator_projection_aliases[value.id]
            _note_factory_product_from_value(name, value)
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
            if value.attr == "MappingProxyType":
                adapter_aliases.add(name)
            if value.attr in _OPERATOR_PROJECTION_NAMES:
                operator_projection_aliases[name] = value.attr
            return
        if isinstance(value, ast.Subscript):
            _note_adapter_from_subscript(name, value)
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
            if attr in _OPERATOR_PROJECTION_NAMES:
                operator_projection_aliases[name] = attr
            _note_factory_product_from_value(name, value)

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
        for stmt in fn_node.body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                nested_fns[stmt.name] = stmt
            elif isinstance(stmt, ast.ClassDef):
                nested_classes[stmt.name] = stmt
                class_registry[stmt.name] = stmt
        _scan_stmts(
            fn_node.body,
            path=path,
            index=index,
            env=call_env,
            visited_fns=visited_fns,
            local_fns=nested_fns,
            local_classes=nested_classes,
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
                elif alias.name in _OPERATOR_PROJECTION_NAMES:
                    # ``from operator import itemgetter as ig`` / ``call as opcall``.
                    operator_projection_aliases[local] = alias.name
                elif alias.name == "partial":
                    partial_aliases.add(local)
                elif alias.name == "MappingProxyType":
                    adapter_aliases.add(local)
                elif alias.name == "getattr":
                    getattr_aliases.add(local)
                if module_path is None:
                    env[local] = _IdentityPointsTo.unknown_only()
                else:
                    env[local] = _IdentityPointsTo.precise(
                        CallableObject(module_path, alias.name)
                    )
        elif isinstance(node, ast.Import):
            for alias in node.names:
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
                    top = alias.name.split(".", 1)[0]
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
            for i, arg in enumerate(call.args):
                if isinstance(arg, ast.Starred):
                    _escape_if_tracked(_eval_expr(arg.value, env, path=path))
                    continue
                if i < len(pos_params):
                    call_env[pos_params[i]] = _eval_expr(arg, env, path=path)
                    bound_pos.add(i)
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
                    if isinstance(default_expr, ast.Lambda):
                        saved_lambda_bindings.setdefault(
                            name, lambda_bindings.get(name)
                        )
                        lambda_bindings[name] = default_expr
                else:
                    call_env[name] = _IdentityPointsTo.unknown_only()
            provided_kw: set[str] = set()
            for kw in call.keywords:
                if kw.arg is None:
                    _escape_if_tracked(_eval_expr(kw.value, env, path=path))
                    continue
                provided_kw.add(kw.arg)
                if kw.arg in pos_params or kw.arg in kwonly_params:
                    call_env[kw.arg] = _eval_expr(kw.value, env, path=path)
                    if isinstance(kw.value, ast.Lambda):
                        saved_lambda_bindings.setdefault(
                            kw.arg, lambda_bindings.get(kw.arg)
                        )
                        lambda_bindings[kw.arg] = kw.value
                else:
                    _escape_if_tracked(_eval_expr(kw.value, env, path=path))
            for name, default in zip(kwonly_params, func.args.kw_defaults):
                if name in provided_kw:
                    continue
                if default is not None:
                    call_env[name] = _eval_expr(default, env, path=path)
                    if isinstance(default, ast.Lambda):
                        saved_lambda_bindings.setdefault(
                            name, lambda_bindings.get(name)
                        )
                        lambda_bindings[name] = default
                else:
                    call_env[name] = _IdentityPointsTo.unknown_only()
            if func.args.vararg is not None:
                call_env[func.args.vararg.arg] = _IdentityPointsTo.unknown_only()
            if func.args.kwarg is not None:
                call_env[func.args.kwarg.arg] = _IdentityPointsTo.unknown_only()
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
        # Bound method alias: ``p = Mut().poison; p()``.
        if isinstance(func, ast.Name) and func.id in method_bindings:
            _scan_fn_body(
                method_bindings[func.id],
                path=path,
                index=index,
                env=env,
                visited_fns=visited_fns,
                local_fns=local_fns,
                local_classes=local_classes,
                formals=_formal_bindings_for_call(
                    call, method_bindings[func.id], env, path=path
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

        if isinstance(func, ast.Call):
            # Shared packing/projection peel: .get/.pop/getattr/attrgetter/
            # itemgetter/getitem/methodcaller/partial/next(iter)/…
            if _observe_classes_from_names(_packed_names(func)):
                for arg in call.args:
                    _escape_if_tracked(_eval_expr(arg, env, path=path))
                for kw in call.keywords:
                    _escape_if_tracked(_eval_expr(kw.value, env, path=path))
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
                if isinstance(func.value, ast.Name):
                    if (
                        func.value.id == _TYPE_BUILTIN_NAME
                        or func.value.id in type_aliases
                    ):
                        type_call_recv = True
                    else:
                        cls_node = _lookup_class(func.value.id, local_classes)
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
                elif isinstance(func.value, ast.Attribute) and func.value.attr in {
                    "__class__",
                    _TYPE_BUILTIN_NAME,
                }:
                    # ``object.__class__.__call__(Mut)`` / ``x.type.__call__(…)``.
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
            method = _resolve_attribute_method(
                func, local_classes=local_classes
            )
            if method is not None:
                scan_classes = dict(local_classes or {})
                if _method_has_decorator(method, frozenset({"classmethod"})):
                    owner = _resolve_receiver_class(
                        func.value, local_classes=local_classes
                    )
                    if owner is not None and method.args.args:
                        scan_classes[method.args.args[0].arg] = owner
                _scan_fn_body(
                    method,
                    path=path,
                    index=index,
                    env=env,
                    visited_fns=visited_fns,
                    local_fns=local_fns,
                    local_classes=scan_classes,
                    formals=_formal_bindings_for_call(
                        call, method, env, path=path
                    ),
                )
                return
            # Factory / opaque receivers: may-execute every registered method
            # with this name (Unknown > false PASS).
            if _follow_methods_named(
                func.attr,
                call,
                path=path,
                index=index,
                env=env,
                visited_fns=visited_fns,
                local_fns=local_fns,
                local_classes=local_classes,
            ):
                return
            # ModuleNamespace method receivers (e.g. d.get) escape; ModuleObject
            # receivers of ordinary calls do not.
            receiver = _eval_expr(func.value, env, path=path)
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
        # Name-bound factory product: ``p = partial(Mut); p()`` /
        # ``mc = methodcaller("poison"); mc(obj)``.
        if _observe_name_bound_factory_product(func.id):
            return
        if func.id in _BENIGN_BUILTINS:
            # Container / higher-order builtins must still evaluate arguments so
            # ``list(genexp)``, ``map(fn, …)`` cannot hide request-time mutations.
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
                # ``map(lambda c: c(), [Mut])`` — observe per-element class
                # construction from iterable packing (Unknown > false PASS).
                for arg in call.args[1:]:
                    _eval_expr(arg, env, path=path)
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
            # ``operator.call(exec, ...)`` / Name aliases of ``call`` MUST be
            # checked before the bare-Name short-circuit — otherwise
            # ``from operator import call as oc; oc(exec, ...)`` false-PASSes.
            if _is_operator_call_factory(
                call,
                projection_aliases=operator_projection_aliases,
                getattr_aliases=frozenset(getattr_aliases),
            ):
                if call.args:
                    for name in _packed_names(call.args[0]):
                        if _name_is_exec_eval_compile(name):
                            return True
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
                            for n in base_names
                        ):
                            return True
                        if isinstance(base.func, ast.Name) and (
                            base.func.id in {"vars", "globals", "locals"}
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
        setattr_parts = _setattr_target_and_name(call)
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
            if isinstance(call.func, ast.Name) and call.func.id == "setattr":
                if len(call.args) >= 3:
                    _eval_expr(call.args[2], env, path=path)
            elif isinstance(call.func, ast.Attribute) and call.func.attr == "__setattr__":
                if (
                    isinstance(call.func.value, ast.Name)
                    and call.func.value.id == "object"
                ):
                    if len(call.args) >= 3:
                        _eval_expr(call.args[2], env, path=path)
                elif len(call.args) >= 2:
                    _eval_expr(call.args[1], env, path=path)
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
    ) -> None:
        # Mutable nested-def / class maps for this statement sequence.
        active_fns: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = dict(
            local_fns or {}
        )
        active_classes: dict[str, ast.ClassDef] = dict(local_classes or {})
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
                    # Name-bound lambdas / bound methods followed on later calls.
                    if isinstance(target, ast.Name):
                        _note_protocol_alias_from_value(target.id, stmt.value)
                        if isinstance(stmt.value, ast.Lambda):
                            lambda_bindings[target.id] = stmt.value
                            method_bindings.pop(target.id, None)
                            instance_class_of.pop(target.id, None)
                        elif isinstance(stmt.value, ast.Attribute):
                            lambda_bindings.pop(target.id, None)
                            instance_class_of.pop(target.id, None)
                            method = _resolve_attribute_method(
                                stmt.value, local_classes=active_classes
                            )
                            if method is not None:
                                method_bindings[target.id] = method
                            else:
                                method_bindings.pop(target.id, None)
                        elif (
                            isinstance(stmt.value, ast.Call)
                            and isinstance(stmt.value.func, ast.Name)
                            and _lookup_class(stmt.value.func.id, active_classes)
                            is not None
                        ):
                            lambda_bindings.pop(target.id, None)
                            method_bindings.pop(target.id, None)
                            instance_class_of[target.id] = stmt.value.func.id
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
                continue
            if isinstance(stmt, ast.AugAssign):
                # RHS executes (``x += poison()``) before the store.
                _eval_expr(stmt.value, env, path=path)
                if isinstance(stmt.target, ast.Name):
                    # Name += rebinds / replaces the local; treat as severed
                    # bottom so a later attr write does not spelling-poison.
                    env[stmt.target.id] = _IdentityPointsTo.bottom()
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
                    # ``match Base: case x: class C(x)`` — identity-bind class
                    # aliases through MatchAs so ``__init_subclass__`` observes.
                    if (
                        isinstance(case.pattern, ast.MatchAs)
                        and case.pattern.name
                        and case.pattern.pattern is None
                        and isinstance(stmt.subject, ast.Name)
                    ):
                        src_cls = _lookup_class(stmt.subject.id, active_classes)
                        if src_cls is not None:
                            active_classes[case.pattern.name] = src_cls
                            class_registry[case.pattern.name] = src_cls
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

    class _IdentityScanner:
        pass

    scanner = _IdentityScanner()
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
