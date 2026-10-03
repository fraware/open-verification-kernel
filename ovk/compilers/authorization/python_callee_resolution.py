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

_IMPLEMENTATION_VERSION = "0.16.0"
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


def _attrsetter_static_name(call: ast.Call) -> str | None:
    """Return the static attribute name for ``operator.attrsetter("x")``."""

    func = call.func
    if isinstance(func, ast.Name) and func.id == "attrsetter" and call.args:
        return _static_str(call.args[0])
    if (
        isinstance(func, ast.Attribute)
        and func.attr == "attrsetter"
        and isinstance(func.value, ast.Name)
        and func.value.id == "operator"
        and call.args
    ):
        return _static_str(call.args[0])
    return None


def _methodcaller_static_name(call: ast.Call) -> str | None:
    """Return the static method name for ``operator.methodcaller("x")``."""

    func = call.func
    if isinstance(func, ast.Name) and func.id == "methodcaller" and call.args:
        return _static_str(call.args[0])
    if (
        isinstance(func, ast.Attribute)
        and func.attr == "methodcaller"
        and isinstance(func.value, ast.Name)
        and func.value.id == "operator"
        and call.args
    ):
        return _static_str(call.args[0])
    return None


def _getattr_static_name(call: ast.Call) -> str | None:
    """Return the static attribute name for ``getattr(obj, "x")``."""

    if not (
        isinstance(call.func, ast.Name)
        and call.func.id == "getattr"
        and len(call.args) >= 2
        and not call.keywords
    ):
        return None
    return _static_str(call.args[1])


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
        ``wrapper(poison())``, comprehensions, awaits) cannot diverge from
        statement-position call scanning.
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
            _scan_fn_body(
                method,
                path=path,
                index=index,
                env=env,
                visited_fns=visited_fns,
                local_fns=local_fns,
                local_classes=local_classes,
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
            return points
        if isinstance(expr, ast.IfExp):
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
            and expr.func.id == "getattr"
            and len(expr.args) >= 2
            and not expr.keywords
        ):
            # getattr(module, "export") may alias a callable; model when attr is
            # static, otherwise escape the receiver (Unknown > false PASS).
            owner = _eval_expr(expr.args[0], env, path=path)
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
            _escape_if_tracked(_eval_expr(expr.elt, env, path=path))
            for gen in expr.generators:
                _escape_if_tracked(_eval_expr(gen.iter, env, path=path))
                for if_clause in gen.ifs:
                    _escape_if_tracked(_eval_expr(if_clause, env, path=path))
            return _IdentityPointsTo.unknown_only()
        if isinstance(expr, ast.DictComp):
            _escape_if_tracked(_eval_expr(expr.key, env, path=path))
            _escape_if_tracked(_eval_expr(expr.value, env, path=path))
            for gen in expr.generators:
                _escape_if_tracked(_eval_expr(gen.iter, env, path=path))
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
            # Lambda body is not executed at definition time.
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
            # Bind lambda formals from actuals for the single expression body.
            params = [a.arg for a in func.args.args]
            if (
                func.args.vararg is None
                and func.args.kwarg is None
                and not func.args.posonlyargs
                and not func.args.kwonlyargs
                and len(call.args) <= len(params)
                and all(kw.arg is not None for kw in call.keywords)
            ):
                call_env = _copy_env(env)
                for i, arg in enumerate(call.args):
                    if i < len(params):
                        call_env[params[i]] = _eval_expr(arg, env, path=path)
                    else:
                        _escape_if_tracked(_eval_expr(arg, env, path=path))
                for kw in call.keywords:
                    assert kw.arg is not None
                    if kw.arg in params:
                        call_env[kw.arg] = _eval_expr(kw.value, env, path=path)
                    else:
                        _escape_if_tracked(_eval_expr(kw.value, env, path=path))
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
            else:
                for arg in call.args:
                    _escape_if_tracked(_eval_expr(arg, env, path=path))
                for kw in call.keywords:
                    _escape_if_tracked(_eval_expr(kw.value, env, path=path))
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
        if isinstance(func, ast.Call):
            # getattr(obj, "poison")() — follow the named method when static.
            getattr_name = _getattr_static_name(func)
            if getattr_name is not None:
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
            # operator.methodcaller("poison")(obj)
            methodcaller_name = _methodcaller_static_name(func)
            if methodcaller_name is not None:
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
            # Chained call ``make()()``: evaluate the callee expression first so
            # returned nested helpers still contribute mutation effects.
            _scan_call(
                func,
                path=path,
                index=index,
                env=env,
                visited_fns=visited_fns,
                local_fns=local_fns,
                local_classes=local_classes,
            )
            for arg in call.args:
                _escape_if_tracked(_eval_expr(arg, env, path=path))
            for kw in call.keywords:
                _escape_if_tracked(_eval_expr(kw.value, env, path=path))
            return
        if isinstance(func, ast.Attribute):
            # Method calls: Mut().poison() / Mut.poison() / instance.poison().
            method = _resolve_attribute_method(
                func, local_classes=local_classes
            )
            if method is not None:
                _scan_fn_body(
                    method,
                    path=path,
                    index=index,
                    env=env,
                    visited_fns=visited_fns,
                    local_fns=local_fns,
                    local_classes=local_classes,
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
        if func.id in _BENIGN_BUILTINS:
            # Container / higher-order builtins must still evaluate arguments so
            # ``list(genexp)``, ``map(fn, …)`` cannot hide request-time mutations.
            if func.id in {"map", "filter"} and call.args:
                synthetic = ast.Call(
                    func=call.args[0],
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
                for arg in call.args[1:]:
                    _eval_expr(arg, env, path=path)
                return
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
            # Unresolved / imported callee receiving module/callable actual.
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
        setattr_parts = _setattr_target_and_name(call)
        if setattr_parts is not None:
            obj, name_expr = setattr_parts
            attr = _static_str(name_expr)
            _mutate_through_expr(
                obj,
                export_name=attr,
                behavior=True,
                env=env,
                path=path,
                index=index,
            )
            return
        delattr_parts = _delattr_target_and_name(call)
        if delattr_parts is not None:
            obj, name_expr = delattr_parts
            attr = _static_str(name_expr)
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
                for base in stmt.bases:
                    _eval_expr(base, env, path=path)
                for kw in stmt.keywords:
                    _eval_expr(kw.value, env, path=path)
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
                if isinstance(stmt.target, ast.Name):
                    if isinstance(stmt.value, ast.Lambda):
                        lambda_bindings[stmt.target.id] = stmt.value
                    else:
                        lambda_bindings.pop(stmt.target.id, None)
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
                        _scan_assign_target(
                            target,
                            path=path,
                            index=index,
                            env=env,
                            value_points=None,
                        )
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
                # is unmodeled. Iterable always executes before zero-iteration
                # join (#173).
                _eval_expr(stmt.iter, env, path=path)
                _bind_target_names(
                    stmt.target, _IdentityPointsTo.unknown_only(), env
                )
                env_body = _copy_env(env)
                _scan_stmts(
                    list(stmt.body) + list(stmt.orelse),
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
            if isinstance(stmt, ast.While):
                # Test executes (at least once) before body / zero-iteration
                # join; nested short-circuit may-effects are conservative via
                # _eval_expr BoolOp / IfExp joins (#173).
                _eval_expr(stmt.test, env, path=path)
                env_body = _copy_env(env)
                _scan_stmts(
                    list(stmt.body) + list(stmt.orelse),
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
            if isinstance(stmt, (ast.With, ast.AsyncWith)):
                bound_as: set[str] = set()
                for item in stmt.items:
                    subject = _eval_expr(item.context_expr, env, path=path)
                    if item.optional_vars is not None:
                        # Unmodeled context-manager projection: escape subject
                        # identity and bind the target as unknown.
                        _escape_if_tracked(subject)
                        names = _collect_store_names(item.optional_vars)
                        bound_as.update(names)
                        _bind_target_names(
                            item.optional_vars,
                            _IdentityPointsTo.unknown_only(),
                            env,
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
                    pattern_names = _collect_match_pattern_names(case.pattern)
                    if pattern_names:
                        # Pattern bind is an unmodeled projection of subject.
                        _escape_if_tracked(subject)
                    for name in pattern_names:
                        env_c[name] = _IdentityPointsTo.unknown_only()
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
