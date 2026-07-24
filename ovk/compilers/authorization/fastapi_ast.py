"""AST-based FastAPI authorization compiler (profile ``authorization.fastapi.ast_v1``).

Prefer this over the regex FastAPI compiler when source profiles are enabled.
Dynamic path construction, runtime-computed dependencies, and unrecognized
auth helpers are marked ``dynamic`` / ``unsupported``.
"""

from __future__ import annotations

import ast
from typing import Any

from ovk.compilers.authorization.base import looks_admin_protected, normalize_path
from ovk.compilers.authorization.ir import (
    AuthCheck,
    AuthDependency,
    AuthMount,
    AuthRoute,
    AuthorizationIR,
    SourceSpan,
)
from ovk.compilers.authorization.material_loader import AuthMaterials

_HTTP_METHODS = frozenset({"get", "post", "put", "patch", "delete", "options", "head"})
_SOURCE_PROFILE_ID = "authorization.fastapi.ast_v1"


def _const_str(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _name_of(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _call_name(node: ast.Call) -> str | None:
    return _name_of(node.func)


def _kw_str(call: ast.Call, name: str) -> str | None:
    for keyword in call.keywords:
        if keyword.arg == name:
            return _const_str(keyword.value)
    return None


def _depends_names(node: ast.AST | None) -> list[str]:
    found: list[str] = []
    if node is None:
        return found
    for child in ast.walk(node):
        if isinstance(child, ast.Call) and _call_name(child) == "Depends" and child.args:
            dep = _name_of(child.args[0])
            if dep:
                found.append(dep)
    return found


def _span(path: str, node: ast.AST) -> SourceSpan:
    return SourceSpan(
        path=path,
        start_line=getattr(node, "lineno", None),
        end_line=getattr(node, "end_lineno", getattr(node, "lineno", None)),
    )


class FastApiAstAuthorizationCompiler:
    """Compile FastAPI sources via the Python AST (not regex)."""

    framework = "fastapi"
    source_profile_id = _SOURCE_PROFILE_ID

    def compile(self, materials: AuthMaterials) -> AuthorizationIR:
        base_index = self._index(materials.base_files)
        head_index = self._index(materials.head_files)
        routes = self._merge_routes(base_index, head_index)
        mounts = sorted(
            {**base_index["mounts"], **head_index["mounts"]}.values(),
            key=lambda item: item.mount_id,
        )
        dependencies = sorted(
            {**base_index["dependencies"], **head_index["dependencies"]}.values(),
            key=lambda item: item.name,
        )
        unsupported = sorted(set(base_index["unsupported"] + head_index["unsupported"]))
        warnings: list[str] = [f"compiled_with_source_profile:{_SOURCE_PROFILE_ID}"]
        if not materials.has_base():
            warnings.append("base materials missing")
        if not materials.has_head():
            warnings.append("head materials missing")
        return AuthorizationIR(
            framework="fastapi",
            subject_repo=materials.repo,
            base_revision=materials.base_revision,
            head_revision=materials.head_revision,
            routes=sorted(routes, key=lambda item: (item.path, ",".join(item.methods), item.route_id)),
            mounts=list(mounts),
            dependencies=list(dependencies),
            unsupported_constructs=unsupported,
            warnings=warnings,
            materials=materials.paths,
        )

    def _index(self, files: dict[str, str]) -> dict[str, Any]:
        routers: dict[str, str] = {}
        mounts: dict[str, AuthMount] = {}
        dependencies: dict[str, AuthDependency] = {}
        route_map: dict[tuple[str, str], dict[str, Any]] = {}
        unsupported: list[str] = []

        for path, source in sorted(files.items()):
            try:
                tree = ast.parse(source, filename=path)
            except SyntaxError as exc:
                unsupported.append(f"{path}:syntax_error:{exc.msg}")
                continue

            for node in tree.body:
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    roles = ["admin"] if looks_admin_protected(ast.get_source_segment(source, node) or node.name) else []
                    dependencies[node.name] = AuthDependency(
                        name=node.name,
                        kind="dependency",
                        role_checks=roles,
                        support="supported",
                    )

            for node in ast.walk(tree):
                if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
                    if _call_name(node.value) == "APIRouter":
                        for target in node.targets:
                            name = _name_of(target)
                            if not name:
                                continue
                            prefix = _kw_str(node.value, "prefix") or ""
                            routers[name] = prefix
                            deps = _depends_names(node.value)
                            if deps:
                                mounts[f"{path}:{name}"] = AuthMount(
                                    mount_id=f"{path}:{name}",
                                    prefix=prefix,
                                    middleware=deps,
                                    included_router=name,
                                )

                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                    if node.func.attr == "include_router" and node.args:
                        router = _name_of(node.args[0])
                        if not router:
                            continue
                        prefix = _kw_str(node, "prefix") or routers.get(router, "")
                        mounts[f"{path}:include:{router}"] = AuthMount(
                            mount_id=f"{path}:include:{router}",
                            prefix=prefix,
                            included_router=router,
                        )
                        routers.setdefault(router, prefix)

                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    for decorator in node.decorator_list:
                        route = self._route_from_decorator(
                            decorator,
                            handler=node,
                            path=path,
                            source=source,
                            routers=routers,
                            dependencies=dependencies,
                            unsupported=unsupported,
                        )
                        if route is None:
                            continue
                        key = (route["path"], route["method"])
                        route_map[key] = route

        return {
            "routes": route_map,
            "mounts": mounts,
            "dependencies": dependencies,
            "unsupported": unsupported,
        }

    def _route_from_decorator(
        self,
        decorator: ast.AST,
        *,
        handler: ast.AST,
        path: str,
        source: str,
        routers: dict[str, str],
        dependencies: dict[str, AuthDependency],
        unsupported: list[str],
    ) -> dict[str, Any] | None:
        if not isinstance(decorator, ast.Call) or not isinstance(decorator.func, ast.Attribute):
            return None
        method = decorator.func.attr.lower()
        if method not in _HTTP_METHODS:
            return None
        app = _name_of(decorator.func.value) or "app"
        if not decorator.args:
            unsupported.append(f"{path}:dynamic_route_path")
            return None
        route_path = _const_str(decorator.args[0])
        if route_path is None:
            unsupported.append(f"{path}:dynamic_route_path")
            return None

        prefix = routers.get(app, "")
        full_path = normalize_path(prefix, route_path)
        deps = _depends_names(decorator)
        # Also inspect handler signature defaults for Depends(...).
        if isinstance(handler, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for arg in list(handler.args.args) + list(handler.args.kwonlyargs):
                deps.extend(_depends_names(arg.annotation))
            for default in list(handler.args.defaults) + list(handler.args.kw_defaults):
                deps.extend(_depends_names(default))
        # Deduplicate while preserving order.
        seen: set[str] = set()
        ordered_deps: list[str] = []
        for dep in deps:
            if dep not in seen:
                seen.add(dep)
                ordered_deps.append(dep)

        checks: list[AuthCheck] = []
        admin = False
        for dep in ordered_deps:
            dep_meta = dependencies.get(dep)
            roles = list(dep_meta.role_checks) if dep_meta else []
            if looks_admin_protected(dep) or roles:
                admin = True
                roles = roles or ["admin"]
            checks.append(
                AuthCheck(
                    kind="dependency",
                    expression=f"Depends({dep})",
                    roles=roles,
                    span=_span(path, decorator),
                )
            )

        handler_name = getattr(handler, "name", None)
        if handler_name:
            handler_meta = dependencies.get(handler_name)
            if handler_meta and handler_meta.role_checks:
                admin = True
            body_text = ast.get_source_segment(source, handler) or ""
            if looks_admin_protected(body_text):
                admin = True

        return {
            "path": full_path,
            "method": method.upper(),
            "handler": handler_name,
            "prefixes": [prefix] if prefix else [],
            "checks": checks,
            "dependencies": ordered_deps,
            "admin_only": admin,
            "support": "supported",
            "unsupported": [],
            "span": _span(path, decorator),
            "source_path": path,
        }

    def _merge_routes(self, base_index: dict[str, Any], head_index: dict[str, Any]) -> list[AuthRoute]:
        keys = sorted(set(base_index["routes"]) | set(head_index["routes"]))
        routes: list[AuthRoute] = []
        for index, key in enumerate(keys):
            before = base_index["routes"].get(key)
            after = head_index["routes"].get(key)
            path = (after or before)["path"]
            method = (after or before)["method"]
            routes.append(
                AuthRoute(
                    route_id=f"fastapi-ast:{path}:{method}:{index}",
                    methods=[method],
                    path=path,
                    handler=(after or before).get("handler"),
                    router_prefixes=(after or before).get("prefixes") or [],
                    checks_before=list((before or {}).get("checks") or []),
                    checks_after=list((after or {}).get("checks") or []),
                    dependencies_before=list((before or {}).get("dependencies") or []),
                    dependencies_after=list((after or {}).get("dependencies") or []),
                    admin_only_before=bool((before or {}).get("admin_only")),
                    admin_only_after=bool((after or {}).get("admin_only")),
                    support=(after or before).get("support", "supported"),
                    unsupported_constructs=list((after or before).get("unsupported") or []),
                    span=(after or before).get("span"),
                )
            )
        return routes
