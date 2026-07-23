"""FastAPI source-grounded authorization compiler.

Supports:
* ``APIRouter`` / ``FastAPI`` route decorators
* ``prefix=`` and ``include_router``
* ``Depends(...)`` dependency chains
* common role checks (``require_admin``, role comparisons)

Dynamic path construction, runtime-computed dependencies, and unrecognized
auth helpers are marked ``dynamic`` / ``unsupported``.
"""

from __future__ import annotations

import re
from collections import defaultdict

from ovk.compilers.authorization.base import (
    extract_string_literal,
    line_span,
    looks_admin_protected,
    normalize_path,
)
from ovk.compilers.authorization.ir import (
    AuthCheck,
    AuthDependency,
    AuthMount,
    AuthRoute,
    AuthorizationIR,
)
from ovk.compilers.authorization.material_loader import AuthMaterials

_ROUTE_DECORATOR = re.compile(
    r"@(?:(?P<app>\w+)\.)?(?P<method>get|post|put|patch|delete|options|head)\(\s*['\"](?P<path>[^'\"]+)['\"]"
    r"(?P<rest>[^)]*)\)",
    re.IGNORECASE | re.DOTALL,
)
_ROUTER_ASSIGN = re.compile(
    r"(?P<name>\w+)\s*=\s*APIRouter\((?P<args>[^)]*)\)",
    re.DOTALL,
)
_INCLUDE = re.compile(
    r"(?P<app>\w+)\.include_router\(\s*(?P<router>\w+)\s*(?:,\s*prefix\s*=\s*['\"](?P<prefix>[^'\"]+)['\"])?",
)
_DEPENDS = re.compile(r"Depends\(\s*(?P<name>\w+)\s*\)")
_DEF = re.compile(r"^(?:async\s+)?def\s+(?P<name>\w+)\s*\((?P<args>[^)]*)\)", re.MULTILINE)
_DYNAMIC_PATH = re.compile(r"@(?:get|post|put|patch|delete)\(\s*(?!\s*['\"])", re.IGNORECASE)


class FastApiAuthorizationCompiler:
    framework = "fastapi"

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
        warnings: list[str] = []
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

    def _index(self, files: dict[str, str]) -> dict:
        routers: dict[str, str] = {}
        mounts: dict[str, AuthMount] = {}
        dependencies: dict[str, AuthDependency] = {}
        route_map: dict[tuple[str, str], dict] = {}
        unsupported: list[str] = []

        for path, source in sorted(files.items()):
            for match in _ROUTER_ASSIGN.finditer(source):
                name = match.group("name")
                args = match.group("args") or ""
                prefixes = extract_string_literal(args, r"prefix\s*=\s*['\"]([^'\"]+)['\"]")
                routers[name] = prefixes[0] if prefixes else ""
                deps = _DEPENDS.findall(args)
                if deps:
                    mounts[f"{path}:{name}"] = AuthMount(
                        mount_id=f"{path}:{name}",
                        prefix=routers[name],
                        middleware=deps,
                        included_router=name,
                    )

            for match in _INCLUDE.finditer(source):
                router = match.group("router")
                prefix = match.group("prefix") or routers.get(router, "")
                mounts[f"{path}:include:{router}"] = AuthMount(
                    mount_id=f"{path}:include:{router}",
                    prefix=prefix,
                    included_router=router,
                )
                routers.setdefault(router, prefix)

            for match in _DEF.finditer(source):
                name = match.group("name")
                body_start = match.end()
                body = source[body_start : body_start + 400]
                roles = []
                if looks_admin_protected(match.group(0) + body):
                    roles = ["admin"]
                dependencies[name] = AuthDependency(
                    name=name,
                    kind="dependency",
                    role_checks=roles,
                    support="supported",
                )

            if _DYNAMIC_PATH.search(source):
                unsupported.append(f"{path}:dynamic_route_path")

            for match in _ROUTE_DECORATOR.finditer(source):
                app = match.group("app") or "app"
                method = match.group("method").upper()
                route_path = match.group("path")
                rest = match.group("rest") or ""
                prefix = routers.get(app, "")
                full_path = normalize_path(prefix, route_path)
                deps = _DEPENDS.findall(rest)
                checks: list[AuthCheck] = []
                admin = False
                for dep in deps:
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
                            span=line_span(source, match.start(), match.end(), path),
                        )
                    )
                if looks_admin_protected(rest):
                    admin = True
                    checks.append(
                        AuthCheck(
                            kind="decorator",
                            expression=rest.strip(),
                            roles=["admin"],
                            span=line_span(source, match.start(), match.end(), path),
                        )
                    )
                # Capture following def name as handler when present.
                after = source[match.end() : match.end() + 200]
                handler_match = re.search(r"(?:async\s+)?def\s+(\w+)", after)
                handler = handler_match.group(1) if handler_match else None
                if handler:
                    handler_meta = dependencies.get(handler)
                    if handler_meta and handler_meta.role_checks:
                        admin = True
                key = (full_path, method)
                route_map[key] = {
                    "path": full_path,
                    "method": method,
                    "handler": handler,
                    "prefixes": [prefix] if prefix else [],
                    "checks": checks,
                    "dependencies": deps,
                    "admin_only": admin,
                    "support": "supported",
                    "unsupported": [],
                    "span": line_span(source, match.start(), match.end(), path),
                    "source_path": path,
                }

        return {
            "routes": route_map,
            "mounts": mounts,
            "dependencies": dependencies,
            "unsupported": unsupported,
        }

    def _merge_routes(self, base_index: dict, head_index: dict) -> list[AuthRoute]:
        keys = sorted(set(base_index["routes"]) | set(head_index["routes"]))
        routes: list[AuthRoute] = []
        for index, key in enumerate(keys):
            before = base_index["routes"].get(key)
            after = head_index["routes"].get(key)
            path = (after or before)["path"]
            method = (after or before)["method"]
            routes.append(
                AuthRoute(
                    route_id=f"fastapi:{path}:{method}:{index}",
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
