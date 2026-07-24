"""Express source-grounded authorization compiler.

Supports:
* ``express.Router()`` and ``app.use`` mounting
* middleware order on routers/app
* route handlers (``get/post/...``)
* imported middleware identities
* common auth/role checks (``requireAuth``, ``requireAdmin``, role arrays)

Dynamic paths and unrecognized middleware are marked unsupported.
"""

from __future__ import annotations

import re

from ovk.compilers.authorization.base import line_span, looks_admin_protected, normalize_path
from ovk.compilers.authorization.ir import AuthCheck, AuthDependency, AuthMount, AuthRoute, AuthorizationIR
from ovk.compilers.authorization.material_loader import AuthMaterials

_ROUTER = re.compile(r"(?:const|let|var)\s+(?P<name>\w+)\s*=\s*(?:express\.)?Router\(\)")
_APP_USE = re.compile(
    r"(?P<app>\w+)\.use\(\s*(?:['\"](?P<prefix>[^'\"]+)['\"]\s*,\s*)?(?P<target>\w+)",
)
_ROUTE = re.compile(
    r"(?P<app>\w+)\.(?P<method>get|post|put|patch|delete|use)\(\s*['\"](?P<path>[^'\"]+)['\"]\s*,(?P<rest>[^)]*)\)",
    re.IGNORECASE | re.DOTALL,
)
_IMPORT = re.compile(
    r"(?:const|let|var)\s+(?:\{[^}]*\b(?P<named>\w+)\b[^}]*\}|(?P<default>\w+))\s*=\s*require\(['\"](?P<mod>[^'\"]+)['\"]\)"
    r"|import\s+(?:\{[^}]*\b(?P<imnamed>\w+)\b[^}]*\}|(?P<imdefault>\w+))\s+from\s+['\"](?P<immod>[^'\"]+)['\"]"
)
_DYNAMIC = re.compile(r"\.(?:get|post|put|patch|delete)\(\s*(?![`'\"]).+?\)")


class ExpressAuthorizationCompiler:
    framework = "express"

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
            framework="express",
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
            for match in _IMPORT.finditer(source):
                name = (
                    match.group("named") or match.group("default") or match.group("imnamed") or match.group("imdefault")
                )
                mod = match.group("mod") or match.group("immod")
                if not name:
                    continue
                roles = ["admin"] if looks_admin_protected(name) else []
                dependencies[name] = AuthDependency(
                    name=name,
                    kind="middleware",
                    imported_from=mod,
                    role_checks=roles,
                )

            for match in _ROUTER.finditer(source):
                routers[match.group("name")] = ""

            for match in _APP_USE.finditer(source):
                prefix = match.group("prefix") or ""
                target = match.group("target")
                mounts[f"{path}:use:{target}:{prefix}"] = AuthMount(
                    mount_id=f"{path}:use:{target}:{prefix}",
                    prefix=prefix,
                    middleware=[target],
                    included_router=target if target in routers else None,
                )
                if target in routers:
                    routers[target] = prefix

            if _DYNAMIC.search(source):
                unsupported.append(f"{path}:dynamic_route_path")

            for match in _ROUTE.finditer(source):
                app = match.group("app")
                method = match.group("method").upper()
                if method == "USE":
                    continue
                route_path = match.group("path")
                rest = match.group("rest") or ""
                prefix = routers.get(app, "")
                full_path = normalize_path(prefix, route_path)
                middleware_names = [item.strip() for item in rest.split(",") if item.strip()]
                # Drop trailing handler arrow/function literal names heuristically.
                checks: list[AuthCheck] = []
                deps: list[str] = []
                admin = False
                for raw in middleware_names[:-1] if len(middleware_names) > 1 else middleware_names:
                    name = re.sub(r"[^\w].*$", "", raw.strip())
                    if not name or name in {"async", "function"}:
                        if looks_admin_protected(raw):
                            admin = True
                            checks.append(
                                AuthCheck(
                                    kind="inline_guard",
                                    expression=raw.strip()[:120],
                                    roles=["admin"],
                                    support="dynamic",
                                )
                            )
                            unsupported.append(f"{path}:inline_dynamic_guard")
                        continue
                    deps.append(name)
                    meta = dependencies.get(name)
                    roles = list(meta.role_checks) if meta else ([] if not looks_admin_protected(name) else ["admin"])
                    if roles or looks_admin_protected(name):
                        admin = True
                        roles = roles or ["admin"]
                    checks.append(
                        AuthCheck(
                            kind="middleware",
                            expression=name,
                            roles=roles,
                            span=line_span(source, match.start(), match.end(), path),
                        )
                    )
                if looks_admin_protected(rest):
                    admin = True
                key = (full_path, method)
                route_map[key] = {
                    "path": full_path,
                    "method": method,
                    "handler": middleware_names[-1].strip()[:80] if middleware_names else None,
                    "prefixes": [prefix] if prefix else [],
                    "checks": checks,
                    "dependencies": deps,
                    "admin_only": admin,
                    "support": "supported",
                    "unsupported": [],
                    "span": line_span(source, match.start(), match.end(), path),
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
                    route_id=f"express:{path}:{method}:{index}",
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
