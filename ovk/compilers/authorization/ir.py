"""Canonical authorization intermediate representation.

Reconstruction is always base+head material based. Compilers must not infer
``before`` protections solely from a post-image.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

AuthFramework = Literal["fastapi", "express", "unknown"]
RouteSupport = Literal["supported", "dynamic", "unsupported"]
CheckKind = Literal[
    "role_required",
    "permission_required",
    "dependency",
    "middleware",
    "decorator",
    "inline_guard",
    "unknown",
]


class SourceSpan(BaseModel):
    """Source location within a material file."""

    path: str
    start_line: int | None = None
    end_line: int | None = None


class AuthDependency(BaseModel):
    """Named dependency or middleware identity."""

    name: str
    kind: CheckKind = "dependency"
    imported_from: str | None = None
    role_checks: list[str] = Field(default_factory=list)
    support: RouteSupport = "supported"
    notes: list[str] = Field(default_factory=list)


class AuthCheck(BaseModel):
    """An authorization check attached to a route or mount."""

    kind: CheckKind
    expression: str
    roles: list[str] = Field(default_factory=list)
    support: RouteSupport = "supported"
    span: SourceSpan | None = None


class AuthRoute(BaseModel):
    """One HTTP route with reconstructed before/after protection."""

    route_id: str
    methods: list[str] = Field(default_factory=list)
    path: str
    handler: str | None = None
    router_prefixes: list[str] = Field(default_factory=list)
    checks_before: list[AuthCheck] = Field(default_factory=list)
    checks_after: list[AuthCheck] = Field(default_factory=list)
    dependencies_before: list[str] = Field(default_factory=list)
    dependencies_after: list[str] = Field(default_factory=list)
    admin_only_before: bool = False
    admin_only_after: bool = False
    support: RouteSupport = "supported"
    unsupported_constructs: list[str] = Field(default_factory=list)
    span: SourceSpan | None = None


class AuthMount(BaseModel):
    """Router/app mount with prefix and middleware order."""

    mount_id: str
    prefix: str = ""
    middleware: list[str] = Field(default_factory=list)
    included_router: str | None = None
    support: RouteSupport = "supported"


class AuthorizationIR(BaseModel):
    """Framework-neutral authorization IR."""

    schema_version: Literal["ovk.authorization.ir.v1"] = "ovk.authorization.ir.v1"
    framework: AuthFramework
    subject_repo: str | None = None
    base_revision: str | None = None
    head_revision: str | None = None
    routes: list[AuthRoute] = Field(default_factory=list)
    mounts: list[AuthMount] = Field(default_factory=list)
    dependencies: list[AuthDependency] = Field(default_factory=list)
    unsupported_constructs: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    materials: list[str] = Field(default_factory=list)

    def sorted_routes(self) -> list[AuthRoute]:
        return sorted(self.routes, key=lambda item: (item.path, ",".join(item.methods), item.route_id))

    def to_lane_input(self) -> dict[str, Any]:
        """Project IR into the legacy authorization lane abstraction shape."""
        routes: list[dict[str, Any]] = []
        for route in self.sorted_routes():
            reachable_after: list[dict[str, Any]] = []
            if route.admin_only_before and not route.admin_only_after:
                reachable_after.append({"role": "user", "via": ["unprotected_after"]})
            routes.append(
                {
                    "path": route.path,
                    "admin_only_before": route.admin_only_before,
                    "admin_only_after": route.admin_only_after,
                    "reachable_after": reachable_after,
                    "methods": list(route.methods),
                    "support": route.support,
                }
            )
        return {
            "framework": self.framework,
            "routes": routes,
            "unsupported_constructs": list(self.unsupported_constructs),
            "warnings": list(self.warnings),
        }
