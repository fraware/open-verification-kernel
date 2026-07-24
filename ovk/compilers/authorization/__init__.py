"""Source-grounded authorization compilers package."""

from __future__ import annotations

from ovk.compilers.authorization.coverage import CoveragePolicy, assess_coverage, strict_allow_permitted
from ovk.compilers.authorization.express import ExpressAuthorizationCompiler
from ovk.compilers.authorization.fastapi import FastApiAuthorizationCompiler
from ovk.compilers.authorization.fastapi_ast import FastApiAstAuthorizationCompiler
from ovk.compilers.authorization.ir import AuthorizationIR
from ovk.compilers.authorization.material_loader import (
    AuthMaterials,
    load_materials_from_dirs,
    materials_from_pair,
)

__all__ = [
    "AuthMaterials",
    "AuthorizationIR",
    "CoveragePolicy",
    "ExpressAuthorizationCompiler",
    "FastApiAstAuthorizationCompiler",
    "FastApiAuthorizationCompiler",
    "assess_coverage",
    "load_materials_from_dirs",
    "materials_from_pair",
    "strict_allow_permitted",
]
