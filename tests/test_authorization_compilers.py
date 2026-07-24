"""Tests for source-grounded authorization compilers and coverage policy."""

from __future__ import annotations

from ovk.compilers.authorization import (
    CoveragePolicy,
    ExpressAuthorizationCompiler,
    FastApiAuthorizationCompiler,
    assess_coverage,
    materials_from_pair,
    strict_allow_permitted,
)
from ovk.compilers.authorization.corpus import TARGET, build_corpus, classify_case


def test_fastapi_preserves_admin_depends() -> None:
    base = """
from fastapi import Depends, FastAPI
def require_admin():
    return "admin"
app = FastAPI()
@app.get("/admin/users", dependencies=[Depends(require_admin)])
def users():
    return []
""".strip()
    materials = materials_from_pair(path="app.py", base_source=base, head_source=base)
    ir = FastApiAuthorizationCompiler().compile(materials)
    assert ir.framework == "fastapi"
    assert ir.routes
    assert ir.routes[0].admin_only_before is True
    assert ir.routes[0].admin_only_after is True
    coverage = assess_coverage(ir, materials)
    assert coverage.status == "complete"
    assert strict_allow_permitted(coverage) is True


def test_fastapi_detects_admin_bypass() -> None:
    base = """
from fastapi import Depends, FastAPI
def require_admin():
    return "admin"
app = FastAPI()
@app.get("/admin/users", dependencies=[Depends(require_admin)])
def users():
    return []
""".strip()
    head = """
from fastapi import FastAPI
app = FastAPI()
@app.get("/admin/users")
def users():
    return []
""".strip()
    materials = materials_from_pair(path="app.py", base_source=base, head_source=head)
    ir = FastApiAuthorizationCompiler().compile(materials)
    assert any(route.admin_only_before and not route.admin_only_after for route in ir.routes)
    lane = ir.to_lane_input()
    assert lane["routes"][0]["reachable_after"]


def test_fastapi_include_router_prefix() -> None:
    source = (
        "from fastapi import APIRouter, Depends, FastAPI\n"
        "def require_admin():\n"
        "    return 'admin'\n"
        "router = APIRouter(prefix='/v1')\n"
        "@router.get('/admin', dependencies=[Depends(require_admin)])\n"
        "def admin():\n"
        "    return {}\n"
        "app = FastAPI()\n"
        "app.include_router(router, prefix='/api')\n"
    )
    materials = materials_from_pair(path="app.py", base_source=source, head_source=source)
    ir = FastApiAuthorizationCompiler().compile(materials)
    assert any(route.path.endswith("/admin") for route in ir.routes)
    assert ir.mounts


def test_express_middleware_order_and_import() -> None:
    source = """
const express = require('express');
const { requireAdmin } = require('./auth');
const router = express.Router();
router.get('/admin/users', requireAdmin, (req, res) => res.json([]));
const app = express();
app.use('/api', router);
""".strip()
    materials = materials_from_pair(path="app.js", base_source=source, head_source=source)
    ir = ExpressAuthorizationCompiler().compile(materials)
    assert ir.routes
    assert ir.routes[0].admin_only_after is True
    assert any(dep.imported_from == "./auth" for dep in ir.dependencies)


def test_express_detects_middleware_removal() -> None:
    base = """
const express = require('express');
const { requireAdmin } = require('./auth');
const app = express();
app.get('/admin', requireAdmin, (req, res) => res.end());
""".strip()
    head = """
const express = require('express');
const app = express();
app.get('/admin', (req, res) => res.end());
""".strip()
    materials = materials_from_pair(path="app.js", base_source=base, head_source=head)
    ir = ExpressAuthorizationCompiler().compile(materials)
    assert any(route.admin_only_before and not route.admin_only_after for route in ir.routes)


def test_missing_base_is_unknown_coverage() -> None:
    head = """
from fastapi import FastAPI
app = FastAPI()
@app.get("/x")
def x():
    return 1
""".strip()
    materials = materials_from_pair(path="app.py", base_source=None, head_source=head)
    ir = FastApiAuthorizationCompiler().compile(materials)
    coverage = assess_coverage(ir, materials)
    assert coverage.status == "unknown"
    assert strict_allow_permitted(coverage) is False


def test_partial_requires_explicit_policy_for_strict_allow() -> None:
    source = """
from fastapi import FastAPI
app = FastAPI()
PATH = "/dyn"
@app.get(PATH)
def dyn():
    return {}
""".strip()
    materials = materials_from_pair(path="app.py", base_source=source, head_source=source)
    ir = FastApiAuthorizationCompiler().compile(materials)
    coverage = assess_coverage(ir, materials)
    assert coverage.status in {"partial", "complete", "unknown"}
    if coverage.status == "partial":
        assert strict_allow_permitted(coverage) is False
        assert strict_allow_permitted(coverage, CoveragePolicy(accept_partial_coverage=True)) is True


def test_does_not_infer_before_from_post_image_only() -> None:
    head = """
from fastapi import Depends, FastAPI
def require_admin():
    return "admin"
app = FastAPI()
@app.get("/admin", dependencies=[Depends(require_admin)])
def admin():
    return {}
""".strip()
    materials = materials_from_pair(path="app.py", base_source=None, head_source=head)
    ir = FastApiAuthorizationCompiler().compile(materials)
    # Without base materials, before must not be invented as protected.
    assert all(route.admin_only_before is False for route in ir.routes)
    assert any(route.admin_only_after for route in ir.routes)


def test_acceptance_corpus_meets_program_targets() -> None:
    cases = build_corpus(meet_targets=True)
    by_framework = {
        "fastapi": {"pass": 0, "fail": 0, "incomplete": 0},
        "express": {"pass": 0, "fail": 0, "incomplete": 0},
    }
    for case in cases:
        classified = classify_case(case)
        assert classified == case.category, f"{case.case_id} expected {case.category} got {classified}"
        by_framework[case.framework][case.category] += 1
    for framework, counts in by_framework.items():
        assert counts["pass"] == TARGET["pass"], framework
        assert counts["fail"] == TARGET["fail"], framework
        assert counts["incomplete"] == TARGET["incomplete"], framework
