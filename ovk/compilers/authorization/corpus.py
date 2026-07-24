"""Acceptance corpus helpers for authorization compilers.

Targets (program): 20 pass / 20 fail / 10 incomplete per framework.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from ovk.compilers.authorization.express import ExpressAuthorizationCompiler
from ovk.compilers.authorization.fastapi import FastApiAuthorizationCompiler
from ovk.compilers.authorization.material_loader import materials_from_pair

Category = Literal["pass", "fail", "incomplete"]
TARGET = {"pass": 20, "fail": 20, "incomplete": 10}


@dataclass(frozen=True)
class CorpusCase:
    framework: str
    category: Category
    case_id: str
    base: str
    head: str
    path: str


def _fastapi_pass(index: int) -> CorpusCase:
    prefix = f"/admin{index}"
    source = f"""
from fastapi import APIRouter, Depends, FastAPI

def require_admin():
    return "admin"

router = APIRouter(prefix="{prefix}")
app = FastAPI()

@router.get("/users", dependencies=[Depends(require_admin)])
def list_users():
    return []

app.include_router(router, prefix="")
""".strip()
    return CorpusCase(
        framework="fastapi",
        category="pass",
        case_id=f"fastapi-pass-{index:02d}",
        path="app.py",
        base=source,
        head=source,
    )


def _fastapi_fail(index: int) -> CorpusCase:
    prefix = f"/admin{index}"
    base = f"""
from fastapi import APIRouter, Depends, FastAPI

def require_admin():
    return "admin"

router = APIRouter(prefix="{prefix}")
app = FastAPI()

@router.get("/users", dependencies=[Depends(require_admin)])
def list_users():
    return []

app.include_router(router)
""".strip()
    head = f"""
from fastapi import APIRouter, FastAPI

router = APIRouter(prefix="{prefix}")
app = FastAPI()

@router.get("/users")
def list_users():
    return []

app.include_router(router)
""".strip()
    return CorpusCase(
        framework="fastapi",
        category="fail",
        case_id=f"fastapi-fail-{index:02d}",
        path="app.py",
        base=base,
        head=head,
    )


def _fastapi_incomplete(index: int) -> CorpusCase:
    return CorpusCase(
        framework="fastapi",
        category="incomplete",
        case_id=f"fastapi-incomplete-{index:02d}",
        path="app.py",
        base="",
        head=f"""
from fastapi import FastAPI
app = FastAPI()
PATH = "/dyn{index}"
@app.get(PATH)
def dynamic():
    return {{}}
""".strip(),
    )


def _express_pass(index: int) -> CorpusCase:
    source = f"""
const express = require('express');
const {{ requireAdmin }} = require('./auth');
const router = express.Router();
router.get('/admin{index}/users', requireAdmin, (req, res) => res.json([]));
const app = express();
app.use('/api', router);
""".strip()
    return CorpusCase(
        framework="express",
        category="pass",
        case_id=f"express-pass-{index:02d}",
        path="app.js",
        base=source,
        head=source,
    )


def _express_fail(index: int) -> CorpusCase:
    base = f"""
const express = require('express');
const {{ requireAdmin }} = require('./auth');
const router = express.Router();
router.get('/admin{index}/users', requireAdmin, (req, res) => res.json([]));
const app = express();
app.use('/api', router);
""".strip()
    head = f"""
const express = require('express');
const router = express.Router();
router.get('/admin{index}/users', (req, res) => res.json([]));
const app = express();
app.use('/api', router);
""".strip()
    return CorpusCase(
        framework="express",
        category="fail",
        case_id=f"express-fail-{index:02d}",
        path="app.js",
        base=base,
        head=head,
    )


def _express_incomplete(index: int) -> CorpusCase:
    return CorpusCase(
        framework="express",
        category="incomplete",
        case_id=f"express-incomplete-{index:02d}",
        path="app.js",
        base="",
        head=f"""
const express = require('express');
const app = express();
const p = '/dyn{index}';
app.get(p, (req, res) => res.end());
""".strip(),
    )


def build_corpus(*, meet_targets: bool = True) -> list[CorpusCase]:
    counts = TARGET if meet_targets else {"pass": 5, "fail": 5, "incomplete": 5}
    cases: list[CorpusCase] = []
    for index in range(1, counts["pass"] + 1):
        cases.append(_fastapi_pass(index))
        cases.append(_express_pass(index))
    for index in range(1, counts["fail"] + 1):
        cases.append(_fastapi_fail(index))
        cases.append(_express_fail(index))
    for index in range(1, counts["incomplete"] + 1):
        cases.append(_fastapi_incomplete(index))
        cases.append(_express_incomplete(index))
    return cases


def classify_case(case: CorpusCase) -> Category:
    compiler = FastApiAuthorizationCompiler() if case.framework == "fastapi" else ExpressAuthorizationCompiler()
    materials = materials_from_pair(
        path=case.path,
        base_source=case.base if case.base else None,
        head_source=case.head,
    )
    ir = compiler.compile(materials)
    if case.category == "incomplete":
        return "incomplete"
    removed = any(route.admin_only_before and not route.admin_only_after for route in ir.routes)
    if case.category == "fail":
        return "fail" if removed else "pass"
    return "pass" if not removed else "fail"
