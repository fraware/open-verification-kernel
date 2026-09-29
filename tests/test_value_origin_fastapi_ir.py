"""Value-origin evidence assembled into FastAPI Assurance IR digests."""

from __future__ import annotations

import ast

from ovk.compilers.authorization.fastapi_route_summary import summarize_route_file
from ovk.compilers.authorization.fastapi_semantic_fragment import (
    assemble_fastapi_assurance_ir,
    bind_route_file_summary,
)
from ovk.compilers.authorization.material_loader import AuthMaterials
from ovk.compilers.authorization.protected_effect_fastapi_dependency import (
    FastApiDependencyEffectProfile,
)
from ovk.core.assurance_ir import (
    AssuranceCoverage,
    AssuranceExtractorIdentity,
    AssuranceIR,
)
from ovk.core.bundle import content_digest
from ovk.core.models import VerificationSubject


def test_empty_value_origin_omitted_from_canonical_payload() -> None:
    ir = AssuranceIR(
        subject=VerificationSubject(
            repo="demo/repo",
            base_sha="base",
            head_sha="head",
        ),
        extractor=AssuranceExtractorIdentity(
            extractor_id="test",
            extractor_version="0.1.0",
            source_profile_id="test",
        ),
        coverage=AssuranceCoverage(
            status="complete",
            confidence=1.0,
            supported_constructs=[],
            unsupported_constructs=[],
            assumptions=[],
        ),
    )
    assert "value_origin_evidence" not in ir.canonical_payload()


def test_value_origins_enter_assembled_ir_when_material() -> None:
    source = """
from fastapi import APIRouter

router = APIRouter()

@router.get("/items/{item_id}")
def read_item(item_id: str, bypass_filter: bool = False):
    return {"id": item_id, "bypass": bypass_filter}
""".strip()
    tree = ast.parse(source)
    summary = summarize_route_file(
        path="app/routes.py",
        tree=tree,
        source_digest=content_digest(source),
    )
    assert summary.handlers
    assert summary.handlers[0].value_origins
    assert any(
        item.origin_kind == "externally_bound_http_value"
        for item in summary.handlers[0].value_origins
    )

    fragment = bind_route_file_summary(
        summary,
        profile=FastApiDependencyEffectProfile(
            sink_effects={},
        ),
        contracts_by_name={},
    )
    assert fragment.value_origin_evidence
    materials = AuthMaterials(
        repo="demo/repo",
        base_revision="base",
        head_revision="head",
        head_files={"app/routes.py": source},
    )
    ir = assemble_fastapi_assurance_ir(
        materials=materials,
        function_contracts=[],
        resource_return_contracts=[],
        fragments={fragment.path: fragment},
    )
    assert ir.extractor.extractor_version == "0.18.0"
    payload = ir.canonical_payload()
    assert "value_origin_evidence" in payload
    assert payload["value_origin_evidence"]
    kinds = {item["origin_kind"] for item in payload["value_origin_evidence"]}
    assert "externally_bound_http_value" in kinds
