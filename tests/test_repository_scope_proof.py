"""Machine-derived repository closed-world scope proofs (#142 / #146)."""

from __future__ import annotations

import pytest

from ovk.compilers.authorization.bypass_authority import analyze_bypass_authority
from ovk.compilers.authorization.repository_scope_proof import (
    derive_closed_world_scope_proof,
    derive_python_source_roots,
    scope_proof_invalidated_by_file_change,
    scope_proof_invalidated_by_roots,
)


def test_derived_scope_proof_is_content_addressed() -> None:
    files = {
        "app/a.py": "x = 1\n",
        "app/b.py": "y = 2\n",
    }
    first = derive_closed_world_scope_proof(
        repo="example/app",
        revision="abc123",
        files=files,
        source_roots=(".",),
        field_searched="bypass_filter",
    )
    second = derive_closed_world_scope_proof(
        repo="example/app",
        revision="abc123",
        files={"app/b.py": "y = 2\n", "app/a.py": "x = 1\n"},
        source_roots=(".",),
        field_searched="bypass_filter",
    )
    assert first.digest() == second.digest()
    assert first.accounted_paths == ("app/a.py", "app/b.py")
    assert first.as_closed_world_scope_proof().accounted_paths == first.accounted_paths


def test_added_or_changed_file_invalidates_proof() -> None:
    files = {"app/a.py": "x = 1\n"}
    proof = derive_closed_world_scope_proof(
        repo="example/app",
        revision="abc123",
        files=files,
        source_roots=(".",),
    )
    changed = {"app/a.py": "x = 2\n"}
    added = {"app/a.py": "x = 1\n", "app/b.py": "y = 1\n"}
    assert scope_proof_invalidated_by_file_change(proof, files=changed) is True
    assert scope_proof_invalidated_by_file_change(proof, files=added) is True
    assert scope_proof_invalidated_by_file_change(proof, files=files) is False


def test_source_root_change_invalidates_proof() -> None:
    proof = derive_closed_world_scope_proof(
        repo="example/app",
        revision="abc123",
        files={"backend/app.py": "x = 1\n"},
        source_roots=("backend",),
    )
    assert scope_proof_invalidated_by_roots(proof, source_roots=(".",)) is True
    assert scope_proof_invalidated_by_roots(proof, source_roots=("backend",)) is False


def test_derived_proof_authorizes_literal_bypass_write() -> None:
    files = {
        "app.py": """
def middleware(request):
    request.state.bypass_filter = True

def handler(request):
    return request.state.bypass_filter
""".strip()
    }
    proof = derive_closed_world_scope_proof(
        repo="example/app",
        revision="rev1",
        files=files,
        source_roots=(".",),
        field_searched="bypass_filter",
    )
    findings = analyze_bypass_authority(
        files["app.py"],
        path="app.py",
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=proof.as_closed_world_scope_proof(),
    )
    assert findings[0].status == "authorized"


def test_analyzed_paths_must_be_subset() -> None:
    with pytest.raises(ValueError, match="subset"):
        derive_closed_world_scope_proof(
            repo="example/app",
            revision="rev1",
            files={"app.py": "x = 1\n"},
            source_roots=(".",),
            analyzed_paths=("missing.py",),
        )


def test_empty_source_roots_rejected() -> None:
    with pytest.raises(ValueError, match="source_roots"):
        derive_closed_world_scope_proof(
            repo="example/app",
            revision="rev1",
            files={"app.py": "x = 1\n"},
            source_roots=(),
        )


def test_derive_python_source_roots_rejects_empty() -> None:
    with pytest.raises(ValueError, match="source_roots"):
        derive_python_source_roots([])
