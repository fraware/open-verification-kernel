"""Tests for closed-world trusted bypass authority (#124)."""

from __future__ import annotations

from ovk.compilers.authorization.bypass_authority import (
    ClosedWorldScopeProof,
    analyze_bypass_authority,
)


def _scope(*paths: str, source_roots: tuple[str, ...] = (".",)) -> ClosedWorldScopeProof:
    return ClosedWorldScopeProof(
        accounted_paths=tuple(paths),
        source_roots=source_roots,
    )


def test_client_controlled_bypass_is_violated() -> None:
    findings = analyze_bypass_authority(
        """
def middleware(request, bypass_filter: bool = False):
    request.state.bypass_filter = bypass_filter

def handler(request):
    if request.state.bypass_filter:
        return sink()
    require_access()
    return sink()
""".strip(),
        bypass_fields=frozenset({"bypass_filter"}),
    )
    assert findings
    assert findings[0].status == "violated"
    assert findings[0].reason == "client_controlled_bypass_write"


def test_config_shaped_bypass_is_unknown_without_binding_proof() -> None:
    findings = analyze_bypass_authority(
        """
def middleware(request):
    request.state.bypass_filter = settings.ALLOW

def handler(request):
    if request.state.bypass_filter:
        return sink()
    require_access()
    return sink()
""".strip(),
        bypass_fields=frozenset({"bypass_filter"}),
    )
    assert findings[0].status == "unknown"
    assert findings[0].reason == "unsupported_write_origin_mix"


def test_unresolved_writer_is_unknown() -> None:
    findings = analyze_bypass_authority(
        """
def handler(request):
    if request.state.bypass_filter:
        return sink()
    require_access()
    return sink()
""".strip(),
        bypass_fields=frozenset({"bypass_filter"}),
    )
    assert findings[0].status == "unknown"
    assert findings[0].reason == "unresolved_writer_provenance"


def test_dynamic_setattr_is_unknown() -> None:
    findings = analyze_bypass_authority(
        """
def middleware(request, name, value):
    setattr(request.state, name, value)

def handler(request):
    return request.state.bypass_filter
""".strip(),
        bypass_fields=frozenset({"bypass_filter"}),
    )
    assert findings[0].status == "unknown"
    assert "dynamic" in findings[0].reason or findings[0].write_count >= 1


def test_literal_server_write_is_authorized() -> None:
    findings = analyze_bypass_authority(
        """
def middleware(request):
    request.state.bypass_filter = True

def handler(request):
    return getattr(request.state, "bypass_filter", False)
""".strip(),
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope("<module>"),
    )
    assert findings[0].status == "authorized"
    assert findings[0].closed_world is not None
    assert findings[0].closed_world.complete is True


def test_literal_write_without_scope_proof_is_unknown() -> None:
    findings = analyze_bypass_authority(
        """
def handler(request):
    request.state.bypass_filter = True
    return request.state.bypass_filter
""".strip(),
        function_name="handler",
        bypass_fields=frozenset({"bypass_filter"}),
    )
    assert findings[0].status == "unknown"
    assert findings[0].reason == "closed_world_incomplete"
    assert findings[0].closed_world is not None
    assert findings[0].closed_world.reason == "closed_world_scope_proof_missing"


def test_non_entry_middleware_parameter_origin_is_unknown() -> None:
    """Helper parameters need caller provenance before they are HTTP-controlled."""

    findings = analyze_bypass_authority(
        """
def middleware(request, bypass_filter: bool = False):
    request.state.bypass_filter = bypass_filter

def handler(request):
    if request.state.bypass_filter:
        return sink()
    require_access()
    return sink()
""".strip(),
        function_name="handler",
        bypass_fields=frozenset({"bypass_filter"}),
    )
    assert findings[0].status == "unknown"
    assert findings[0].reason == "unresolved_write_origin"


def test_wildcard_state_update_is_unknown() -> None:
    findings = analyze_bypass_authority(
        """
def middleware(request, payload):
    request.state.__dict__.update(payload)

def handler(request):
    return request.state.bypass_filter
""".strip(),
        bypass_fields=frozenset({"bypass_filter"}),
    )
    assert findings[0].status == "unknown"
    assert findings[0].reason == "dynamic_or_wildcard_state_mutation"


def test_derived_write_origin_is_unknown_not_authorized() -> None:
    findings = analyze_bypass_authority(
        """
def middleware(request, flag):
    request.state.bypass_filter = flag or settings.ALLOW

def handler(request):
    return request.state.bypass_filter
""".strip(),
        bypass_fields=frozenset({"bypass_filter"}),
    )
    assert findings[0].status == "unknown"
    assert findings[0].reason == "unsupported_write_origin_mix"


def test_absence_of_external_write_is_not_trusted() -> None:
    """No discovered writer must remain UNKNOWN — never an authorized PASS."""

    findings = analyze_bypass_authority(
        """
def handler(request):
    if request.state.bypass_filter:
        return sink()
""".strip(),
        bypass_fields=frozenset({"bypass_filter"}),
    )
    assert findings[0].status == "unknown"
    assert findings[0].write_count == 0
    assert findings[0].reason == "unresolved_writer_provenance"


def test_cross_file_trusted_write_is_authorized() -> None:
    from ovk.compilers.authorization.bypass_authority import (
        analyze_bypass_authority_unit,
    )

    findings = analyze_bypass_authority_unit(
        {
            "app/middleware.py": """
def attach(request):
    request.state.bypass_filter = True
""".strip(),
            "app/handler.py": """
from app.middleware import attach

def handler(request):
    if request.state.bypass_filter:
        return sink()
    require_access()
    return sink()
""".strip(),
        },
        entry_path="app/handler.py",
        function_name="handler",
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope("app/middleware.py", "app/handler.py"),
    )
    assert findings[0].status == "authorized"
    assert findings[0].closed_world is not None
    assert findings[0].closed_world.complete is True
    assert findings[0].write_count >= 1


def test_cross_file_helper_parameter_requires_caller_provenance() -> None:
    from ovk.compilers.authorization.bypass_authority import (
        analyze_bypass_authority_unit,
    )

    findings = analyze_bypass_authority_unit(
        {
            "app/middleware.py": """
def attach(request, bypass_filter: bool = False):
    request.state.bypass_filter = bypass_filter
""".strip(),
            "app/handler.py": """
from app.middleware import attach

def handler(request):
    if request.state.bypass_filter:
        return sink()
""".strip(),
        },
        entry_path="app/handler.py",
        bypass_fields=frozenset({"bypass_filter"}),
    )
    assert findings[0].status == "unknown"
    assert findings[0].reason == "unresolved_write_origin"


def test_missing_absolute_import_is_external_not_root_special_cased() -> None:
    """Zero manifest candidates for a foreign top-level name mean external."""

    from ovk.compilers.authorization.bypass_authority import (
        analyze_bypass_authority_unit,
    )

    findings = analyze_bypass_authority_unit(
        {
            "app/handler.py": """
from missing_middleware_pkg import attach

def handler(request):
    request.state.bypass_filter = True
    if request.state.bypass_filter:
        return sink()
""".strip(),
        },
        entry_path="app/handler.py",
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope("app/handler.py"),
    )
    # No */missing_middleware_pkg.py in the manifest → external import.
    assert findings[0].closed_world is not None
    assert findings[0].closed_world.complete is True
    assert findings[0].status == "authorized"


def test_missing_relative_import_refuses_authorized() -> None:
    """Relative imports are never external; unresolved ones poison closure."""

    from ovk.compilers.authorization.bypass_authority import (
        analyze_bypass_authority_unit,
    )

    findings = analyze_bypass_authority_unit(
        {
            "app/handler.py": """
from .evil import client_writer

def handler(request):
    request.state.bypass_filter = True
    return request.state.bypass_filter
""".strip(),
        },
        entry_path="app/handler.py",
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope("app/handler.py"),
    )
    assert findings[0].status != "authorized"
    assert findings[0].closed_world is not None
    assert findings[0].closed_world.complete is False
    assert any(
        "unresolvable_relative_import:app.evil" in item
        for item in findings[0].closed_world.unresolvable_imports
    )


def test_missing_local_package_absolute_import_refuses_authorized() -> None:
    """Absolute import under an existing local package top is not external."""

    from ovk.compilers.authorization.bypass_authority import (
        analyze_bypass_authority_unit,
    )

    findings = analyze_bypass_authority_unit(
        {
            "app/handler.py": """
from app.missing_middleware import attach

def handler(request):
    request.state.bypass_filter = True
    return request.state.bypass_filter
""".strip(),
        },
        entry_path="app/handler.py",
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope("app/handler.py"),
    )
    assert findings[0].status != "authorized"
    assert findings[0].closed_world is not None
    assert findings[0].closed_world.complete is False
    assert any(
        "unresolvable_local_import:app.missing_middleware" in item
        for item in findings[0].closed_world.unresolvable_imports
    )


def test_ambiguous_manifest_import_refuses_authorized() -> None:
    from ovk.compilers.authorization.bypass_authority import (
        analyze_bypass_authority_unit,
    )

    findings = analyze_bypass_authority_unit(
        {
            "src/acme/auth.py": "def check():\n    pass\n",
            "lib/acme/auth.py": "def check():\n    pass\n",
            "app/handler.py": """
from acme.auth import check

def handler(request):
    request.state.bypass_filter = True
    return request.state.bypass_filter
""".strip(),
        },
        entry_path="app/handler.py",
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope(
            "src/acme/auth.py",
            "lib/acme/auth.py",
            "app/handler.py",
        ),
    )
    assert findings[0].status == "unknown"
    assert findings[0].reason == "closed_world_incomplete"
    assert findings[0].closed_world is not None
    assert findings[0].closed_world.complete is False
    assert any(
        "ambiguous_local_import:acme.auth" in item
        for item in findings[0].closed_world.unresolvable_imports
    )


def test_nested_client_overwrite_is_not_authorized() -> None:
    findings = analyze_bypass_authority(
        """
def middleware(request, bypass_filter: bool = False, flag: bool = False):
    request.state.bypass_filter = True
    if flag:
        request.state.bypass_filter = bypass_filter

def handler(request):
    return request.state.bypass_filter
""".strip(),
        bypass_fields=frozenset({"bypass_filter"}),
    )
    assert findings[0].status == "unknown"
    assert findings[0].reason == "control_dependent_state_mutation"
    assert findings[0].write_count >= 2


def test_client_condition_gating_literal_write_is_not_authorized() -> None:
    findings = analyze_bypass_authority(
        """
def middleware(request, bypass_filter: bool = False):
    if bypass_filter:
        request.state.bypass_filter = True

def handler(request):
    return request.state.bypass_filter
""".strip(),
        bypass_fields=frozenset({"bypass_filter"}),
    )
    assert findings[0].status == "unknown"
    assert findings[0].reason == "control_dependent_state_mutation"


def test_request_state_setattr_method_is_unknown() -> None:
    findings = analyze_bypass_authority(
        """
def middleware(request, bypass_filter: bool = False):
    request.state.bypass_filter = settings.ALLOW
    request.state.__setattr__("bypass_filter", bypass_filter)

def handler(request):
    return request.state.bypass_filter
""".strip(),
        bypass_fields=frozenset({"bypass_filter"}),
    )
    assert findings[0].status == "unknown"
    assert findings[0].reason == "dynamic_or_wildcard_state_mutation"


def test_annassign_client_overwrite_is_violated() -> None:
    findings = analyze_bypass_authority(
        """
def middleware(request, bypass_filter: bool = False):
    request.state.bypass_filter = settings.ALLOW
    request.state.bypass_filter: bool = bypass_filter

def handler(request):
    return request.state.bypass_filter
""".strip(),
        bypass_fields=frozenset({"bypass_filter"}),
    )
    assert findings[0].status == "violated"
    assert findings[0].write_count >= 2


def test_in_function_dynamic_import_refuses_authorized() -> None:
    from ovk.compilers.authorization.bypass_authority import (
        analyze_bypass_authority_unit,
    )

    findings = analyze_bypass_authority_unit(
        {
            "app/handler.py": """
def handler(request):
    __import__("secret_mod")
    request.state.bypass_filter = True
    return request.state.bypass_filter
""".strip(),
        },
        entry_path="app/handler.py",
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope("app/handler.py"),
    )
    assert findings[0].status == "unknown"
    assert findings[0].reason == "closed_world_incomplete"
    assert findings[0].closed_world is not None
    assert findings[0].closed_world.complete is False
    assert any(
        "dynamic_import" in item
        for item in findings[0].closed_world.unresolvable_imports
    )


def test_star_import_refuses_authorized() -> None:
    from ovk.compilers.authorization.bypass_authority import (
        analyze_bypass_authority_unit,
    )

    findings = analyze_bypass_authority_unit(
        {
            "app/middleware.py": """
def attach(request):
    request.state.bypass_filter = True
""".strip(),
            "app/handler.py": """
from app.middleware import *

def handler(request):
    return request.state.bypass_filter
""".strip(),
        },
        entry_path="app/handler.py",
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope("app/middleware.py", "app/handler.py"),
    )
    assert findings[0].status == "unknown"
    assert findings[0].reason == "closed_world_incomplete"
    assert findings[0].closed_world is not None
    assert any(
        "star_import" in item for item in findings[0].closed_world.unresolvable_imports
    )



def test_nonconventional_python_layout_resolves_local_import() -> None:
    """``python/acme/...`` must resolve without backend/src special-casing."""

    from ovk.compilers.authorization.bypass_authority import (
        analyze_bypass_authority_unit,
    )

    files = {
        "python/acme/auth.py": """
def attach(request):
    request.state.bypass_filter = True
""".strip(),
        "python/acme/routes.py": """
from acme.auth import attach

def handler(request):
    return request.state.bypass_filter
""".strip(),
    }
    findings = analyze_bypass_authority_unit(
        files,
        entry_path="python/acme/routes.py",
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope(*files, source_roots=(".",)),
    )
    assert findings[0].closed_world is not None
    assert findings[0].closed_world.complete is True
    assert findings[0].status == "authorized"


def test_missing_local_package_submodule_refuses_authorized() -> None:
    """``open_webui`` already appears under the manifest — missing submodule
    is a local miss, not an external import (Unknown > false PASS)."""

    from ovk.compilers.authorization.bypass_authority import (
        analyze_bypass_authority_unit,
    )

    files = {
        "backend/open_webui/routers/openai.py": """
from open_webui.utils.auth import get_verified_user

def handler(request):
    request.state.bypass_filter = True
    return request.state.bypass_filter
""".strip(),
    }
    findings = analyze_bypass_authority_unit(
        files,
        entry_path="backend/open_webui/routers/openai.py",
        function_name="handler",
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope(
            "backend/open_webui/routers/openai.py",
            source_roots=("backend",),
        ),
    )
    assert findings[0].closed_world is not None
    assert findings[0].closed_world.complete is False
    assert findings[0].status != "authorized"
    assert any(
        "unresolvable_local_import:open_webui.utils.auth" in item
        for item in findings[0].closed_world.unresolvable_imports
    )

def test_bare_allcaps_bypass_predicate_is_not_authorized() -> None:
    """Bare ALL_CAPS Names must not authorize trusted bypass authority."""

    for bare in ("BYPASS_FILTER", "ALLOW_ALL", "DEBUG", "SETTINGS_ALLOW"):
        findings = analyze_bypass_authority(
            f"""
{bare} = True

def middleware(request):
    request.state.bypass_filter = {bare}

def handler(request):
    if request.state.bypass_filter:
        return sink()
""".strip(),
            bypass_fields=frozenset({"bypass_filter"}),
        )
        assert findings[0].status == "unknown", bare
        assert findings[0].reason == "unresolved_write_origin", bare
        assert "server_configuration" not in findings[0].origin_kinds, bare


def test_settings_attribute_does_not_authorize_without_binding_proof() -> None:
    findings = analyze_bypass_authority(
        """
def middleware(request):
    request.state.bypass_filter = settings.ALLOW_ALL

def handler(request):
    if request.state.bypass_filter:
        return sink()
""".strip(),
        bypass_fields=frozenset({"bypass_filter"}),
    )
    assert findings[0].status == "unknown"
    assert findings[0].reason == "unsupported_write_origin_mix"
    assert "server_configuration" not in findings[0].origin_kinds


def test_settings_parameter_attribute_does_not_authorize() -> None:
    findings = analyze_bypass_authority(
        """
def middleware(request, settings):
    request.state.bypass_filter = settings.ALLOW

def handler(request):
    return request.state.bypass_filter
""".strip(),
        bypass_fields=frozenset({"bypass_filter"}),
    )
    assert findings[0].status == "unknown"
    assert "server_configuration" not in findings[0].origin_kinds
