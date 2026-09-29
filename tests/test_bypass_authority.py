"""Tests for closed-world trusted bypass authority (#124)."""

from __future__ import annotations

from ovk.compilers.authorization.bypass_authority import analyze_bypass_authority


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


def test_server_authority_bypass_is_authorized() -> None:
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
    assert findings[0].status == "authorized"
    assert findings[0].reason == "source_proved_server_authority_write"


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
    )
    assert findings[0].status == "authorized"


def test_middleware_http_param_remains_violated_when_handler_selected() -> None:
    """Closed-world writes must see middleware params even if reads are scoped."""

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
    assert findings[0].status == "violated"
    assert findings[0].reason == "client_controlled_bypass_write"


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
    request.state.bypass_filter = settings.ALLOW
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
    )
    assert findings[0].status == "authorized"
    assert findings[0].closed_world is not None
    assert findings[0].closed_world.complete is True
    assert findings[0].write_count >= 1


def test_cross_file_client_write_is_violated() -> None:
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
    assert findings[0].status == "violated"
    assert findings[0].reason == "client_controlled_bypass_write"


def test_unresolvable_local_import_refuses_authorized() -> None:
    from ovk.compilers.authorization.bypass_authority import (
        analyze_bypass_authority_unit,
    )

    findings = analyze_bypass_authority_unit(
        {
            "app/handler.py": """
from app.missing_middleware import attach

def handler(request):
    request.state.bypass_filter = settings.ALLOW
    if request.state.bypass_filter:
        return sink()
""".strip(),
        },
        entry_path="app/handler.py",
        bypass_fields=frozenset({"bypass_filter"}),
    )
    assert findings[0].status == "unknown"
    assert findings[0].reason == "closed_world_incomplete"
    assert findings[0].closed_world is not None
    assert findings[0].closed_world.complete is False
    assert findings[0].closed_world.unresolvable_imports


def test_nested_client_overwrite_is_not_authorized() -> None:
    findings = analyze_bypass_authority(
        """
def middleware(request, bypass_filter: bool = False, flag: bool = False):
    request.state.bypass_filter = settings.ALLOW
    if flag:
        request.state.bypass_filter = bypass_filter

def handler(request):
    return request.state.bypass_filter
""".strip(),
        bypass_fields=frozenset({"bypass_filter"}),
    )
    assert findings[0].status == "violated"
    assert findings[0].reason == "client_controlled_bypass_write"
    assert findings[0].write_count >= 2


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
    request.state.bypass_filter = settings.ALLOW
    return request.state.bypass_filter
""".strip(),
        },
        entry_path="app/handler.py",
        bypass_fields=frozenset({"bypass_filter"}),
    )
    assert findings[0].status == "unknown"
    assert findings[0].reason == "closed_world_incomplete"
    assert findings[0].closed_world is not None
    assert findings[0].closed_world.complete is False


def test_star_import_refuses_authorized() -> None:
    from ovk.compilers.authorization.bypass_authority import (
        analyze_bypass_authority_unit,
    )

    findings = analyze_bypass_authority_unit(
        {
            "app/middleware.py": """
def attach(request):
    request.state.bypass_filter = settings.ALLOW
""".strip(),
            "app/handler.py": """
from app.middleware import *

def handler(request):
    return request.state.bypass_filter
""".strip(),
        },
        entry_path="app/handler.py",
        bypass_fields=frozenset({"bypass_filter"}),
    )
    assert findings[0].status == "unknown"
    assert findings[0].reason == "closed_world_incomplete"
    assert findings[0].closed_world is not None
    assert any(
        "star_import" in item for item in findings[0].closed_world.unresolvable_imports
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


def test_settings_attribute_server_config_still_authorizes() -> None:
    """Attribute form under settings.* remains a bounded authorizing source."""

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
    assert findings[0].status == "authorized"
    assert findings[0].reason == "source_proved_server_authority_write"
    assert findings[0].origin_kinds == ("server_configuration",)
