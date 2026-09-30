"""Tests for Open WebUI multi-obligation development replay (#144)."""

from __future__ import annotations

import os

import pytest

from ovk.compilers.authorization.open_webui_bypass_development_replay import (
    OPEN_WEBUI_LIVE_REPLAY_ENV,
    OPEN_WEBUI_REPAIR_SHA,
    OPEN_WEBUI_VULNERABLE_SHA,
)
from ovk.compilers.authorization.open_webui_multi_obligation_replay import (
    OBLIGATION_NAMES,
    analyze_open_webui_multi_obligation_revision,
    build_open_webui_multi_obligation_development_replay,
    build_open_webui_multi_obligation_live_development_replay,
)


def _vulnerable_unit() -> dict[str, str]:
    return {
        "backend/open_webui/utils/chat.py": """
async def generate_chat_completion(request, form_data, user, bypass_filter: bool = False):
    request.state.bypass_filter = bypass_filter
""".strip(),
        "backend/open_webui/routers/openai.py": """
async def handler(request, form_data, user, bypass_filter: bool = False):
    if bypass_filter:
        return sink(user)
    require_access(user)
    return sink(user)
""".strip(),
    }


def _repair_incomplete_provenance_unit() -> dict[str, str]:
    """Repair-shaped unit: helper param writers, no resolved caller provenance."""

    return {
        "backend/open_webui/utils/chat.py": """
async def generate_chat_completion(request, form_data, user, bypass_filter: bool = False):
    request.state.bypass_filter = bypass_filter
""".strip(),
        "backend/open_webui/routers/openai.py": """
async def handler(request, form_data, user):
    bypass_filter = getattr(request.state, "bypass_filter", False)
    if bypass_filter:
        return sink(user)
    require_access(user)
    return sink(user)
""".strip(),
    }


def _ordinary_guard_unit() -> dict[str, str]:
    return {
        "backend/open_webui/routers/openai.py": """
async def handler(request, user):
    require_access(user)
    return sink(user)
""".strip(),
    }


def test_multi_obligation_reports_all_named_obligations() -> None:
    report = build_open_webui_multi_obligation_development_replay(
        vulnerable_files=_vulnerable_unit(),
        repair_files=_repair_incomplete_provenance_unit(),
        vulnerable_kwargs={
            "entry_path": "backend/open_webui/routers/openai.py",
            "function_name": "handler",
            "source_roots": ("backend",),
            "callee_name": "generate_chat_completion",
        },
        repair_kwargs={
            "entry_path": "backend/open_webui/routers/openai.py",
            "function_name": "handler",
            "source_roots": ("backend",),
            "callee_name": "generate_chat_completion",
            "trusted_bypass_authorities": {
                "request.state.bypass_filter": ["model.invoke"],
            },
        },
    )
    assert report.label == "development_replay"
    assert report.held_out_success is False
    assert report.frozen_registry_mutated is False
    assert report.vulnerable.revision_sha == OPEN_WEBUI_VULNERABLE_SHA
    assert report.repair.revision_sha == OPEN_WEBUI_REPAIR_SHA

    for revision in (report.vulnerable, report.repair):
        names = tuple(item.name for item in revision.obligations)
        assert names == OBLIGATION_NAMES
        payload = revision.canonical_payload()
        assert {item["name"] for item in payload["obligations"]} == set(
            OBLIGATION_NAMES
        )


def test_vulnerable_pin_fixture_is_concrete_fail() -> None:
    """Positive theorem: client-controlled bypass reaching sink is FAIL."""

    report = analyze_open_webui_multi_obligation_revision(
        revision_sha=OPEN_WEBUI_VULNERABLE_SHA,
        files=_vulnerable_unit(),
        entry_path="backend/open_webui/routers/openai.py",
        function_name="handler",
        source_roots=("backend",),
        callee_name="generate_chat_completion",
    )
    obligations = report.obligation_map()
    assert obligations["source_extraction"].status == "established"
    assert obligations["cfg_coverage"].status == "established"
    assert obligations["bypass_predicate_representation"].status == "established"
    assert obligations["value_origin"].status == "established"
    assert obligations["ordinary_guard_effectiveness"].status == "violated"
    assert obligations["writer_closure"].status == "violated"
    assert obligations["principal_binding"].status == "unknown"
    assert obligations["effect_binding"].status == "unknown"
    assert obligations["resource_binding"].status == "unknown"
    assert report.final_protected_effect_status == "FAIL"
    assert obligations["final_protected_effect_status"].status == "violated"


def test_sparse_unit_never_establishes_writer_closure() -> None:
    """Adversarial: pin/fixture unit search is not repository closed-world."""

    files = {
        "backend/open_webui/utils/chat.py": """
def attach(request):
    request.state.bypass_filter = True
""".strip(),
        "backend/open_webui/routers/openai.py": """
async def handler(request, user):
    if request.state.bypass_filter:
        return sink(user)
    require_access(user)
    return sink(user)
""".strip(),
    }
    report = analyze_open_webui_multi_obligation_revision(
        revision_sha=OPEN_WEBUI_REPAIR_SHA,
        files=files,
        entry_path="backend/open_webui/routers/openai.py",
        function_name="handler",
        source_roots=("backend",),
        trusted_bypass_authorities={
            "request.state.bypass_filter": ["model.invoke"],
        },
    )
    obligations = report.obligation_map()
    assert obligations["writer_closure"].status == "unknown"
    assert obligations["writer_closure"].reason == "sparse_unit_not_repo_closure"
    assert report.final_protected_effect_status == "UNKNOWN"


def test_repair_stays_unknown_without_caller_provenance() -> None:
    """Near-miss: repair shape without proved caller provenance stays UNKNOWN."""

    report = analyze_open_webui_multi_obligation_revision(
        revision_sha=OPEN_WEBUI_REPAIR_SHA,
        files=_repair_incomplete_provenance_unit(),
        entry_path="backend/open_webui/routers/openai.py",
        function_name="handler",
        source_roots=("backend",),
        callee_name="generate_chat_completion",
        trusted_bypass_authorities={
            "request.state.bypass_filter": ["model.invoke"],
        },
    )
    obligations = report.obligation_map()
    assert obligations["source_extraction"].status == "established"
    assert obligations["caller_provenance"].status == "unknown"
    assert report.final_protected_effect_status == "UNKNOWN"
    assert obligations["final_protected_effect_status"].status == "unknown"
    payload = report.canonical_payload()
    assert payload["label"] == "development_replay"


def test_adversarial_name_alone_does_not_authorize_bypass() -> None:
    """Adversarial: settings-looking names never establish trusted bypass alone."""

    files = {
        "backend/open_webui/utils/chat.py": """
def attach(request):
    request.state.bypass_filter = settings.ALLOW_BYPASS
""".strip(),
        "backend/open_webui/routers/openai.py": """
async def handler(request, user):
    if request.state.bypass_filter:
        return sink(user)
    require_access(user)
    return sink(user)
""".strip(),
    }
    report = analyze_open_webui_multi_obligation_revision(
        revision_sha=OPEN_WEBUI_REPAIR_SHA,
        files=files,
        entry_path="backend/open_webui/routers/openai.py",
        function_name="handler",
        source_roots=("backend",),
        trusted_bypass_authorities={
            "request.state.bypass_filter": ["model.invoke"],
        },
    )
    obligations = report.obligation_map()
    assert obligations["bypass_authority"].status != "established"
    assert report.final_protected_effect_status == "UNKNOWN"


def test_ordinary_guard_dominance_is_not_pe_pass_while_bindings_unknown() -> None:
    """Structural dominance alone is not a Protected Effect PASS."""

    report = analyze_open_webui_multi_obligation_revision(
        revision_sha=OPEN_WEBUI_REPAIR_SHA,
        files=_ordinary_guard_unit(),
        entry_path="backend/open_webui/routers/openai.py",
        function_name="handler",
        source_roots=("backend",),
    )
    obligations = report.obligation_map()
    assert obligations["ordinary_guard_effectiveness"].status == "established"
    assert obligations["collective_path_coverage"].status == "established"
    assert obligations["principal_binding"].status == "unknown"
    assert obligations["effect_binding"].status == "unknown"
    assert obligations["resource_binding"].status == "unknown"
    assert report.final_protected_effect_status == "UNKNOWN"
    assert (
        obligations["final_protected_effect_status"].reason
        == "ordinary_guard_structural_dominance_not_pe_pass"
    )
    top = build_open_webui_multi_obligation_development_replay(
        vulnerable_files=_vulnerable_unit(),
        repair_files=_ordinary_guard_unit(),
        vulnerable_kwargs={
            "entry_path": "backend/open_webui/routers/openai.py",
            "source_roots": ("backend",),
        },
        repair_kwargs={
            "entry_path": "backend/open_webui/routers/openai.py",
            "source_roots": ("backend",),
        },
    )
    assert top.held_out_success is False
    assert top.frozen_registry_mutated is False
    assert top.canonical_payload()["held_out_success"] is False
    assert top.repair.final_protected_effect_status == "UNKNOWN"


def test_live_multi_obligation_requires_explicit_gate() -> None:
    previous = os.environ.pop(OPEN_WEBUI_LIVE_REPLAY_ENV, None)
    try:
        with pytest.raises(RuntimeError, match=OPEN_WEBUI_LIVE_REPLAY_ENV):
            build_open_webui_multi_obligation_live_development_replay()
    finally:
        if previous is not None:
            os.environ[OPEN_WEBUI_LIVE_REPLAY_ENV] = previous


@pytest.mark.skipif(
    os.environ.get(OPEN_WEBUI_LIVE_REPLAY_ENV, "").strip()
    not in {"1", "true", "TRUE", "yes", "YES"},
    reason=f"set {OPEN_WEBUI_LIVE_REPLAY_ENV}=1 to run live Open WebUI pin fetch",
)
def test_live_multi_obligation_pins_when_gated() -> None:
    report = build_open_webui_multi_obligation_live_development_replay(
        require_gate=True
    )
    assert report.source_mode == "live_pin"
    assert report.held_out_success is False
    assert report.frozen_registry_mutated is False
    assert report.vulnerable.revision_sha == OPEN_WEBUI_VULNERABLE_SHA
    assert report.repair.revision_sha == OPEN_WEBUI_REPAIR_SHA
    assert tuple(item.name for item in report.vulnerable.obligations) == (
        OBLIGATION_NAMES
    )
    # Repair stays UNKNOWN while PE bindings are unresolved in development replay.
    assert report.repair.final_protected_effect_status in {"UNKNOWN", "FAIL"}
