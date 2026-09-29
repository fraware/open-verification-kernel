"""Tests for Open WebUI bypass development replay (#125)."""

from __future__ import annotations

from ovk.compilers.authorization.open_webui_bypass_development_replay import (
    OPEN_WEBUI_REPAIR_SHA,
    OPEN_WEBUI_VULNERABLE_SHA,
    build_open_webui_bypass_development_replay,
)


VULNERABLE = """
def middleware(request, bypass_filter: bool = False):
    request.state.bypass_filter = bypass_filter

def handler(request, user):
    if request.state.bypass_filter:
        return sink(user)
    require_access(user)
    return sink(user)
""".strip()


REPAIR = """
SETTINGS_ALLOW_BYPASS = False

def middleware(request):
    request.state.bypass_filter = SETTINGS_ALLOW_BYPASS

def handler(request, user):
    if request.state.bypass_filter:
        return sink(user)
    require_access(user)
    return sink(user)
""".strip()


def test_development_replay_answers_both_revisions_separately() -> None:
    report = build_open_webui_bypass_development_replay(
        vulnerable_source=VULNERABLE,
        repair_source=REPAIR,
    )
    assert report.label == "development_replay"
    assert report.held_out_success is False
    assert report.frozen_registry_mutated is False
    assert report.vulnerable.revision_sha == OPEN_WEBUI_VULNERABLE_SHA
    assert report.repair.revision_sha == OPEN_WEBUI_REPAIR_SHA

    vul = report.vulnerable.answers
    assert vul.source_extraction_succeeded
    assert vul.bypass_predicate_represented
    assert vul.origin_established
    assert vul.ordinary_auth_guard_dominates_sink is False
    assert vul.bypass_path_independently_authorized is False
    assert vul.cfg_coverage_complete is True

    rep = report.repair.answers
    assert rep.source_extraction_succeeded
    assert rep.bypass_predicate_represented
    assert rep.bypass_path_independently_authorized is True
