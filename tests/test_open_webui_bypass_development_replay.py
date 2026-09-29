"""Tests for Open WebUI bypass development replay (#125 / live-pin residual)."""

from __future__ import annotations

import os

import pytest

from ovk.compilers.authorization.open_webui_bypass_development_replay import (
    OPEN_WEBUI_LIVE_REPLAY_ENV,
    OPEN_WEBUI_REPAIR_SHA,
    OPEN_WEBUI_VULNERABLE_SHA,
    analyze_open_webui_live_pin_revision,
    build_open_webui_bypass_development_replay,
    build_open_webui_bypass_live_development_replay,
    live_open_webui_replay_enabled,
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


def _assert_all_seven_questions_present(answers) -> None:
    assert hasattr(answers, "source_extraction_succeeded")
    assert hasattr(answers, "bypass_predicate_represented")
    assert hasattr(answers, "origin_established")
    assert hasattr(answers, "ordinary_auth_guard_dominates_sink")
    assert hasattr(answers, "bypass_path_independently_authorized")
    assert hasattr(answers, "cfg_coverage_complete")
    assert hasattr(answers, "remaining_human_review_reason")
    assert isinstance(answers.remaining_human_review_reason, str)
    assert answers.remaining_human_review_reason


def test_development_replay_answers_both_revisions_separately() -> None:
    report = build_open_webui_bypass_development_replay(
        vulnerable_source=VULNERABLE,
        repair_source=REPAIR,
    )
    assert report.label == "development_replay"
    assert report.source_mode == "synthetic_fixture"
    assert report.held_out_success is False
    assert report.frozen_registry_mutated is False
    assert report.vulnerable.revision_sha == OPEN_WEBUI_VULNERABLE_SHA
    assert report.repair.revision_sha == OPEN_WEBUI_REPAIR_SHA

    vul = report.vulnerable.answers
    _assert_all_seven_questions_present(vul)
    assert vul.source_extraction_succeeded is True
    assert vul.bypass_predicate_represented is True
    assert vul.origin_established is True
    assert vul.ordinary_auth_guard_dominates_sink is False
    assert vul.bypass_path_independently_authorized is False
    assert vul.cfg_coverage_complete is True
    assert vul.remaining_human_review_reason == (
        "client_controlled_bypass_not_authorized"
    )
    assert "client_controlled_bypass" in report.vulnerable.notes

    rep = report.repair.answers
    _assert_all_seven_questions_present(rep)
    assert rep.source_extraction_succeeded is True
    assert rep.bypass_predicate_represented is True
    assert rep.origin_established is True
    assert rep.ordinary_auth_guard_dominates_sink is False
    assert rep.bypass_path_independently_authorized is True
    assert rep.cfg_coverage_complete is True
    assert rep.remaining_human_review_reason == "bypass_independently_authorized"


def test_development_replay_does_not_count_held_out_success() -> None:
    report = build_open_webui_bypass_development_replay(
        vulnerable_source=VULNERABLE,
        repair_source=REPAIR,
    )
    payload = report.canonical_payload()
    assert payload["label"] == "development_replay"
    assert payload["source_mode"] == "synthetic_fixture"
    assert payload["held_out_success"] is False
    assert payload["frozen_registry_mutated"] is False
    assert set(payload["vulnerable"]["answers"]) == {
        "source_extraction_succeeded",
        "bypass_predicate_represented",
        "origin_established",
        "ordinary_auth_guard_dominates_sink",
        "bypass_path_independently_authorized",
        "cfg_coverage_complete",
        "remaining_human_review_reason",
    }
    assert set(payload["repair"]["answers"]) == set(
        payload["vulnerable"]["answers"]
    )


def test_live_replay_requires_explicit_gate() -> None:
    previous = os.environ.pop(OPEN_WEBUI_LIVE_REPLAY_ENV, None)
    try:
        assert live_open_webui_replay_enabled() is False
        with pytest.raises(RuntimeError, match=OPEN_WEBUI_LIVE_REPLAY_ENV):
            build_open_webui_bypass_live_development_replay()
    finally:
        if previous is not None:
            os.environ[OPEN_WEBUI_LIVE_REPLAY_ENV] = previous


def test_live_pin_revision_from_fixture_unit_answers_seven_questions() -> None:
    """Offline stand-in for live pins: multi-file unit + live_pin labeling."""

    vulnerable_unit = {
        "backend/open_webui/utils/chat.py": """
async def generate_chat_completion(request, form_data, user, bypass_filter: bool = False):
    request.state.bypass_filter = bypass_filter
""".strip(),
        "backend/open_webui/routers/openai.py": """
async def generate_chat_completion(request, form_data, user, bypass_filter: bool = False):
    if not bypass_filter:
        check_model_access(user, model)
    metadata = form_data.get("metadata")
    return metadata
""".strip(),
    }
    report = analyze_open_webui_live_pin_revision(
        revision_sha=OPEN_WEBUI_VULNERABLE_SHA,
        files=vulnerable_unit,
    )
    assert report.source_mode == "live_pin"
    assert report.label == "development_replay"
    _assert_all_seven_questions_present(report.answers)
    assert report.answers.source_extraction_succeeded is True
    assert report.answers.bypass_predicate_represented is True
    assert report.answers.bypass_path_independently_authorized is False
    assert report.answers.remaining_human_review_reason == (
        "client_controlled_bypass_not_authorized"
    )


@pytest.mark.skipif(
    not live_open_webui_replay_enabled(),
    reason=f"set {OPEN_WEBUI_LIVE_REPLAY_ENV}=1 to run live Open WebUI pin fetch",
)
def test_live_open_webui_pins_fetchable_when_gated() -> None:
    report = build_open_webui_bypass_live_development_replay(require_gate=True)
    assert report.source_mode == "live_pin"
    assert report.held_out_success is False
    assert report.frozen_registry_mutated is False
    assert report.vulnerable.revision_sha == OPEN_WEBUI_VULNERABLE_SHA
    assert report.repair.revision_sha == OPEN_WEBUI_REPAIR_SHA
    _assert_all_seven_questions_present(report.vulnerable.answers)
    _assert_all_seven_questions_present(report.repair.answers)
    assert report.vulnerable.answers.source_extraction_succeeded is True
    assert report.repair.answers.source_extraction_succeeded is True
