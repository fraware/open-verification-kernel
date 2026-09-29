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
