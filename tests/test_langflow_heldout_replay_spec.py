from __future__ import annotations

from pathlib import Path

from ovk.core.external_assurance_replay import (
    load_external_assurance_replay_suite,
)


SUITE_PATH = Path(
    "benchmarks/assurance_qualification/external/"
    "langflow_monitor_auth_heldout.v1.json"
)


def test_langflow_replay_remains_independent_and_held_out() -> None:
    suite = load_external_assurance_replay_suite(SUITE_PATH)

    assert suite.suite_id == "langflow-heldout-route-auth-v1"
    assert len(suite.cases) == 1

    case = suite.cases[0]
    assert case.repository == "langflow-ai/langflow"
    assert case.validation_class == "independent_external"
    assert case.provenance.contamination_status == "held_out_independent"
    assert case.qualification_human_adjudicated is False
    assert case.human_review_minutes is None


def test_langflow_replay_is_pinned_to_frozen_public_transition() -> None:
    case = load_external_assurance_replay_suite(SUITE_PATH).cases[0]

    assert (
        case.base_sha
        == "9d57aa8f997ec10cd7e53ec2337ba25989926b60"
    )
    assert (
        case.head_sha
        == "3fed9fe1b5658f2c8656dbd73508e113a96e486a"
    )
    assert case.expected_head_assurance == "established"
    assert case.safety_label == "safe"


def test_langflow_prediction_uses_only_predeclared_route_mediation() -> None:
    case = load_external_assurance_replay_suite(SUITE_PATH).cases[0]
    profile = case.protected_effect_profile

    assert profile["source_paths"] == [
        "src/backend/base/langflow/api/v1/monitor.py"
    ]
    assert profile["sink_effects"] == {
        "delete_vertex_builds_by_flow_id": "langflow.monitor.builds.delete"
    }
    assert profile["sink_static_resources"] == {
        "delete_vertex_builds_by_flow_id": "langflow_monitor_builds"
    }
    assert profile["route_dependency_guard_resources"] == {
        "get_current_active_user": "langflow_monitor_builds"
    }
    assert profile["route_dependency_guard_effects"] == {
        "get_current_active_user": ["langflow.monitor.builds.delete"]
    }
    assert profile["dependency_guard_resources"] == {}
    assert profile["dependency_guard_effects"] == {}
