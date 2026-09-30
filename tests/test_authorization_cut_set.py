from __future__ import annotations

from ovk.compilers.authorization.authorization_cut_set import (
    evaluate_authorization_cut_set,
)
from ovk.compilers.authorization.handler_control_flow import (
    build_handler_control_flow_from_source,
    dominates,
    find_nodes_by_expression_substring,
)


def _one(cfg, needle: str) -> str:
    matches = find_nodes_by_expression_substring(cfg, needle)
    assert len(matches) == 1
    return matches[0].node_id


def test_two_branch_guards_collectively_cover_sink() -> None:
    source = """
def handler(flag, user):
    if flag:
        authorize_a(user)
    else:
        authorize_b(user)
    return sink(user)
""".strip()
    cfg = build_handler_control_flow_from_source(source, path="h.py")
    guard_a = _one(cfg, "authorize_a")
    guard_b = _one(cfg, "authorize_b")
    sink = _one(cfg, "sink")

    assert dominates(cfg, guard_a, sink) is False
    assert dominates(cfg, guard_b, sink) is False

    result = evaluate_authorization_cut_set(
        cfg,
        sink_node_id=sink,
        cut_node_ids=frozenset({guard_a, guard_b}),
    )

    assert result.coverage_status == "complete"
    assert result.covers_all_paths is True
    assert result.uncovered_path_node_ids == ()


def test_one_branch_guard_leaves_explicit_uncovered_path() -> None:
    source = """
def handler(flag, user):
    if flag:
        authorize_a(user)
    else:
        authorize_b(user)
    return sink(user)
""".strip()
    cfg = build_handler_control_flow_from_source(source, path="h.py")
    guard_a = _one(cfg, "authorize_a")
    guard_b = _one(cfg, "authorize_b")
    sink = _one(cfg, "sink")

    result = evaluate_authorization_cut_set(
        cfg,
        sink_node_id=sink,
        cut_node_ids=frozenset({guard_a}),
    )

    assert result.coverage_status == "complete"
    assert result.covers_all_paths is False
    assert result.uncovered_path_node_ids
    assert guard_a not in result.uncovered_path_node_ids
    assert guard_b in result.uncovered_path_node_ids
    assert result.uncovered_path_node_ids[-1] == sink


def test_sequential_guard_is_singleton_cut_set() -> None:
    source = """
def handler(user):
    authorize(user)
    return sink(user)
""".strip()
    cfg = build_handler_control_flow_from_source(source, path="h.py")
    guard = _one(cfg, "authorize")
    sink = _one(cfg, "sink")

    result = evaluate_authorization_cut_set(
        cfg,
        sink_node_id=sink,
        cut_node_ids=frozenset({guard}),
    )

    assert result.coverage_status == "complete"
    assert result.covers_all_paths is True


def test_terminal_branch_not_reaching_sink_does_not_need_guard() -> None:
    source = """
def handler(skip, user):
    if skip:
        return None
    authorize(user)
    return sink(user)
""".strip()
    cfg = build_handler_control_flow_from_source(source, path="h.py")
    guard = _one(cfg, "authorize")
    sink = _one(cfg, "sink")

    result = evaluate_authorization_cut_set(
        cfg,
        sink_node_id=sink,
        cut_node_ids=frozenset({guard}),
    )

    assert result.coverage_status == "complete"
    assert result.covers_all_paths is True


def test_partial_sink_reaching_cfg_refuses_positive_cut_set() -> None:
    source = """
def handler(items, user):
    for item in items:
        authorize(user, item)
    return sink(user)
""".strip()
    cfg = build_handler_control_flow_from_source(source, path="h.py")
    guard = _one(cfg, "authorize")
    sink = _one(cfg, "sink")

    result = evaluate_authorization_cut_set(
        cfg,
        sink_node_id=sink,
        cut_node_ids=frozenset({guard}),
    )

    assert result.coverage_status == "partial"
    assert result.covers_all_paths is False
    assert result.reason == "sink_reaching_cfg_coverage_partial"


def test_unknown_cut_node_is_unknown() -> None:
    source = """
def handler(user):
    authorize(user)
    return sink(user)
""".strip()
    cfg = build_handler_control_flow_from_source(source, path="h.py")
    sink = _one(cfg, "sink")

    result = evaluate_authorization_cut_set(
        cfg,
        sink_node_id=sink,
        cut_node_ids=frozenset({"missing:guard"}),
    )

    assert result.coverage_status == "unknown"
    assert result.covers_all_paths is False
    assert result.reason.startswith("cut_node_absent_from_cfg:")


def test_empty_cut_set_returns_uncovered_path() -> None:
    source = """
def handler(user):
    return sink(user)
""".strip()
    cfg = build_handler_control_flow_from_source(source, path="h.py")
    sink = _one(cfg, "sink")

    result = evaluate_authorization_cut_set(
        cfg,
        sink_node_id=sink,
        cut_node_ids=frozenset(),
    )

    assert result.coverage_status == "complete"
    assert result.covers_all_paths is False
    assert result.uncovered_path_node_ids[0] == cfg.entry_id
    assert result.uncovered_path_node_ids[-1] == sink


def test_empty_cut_set_under_partial_cfg_remains_partial() -> None:
    source = """
def handler(items, user):
    for item in items:
        observe(item)
    return sink(user)
""".strip()
    cfg = build_handler_control_flow_from_source(source, path="h.py")
    sink = _one(cfg, "sink")

    result = evaluate_authorization_cut_set(
        cfg,
        sink_node_id=sink,
        cut_node_ids=frozenset(),
    )

    assert result.coverage_status == "partial"
    assert result.covers_all_paths is False
    assert result.reason == "sink_reaching_cfg_coverage_partial"


def test_entry_and_sink_cannot_be_used_as_authorization_nodes() -> None:
    source = """
def handler(user):
    authorize(user)
    return sink(user)
""".strip()
    cfg = build_handler_control_flow_from_source(source, path="h.py")
    sink = _one(cfg, "sink")

    entry_result = evaluate_authorization_cut_set(
        cfg,
        sink_node_id=sink,
        cut_node_ids=frozenset({cfg.entry_id}),
    )
    sink_result = evaluate_authorization_cut_set(
        cfg,
        sink_node_id=sink,
        cut_node_ids=frozenset({sink}),
    )

    assert entry_result.coverage_status == "unknown"
    assert entry_result.covers_all_paths is False
    assert sink_result.coverage_status == "unknown"
    assert sink_result.covers_all_paths is False
