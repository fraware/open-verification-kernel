from __future__ import annotations

from ovk.compilers.authorization.authorization_cut_set import (
    evaluate_authorization_cut_set,
)
from ovk.compilers.authorization.handler_control_flow import (
    build_handler_control_flow_from_source,
    control_flow_edge_id,
    control_flow_edge_ref,
    control_flow_edge_ref_from_summary,
    dominates,
    find_control_flow_edge_ref,
    find_nodes_by_expression_substring,
)


def _one(cfg, needle: str) -> str:
    matches = find_nodes_by_expression_substring(cfg, needle)
    assert len(matches) == 1
    return matches[0].node_id


def _branch(cfg, needle: str) -> str:
    matches = [
        node
        for node in find_nodes_by_expression_substring(cfg, needle)
        if node.kind == "branch"
    ]
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


def test_control_flow_edge_id_is_content_addressed_not_object_identity() -> None:
    first = control_flow_edge_ref("branch:1", "stmt:2", True)
    second = control_flow_edge_ref("branch:1", "stmt:2", True)
    third = control_flow_edge_ref("branch:1", "stmt:2", False)

    assert first.edge_id == second.edge_id
    assert first.edge_id == control_flow_edge_id("branch:1", "stmt:2", True)
    assert first.edge_id != third.edge_id
    assert id(first) != id(second) or first == second


def test_true_edge_plus_require_access_covers_branch_outcome_sink() -> None:
    """True-outcome edge + false-path statement node collectively cover the sink."""

    source = """
def handler(flag):
    if flag:
        pass
    else:
        require_access()
    return sink()
""".strip()
    cfg = build_handler_control_flow_from_source(source, path="h.py")
    branch = _branch(cfg, "flag")
    require_access = _one(cfg, "require_access")
    sink = _one(cfg, "sink")
    true_edge = find_control_flow_edge_ref(
        cfg,
        source_node_id=branch,
        branch_value=True,
    )
    assert true_edge is not None

    result = evaluate_authorization_cut_set(
        cfg,
        sink_node_id=sink,
        cut_node_ids=frozenset({require_access}),
        cut_edge_ids=frozenset({true_edge.edge_id}),
    )

    assert result.coverage_status == "complete"
    assert result.covers_all_paths is True
    assert result.cut_edge_ids == (true_edge.edge_id,)


def test_require_access_node_alone_leaves_true_outcome_uncovered() -> None:
    source = """
def handler(flag):
    if flag:
        pass
    else:
        require_access()
    return sink()
""".strip()
    cfg = build_handler_control_flow_from_source(source, path="h.py")
    require_access = _one(cfg, "require_access")
    sink = _one(cfg, "sink")

    result = evaluate_authorization_cut_set(
        cfg,
        sink_node_id=sink,
        cut_node_ids=frozenset({require_access}),
    )

    assert result.coverage_status == "complete"
    assert result.covers_all_paths is False
    assert require_access not in result.uncovered_path_node_ids
    assert result.uncovered_path_node_ids[-1] == sink


def test_branch_predicate_node_cannot_be_authorization_cut() -> None:
    source = """
def handler(flag):
    if flag:
        pass
    else:
        require_access()
    return sink()
""".strip()
    cfg = build_handler_control_flow_from_source(source, path="h.py")
    branch = _branch(cfg, "flag")
    sink = _one(cfg, "sink")

    result = evaluate_authorization_cut_set(
        cfg,
        sink_node_id=sink,
        cut_node_ids=frozenset({branch}),
    )

    assert result.coverage_status == "unknown"
    assert result.covers_all_paths is False
    assert result.reason.startswith("branch_node_cannot_be_authorization_cut:")


def test_unknown_cut_edge_is_unknown() -> None:
    source = """
def handler(flag):
    if flag:
        pass
    else:
        require_access()
    return sink()
""".strip()
    cfg = build_handler_control_flow_from_source(source, path="h.py")
    sink = _one(cfg, "sink")

    result = evaluate_authorization_cut_set(
        cfg,
        sink_node_id=sink,
        cut_edge_ids=frozenset({"edge:missing->missing:true"}),
    )

    assert result.coverage_status == "unknown"
    assert result.covers_all_paths is False
    assert result.reason.startswith("cut_edge_absent_from_cfg:")


def test_owner_match_or_has_access_operand_edge_is_not_whole_condition() -> None:
    """One short-circuit True edge must not cover the alternate sink path."""

    source = """
def handler(user, owner_match):
    if owner_match or has_access(user):
        return sink(user)
    return None
""".strip()
    cfg = build_handler_control_flow_from_source(source, path="h.py")
    access_branch = _branch(cfg, "has_access")
    sink = _one(cfg, "sink")
    access_true = find_control_flow_edge_ref(
        cfg,
        source_node_id=access_branch,
        branch_value=True,
    )
    assert access_true is not None

    result = evaluate_authorization_cut_set(
        cfg,
        sink_node_id=sink,
        cut_edge_ids=frozenset({access_true.edge_id}),
    )

    assert result.coverage_status == "complete"
    assert result.covers_all_paths is False
    assert result.uncovered_path_node_ids[-1] == sink
    # The owner_match-true path reaches the sink without the has_access edge.
    assert any(
        node.expression == "owner_match"
        for node_id in result.uncovered_path_node_ids
        for node in cfg.nodes
        if node.node_id == node_id
    )


def test_enabled_and_has_access_operand_is_not_unconditional_boolean() -> None:
    """Short-circuit atom edges cover sink paths without authorizing the BoolOp node."""

    source = """
def handler(user, enabled):
    if enabled and has_access(user):
        return sink(user)
    return None
""".strip()
    cfg = build_handler_control_flow_from_source(source, path="h.py")
    enabled_branch = _branch(cfg, "enabled")
    access_branch = _branch(cfg, "has_access")
    sink = _one(cfg, "sink")
    access_true = find_control_flow_edge_ref(
        cfg,
        source_node_id=access_branch,
        branch_value=True,
    )
    assert access_true is not None

    # The expanded BoolOp branch nodes remain rejected as authorization cuts.
    enabled_as_cut = evaluate_authorization_cut_set(
        cfg,
        sink_node_id=sink,
        cut_node_ids=frozenset({enabled_branch}),
    )
    assert enabled_as_cut.coverage_status == "unknown"
    assert enabled_as_cut.reason.startswith(
        "branch_node_cannot_be_authorization_cut:"
    )
    access_as_cut = evaluate_authorization_cut_set(
        cfg,
        sink_node_id=sink,
        cut_node_ids=frozenset({access_branch}),
    )
    assert access_as_cut.coverage_status == "unknown"

    # The has_access-true outcome edge covers the sole sink-reaching path.
    # That is not equivalent to treating the whole Boolean expression node as
    # an authorization control point (rejected above).
    edge_cut = evaluate_authorization_cut_set(
        cfg,
        sink_node_id=sink,
        cut_edge_ids=frozenset({access_true.edge_id}),
    )
    assert edge_cut.coverage_status == "complete"
    assert edge_cut.covers_all_paths is True


def test_nested_boolop_branch_node_cut_is_unknown() -> None:
    source = """
def handler(user, a, b):
    if a and (b or has_access(user)):
        return sink(user)
    return None
""".strip()
    cfg = build_handler_control_flow_from_source(source, path="h.py")
    nested_branch = _branch(cfg, "has_access")
    sink = _one(cfg, "sink")

    result = evaluate_authorization_cut_set(
        cfg,
        sink_node_id=sink,
        cut_node_ids=frozenset({nested_branch}),
    )

    assert result.coverage_status == "unknown"
    assert result.covers_all_paths is False
    assert result.reason.startswith("branch_node_cannot_be_authorization_cut:")


def test_edge_ref_round_trip_matches_cfg_summary() -> None:
    source = """
def handler(flag):
    if flag:
        return sink()
    return None
""".strip()
    cfg = build_handler_control_flow_from_source(source, path="h.py")
    branch = _branch(cfg, "flag")
    true_edges = [
        control_flow_edge_ref_from_summary(edge)
        for edge in cfg.edges
        if edge.source_id == branch and edge.branch_value is True
    ]
    assert len(true_edges) == 1
    resolved = find_control_flow_edge_ref(
        cfg,
        source_node_id=branch,
        branch_value=True,
    )
    assert resolved == true_edges[0]
