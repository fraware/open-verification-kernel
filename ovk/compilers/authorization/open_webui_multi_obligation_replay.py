"""Open WebUI multi-obligation development replay (#144).

Evaluates both pinned revisions and reports each proof obligation separately.
Results are always labeled ``development_replay`` with
``held_out_success=false`` and ``frozen_registry_mutated=false``.

Repair may correctly remain UNKNOWN when caller provenance or repository
closure is incomplete. Faithful classification is the objective — not forcing
a repaired PASS.
"""

from __future__ import annotations

import ast
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal

from ovk.compilers.authorization.authorization_cut_set import (
    evaluate_authorization_cut_set,
)
from ovk.compilers.authorization.bypass_authority import (
    analyze_bypass_authority_unit,
)
from ovk.compilers.authorization.handler_control_flow import (
    build_handler_control_flow_from_source,
    coverage_authoritative_for,
    dominates as cfg_dominates,
    find_nodes_by_expression_substring,
)
from ovk.compilers.authorization.interprocedural_argument_provenance import (
    analyze_interprocedural_argument_provenance,
)
from ovk.compilers.authorization.open_webui_bypass_development_replay import (
    OPEN_WEBUI_LIVE_REPLAY_ENV,
    OPEN_WEBUI_PIN_RELATIVE_PATHS,
    OPEN_WEBUI_REPAIR_SHA,
    OPEN_WEBUI_REPO,
    OPEN_WEBUI_VULNERABLE_SHA,
    fetch_open_webui_pin_unit,
    live_open_webui_replay_enabled,
)
from ovk.compilers.authorization.repository_scope_proof import (
    derive_closed_world_scope_proof,
)
from ovk.compilers.authorization.trusted_bypass_authorization import (
    evaluate_trusted_bypass_authorizations,
    read_origin_for_path,
    resolve_bypass_control_point_edge,
)
from ovk.compilers.authorization.value_origin import (
    extract_value_origins_from_source,
)
from ovk.core.assurance_ir import ValueOriginEvidence
from ovk.core.bundle import content_digest


ReplayLabel = Literal["development_replay"]
ReplaySourceMode = Literal["synthetic_fixture", "live_pin"]
ObligationStatusValue = Literal["established", "violated", "unknown", "not_applicable"]
FinalProtectedEffectStatus = Literal["PASS", "FAIL", "UNKNOWN"]

OBLIGATION_NAMES: tuple[str, ...] = (
    "source_extraction",
    "cfg_coverage",
    "bypass_predicate_representation",
    "value_origin",
    "writer_closure",
    "caller_provenance",
    "ordinary_guard_effectiveness",
    "bypass_authority",
    "branch_outcome_binding",
    "collective_path_coverage",
    "principal_binding",
    "effect_binding",
    "resource_binding",
    "final_protected_effect_status",
)


@dataclass(frozen=True)
class ObligationResult:
    name: str
    status: ObligationStatusValue
    reason: str

    def canonical_payload(self) -> dict[str, str]:
        return {
            "name": self.name,
            "status": self.status,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class OpenWebUIMultiObligationRevisionReport:
    revision_sha: str
    label: ReplayLabel
    source_mode: ReplaySourceMode
    obligations: tuple[ObligationResult, ...]
    final_protected_effect_status: FinalProtectedEffectStatus
    notes: tuple[str, ...] = ()

    def obligation_map(self) -> dict[str, ObligationResult]:
        return {item.name: item for item in self.obligations}

    def canonical_payload(self) -> dict[str, Any]:
        return {
            "revision_sha": self.revision_sha,
            "label": self.label,
            "source_mode": self.source_mode,
            "final_protected_effect_status": self.final_protected_effect_status,
            "obligations": [item.canonical_payload() for item in self.obligations],
            "notes": list(self.notes),
        }


@dataclass(frozen=True)
class OpenWebUIMultiObligationDevelopmentReplayReport:
    vulnerable: OpenWebUIMultiObligationRevisionReport
    repair: OpenWebUIMultiObligationRevisionReport
    schema_version: Literal[
        "ovk.open_webui_multi_obligation_development_replay.v1"
    ] = "ovk.open_webui_multi_obligation_development_replay.v1"
    label: ReplayLabel = "development_replay"
    held_out_success: Literal[False] = False
    frozen_registry_mutated: Literal[False] = False
    source_mode: ReplaySourceMode = "synthetic_fixture"

    def canonical_payload(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "label": self.label,
            "held_out_success": self.held_out_success,
            "frozen_registry_mutated": self.frozen_registry_mutated,
            "source_mode": self.source_mode,
            "vulnerable": self.vulnerable.canonical_payload(),
            "repair": self.repair.canonical_payload(),
        }

    def digest(self) -> str:
        return content_digest(self.canonical_payload())


def _module_functions(tree: ast.AST) -> list[ast.FunctionDef | ast.AsyncFunctionDef]:
    return [
        node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]


def _pick_entry_path(files: Mapping[str, str], preferred: str | None) -> str:
    if preferred is not None and preferred in files:
        return preferred
    for candidate in (
        "backend/open_webui/routers/openai.py",
        "backend/open_webui/routers/ollama.py",
        "app/handler.py",
    ):
        if candidate in files:
            return candidate
    return sorted(files)[0]


def _http_param_bypass(
    origins: Sequence[ValueOriginEvidence],
    *,
    path: str,
    bypass_field: str,
) -> bool:
    return any(
        item.origin_kind == "externally_bound_http_value"
        and (
            item.source_expression == bypass_field
            or item.value_id == f"value:param:{bypass_field}"
        )
        and item.origin.path == path
        for item in origins
    )


def _extract_unit_origins(
    files: Mapping[str, str],
) -> list[ValueOriginEvidence]:
    origins: list[ValueOriginEvidence] = []
    for path, source in sorted(files.items()):
        tree = ast.parse(source)
        for fn in _module_functions(tree):
            origins.extend(
                extract_value_origins_from_source(
                    source,
                    path=path,
                    function_name=fn.name,
                )
            )
    return origins


def analyze_open_webui_multi_obligation_revision(
    *,
    revision_sha: str,
    files: Mapping[str, str],
    entry_path: str | None = None,
    function_name: str = "handler",
    sink_needle: str = "sink",
    guard_needle: str = "require_access",
    bypass_field: str = "bypass_filter",
    callee_name: str | None = None,
    callee_parameter: str = "bypass_filter",
    repo: str = OPEN_WEBUI_REPO,
    source_roots: Sequence[str] = ("backend",),
    trusted_bypass_authorities: Mapping[str, Sequence[str]] | None = None,
    principal_id: str = "principal:user",
    effect_name: str = "model.invoke",
    effect_id: str = "effect:model",
    resource_id: str = "resource:acted",
    source_mode: ReplaySourceMode = "synthetic_fixture",
) -> OpenWebUIMultiObligationRevisionReport:
    """Answer each multi-obligation separately for one pinned revision unit."""

    notes: list[str] = []
    entry = _pick_entry_path(files, entry_path)
    unit = {path.replace("\\", "/"): source for path, source in files.items()}
    policy = dict(trusted_bypass_authorities or {})

    def _fail_extraction(reason: str) -> OpenWebUIMultiObligationRevisionReport:
        obligations = tuple(
            ObligationResult(
                name=name,
                status="unknown" if name != "source_extraction" else "violated",
                reason=reason if name == "source_extraction" else "extraction_failed",
            )
            for name in OBLIGATION_NAMES
            if name != "final_protected_effect_status"
        ) + (
            ObligationResult(
                name="final_protected_effect_status",
                status="unknown",
                reason=reason,
            ),
        )
        return OpenWebUIMultiObligationRevisionReport(
            revision_sha=revision_sha,
            label="development_replay",
            source_mode=source_mode,
            obligations=obligations,
            final_protected_effect_status="UNKNOWN",
            notes=(reason,),
        )

    try:
        handler_source = unit[entry]
        tree = ast.parse(handler_source)
        functions = _module_functions(tree)
        if not functions:
            raise ValueError("no handler function found")
        named = [node for node in functions if node.name == function_name]
        handler = named[0] if named else functions[0]
        cfg = build_handler_control_flow_from_source(
            handler_source,
            path=entry,
            function_name=handler.name,
        )
        origins = _extract_unit_origins(unit)
        derived_scope = derive_closed_world_scope_proof(
            repo=repo,
            revision=revision_sha,
            files=unit,
            source_roots=source_roots,
            analyzed_paths=tuple(unit),
            field_searched=bypass_field,
            import_resolution_status="sparse_unit_not_repo_closure",
        )
        scope_proof = derived_scope.as_closed_world_scope_proof()
        bypass_findings = analyze_bypass_authority_unit(
            unit,
            entry_path=entry,
            function_name=handler.name,
            bypass_fields=frozenset({bypass_field}),
            scope_proof=scope_proof,
        )
    except Exception as exc:  # noqa: BLE001 - replay stays fail-closed
        return _fail_extraction(f"extraction_failed:{type(exc).__name__}:{exc}")

    source_extraction = ObligationResult(
        name="source_extraction",
        status="established",
        reason="unit_parsed",
    )

    sinks = find_nodes_by_expression_substring(cfg, sink_needle)
    guards = find_nodes_by_expression_substring(cfg, guard_needle)
    cfg_complete = bool(sinks) and all(
        coverage_authoritative_for(cfg, sink.node_id) for sink in sinks
    )
    cfg_coverage = ObligationResult(
        name="cfg_coverage",
        status="established" if cfg_complete else "unknown",
        reason="complete" if cfg_complete else "partial_or_sink_missing",
    )

    bypass_represented = any(
        bypass_field in (item.source_expression or "")
        or item.origin_kind == "request_state_attribute"
        for item in origins
    ) or any(item.field_name == bypass_field for item in bypass_findings)
    bypass_predicate = ObligationResult(
        name="bypass_predicate_representation",
        status="established" if bypass_represented else "violated",
        reason="represented" if bypass_represented else "bypass_field_absent",
    )

    field_origins = [
        item
        for item in origins
        if bypass_field in (item.source_expression or "")
        or item.origin_kind == "request_state_attribute"
        or item.value_id == f"value:param:{bypass_field}"
    ]
    origin_kinds = {item.origin_kind for item in field_origins}
    http_param = _http_param_bypass(origins, path=entry, bypass_field=bypass_field)
    if not field_origins and not bypass_findings:
        value_origin = ObligationResult(
            name="value_origin",
            status="unknown",
            reason="no_origin_evidence",
        )
    elif "unknown_origin" in origin_kinds and not http_param:
        value_origin = ObligationResult(
            name="value_origin",
            status="unknown",
            reason="unknown_origin_present",
        )
    elif http_param:
        value_origin = ObligationResult(
            name="value_origin",
            status="established",
            reason="externally_bound_http_value",
        )
    else:
        value_origin = ObligationResult(
            name="value_origin",
            status="established",
            reason=",".join(sorted(origin_kinds)) or "origin_kinds_recorded",
        )

    matching_findings = [
        item for item in bypass_findings if item.field_name == bypass_field
    ]
    finding = matching_findings[0] if matching_findings else None
    if finding is not None and finding.status == "violated":
        writer_closure = ObligationResult(
            name="writer_closure",
            status="violated",
            reason=finding.reason,
        )
        notes.append(finding.reason)
    elif finding is not None and finding.status == "authorized" and not http_param:
        # Sparse development units are not repository closure. Writer search
        # over the supplied pin/fixture set alone must not establish closed
        # world (Unknown > false PASS when writers may exist outside the unit).
        if derived_scope.import_resolution_status == "sparse_unit_not_repo_closure":
            writer_closure = ObligationResult(
                name="writer_closure",
                status="unknown",
                reason="sparse_unit_not_repo_closure",
            )
            notes.append("sparse_unit_not_repo_closure")
        else:
            writer_closure = ObligationResult(
                name="writer_closure",
                status="established",
                reason=finding.reason,
            )
    elif http_param:
        # Route-bound HTTP parameters are client-controlled even when the
        # closed-world writer search remains unresolved.
        writer_closure = ObligationResult(
            name="writer_closure",
            status="violated",
            reason="client_controlled_http_param_bypass",
        )
        notes.append("client_controlled_http_param_bypass")
    elif finding is None:
        writer_closure = ObligationResult(
            name="writer_closure",
            status="unknown",
            reason="no_bypass_authority_finding",
        )
    else:
        writer_closure = ObligationResult(
            name="writer_closure",
            status="unknown",
            reason=finding.reason,
        )
        notes.append(finding.reason)

    if callee_name is None:
        caller_provenance = ObligationResult(
            name="caller_provenance",
            status="not_applicable",
            reason="no_callee_requested",
        )
        caller_kind = None
    else:
        provenance = analyze_interprocedural_argument_provenance(
            unit,
            callee_name=callee_name,
            parameter=callee_parameter,
            scope_proof=scope_proof,
        )
        caller_kind = provenance.provenance
        if provenance.provenance == "server_internal":
            caller_status: ObligationStatusValue = "established"
        elif provenance.provenance == "externally_bound_http":
            caller_status = "violated"
        else:
            caller_status = "unknown"
        caller_provenance = ObligationResult(
            name="caller_provenance",
            status=caller_status,
            reason=provenance.reason,
        )
        notes.append(f"caller_provenance:{provenance.reason}")

    ordinary_dominates = False
    if sinks and guards and cfg_complete:
        ordinary_dominates = all(
            any(cfg_dominates(cfg, guard.node_id, sink.node_id) for guard in guards)
            for sink in sinks
        )
    ordinary_guard = ObligationResult(
        name="ordinary_guard_effectiveness",
        status=(
            "established"
            if ordinary_dominates
            else ("unknown" if not cfg_complete or not guards else "violated")
        ),
        reason=(
            "dominates_sink"
            if ordinary_dominates
            else (
                "cfg_or_guard_incomplete"
                if not cfg_complete or not guards
                else "does_not_dominate"
            )
        ),
    )

    edge_id = resolve_bypass_control_point_edge(cfg, field_name=bypass_field)
    origin = read_origin_for_path(entry)
    trusted = evaluate_trusted_bypass_authorizations(
        files=unit,
        entry_path=entry,
        function_name=handler.name,
        cfg=cfg,
        trusted_bypass_authorities=policy,
        principal_id=principal_id,
        effect_bindings={effect_name: (effect_id, resource_id)},
        origin=origin,
        scope_proof=scope_proof,
    )
    bypass_evidence = next(
        (item for item in trusted.evidence if item.field_name == bypass_field),
        None,
    )
    if bypass_evidence is None and http_param:
        bypass_authority = ObligationResult(
            name="bypass_authority",
            status="violated",
            reason="client_controlled_http_param_bypass",
        )
    elif bypass_evidence is None:
        bypass_authority = ObligationResult(
            name="bypass_authority",
            status="unknown",
            reason="no_trusted_bypass_evidence",
        )
    elif bypass_evidence.status == "established":
        bypass_authority = ObligationResult(
            name="bypass_authority",
            status="established",
            reason=bypass_evidence.reason,
        )
    elif bypass_evidence.status == "violated":
        bypass_authority = ObligationResult(
            name="bypass_authority",
            status="violated",
            reason=bypass_evidence.reason,
        )
    else:
        bypass_authority = ObligationResult(
            name="bypass_authority",
            status="unknown",
            reason=bypass_evidence.reason,
        )

    branch_outcome = ObligationResult(
        name="branch_outcome_binding",
        status="established" if edge_id is not None else "unknown",
        reason=edge_id or "control_point_edge_unresolved",
    )

    collective_status: ObligationStatusValue = "unknown"
    collective_reason = "insufficient_control_points"
    if sinks and cfg_complete:
        sink_id = sinks[0].node_id
        cut_nodes = frozenset(guard.node_id for guard in guards)
        # Only trusted/established bypass edges may participate as authorizing
        # control points. An unauthorized bypass edge is not a cut member.
        authorizing_edge = (
            edge_id
            if edge_id is not None and bypass_authority.status == "established"
            else None
        )
        cut_edges = frozenset({authorizing_edge} if authorizing_edge else ())
        if cut_nodes or cut_edges:
            cut = evaluate_authorization_cut_set(
                cfg,
                sink_node_id=sink_id,
                cut_node_ids=cut_nodes,
                cut_edge_ids=cut_edges,
            )
            if cut.covers_all_paths and cut.coverage_status == "complete":
                collective_status = "established"
                collective_reason = "collective_cut_covers_sink"
            elif cut.coverage_status == "complete":
                collective_status = "violated"
                collective_reason = cut.reason or "uncovered_path"
            else:
                collective_status = "unknown"
                collective_reason = cut.reason or "cut_unknown"
        else:
            collective_reason = "empty_control_point_set"
    collective_path = ObligationResult(
        name="collective_path_coverage",
        status=collective_status,
        reason=collective_reason,
    )

    # Development replay does not claim FastAPI PE IR principal/effect/resource
    # binding. Supplied replay identifiers are labels only — stay UNKNOWN.
    principal_binding = ObligationResult(
        name="principal_binding",
        status="unknown",
        reason="development_replay_bindings_not_ir_proved",
    )
    effect_binding = ObligationResult(
        name="effect_binding",
        status="unknown",
        reason="development_replay_bindings_not_ir_proved",
    )
    resource_binding = ObligationResult(
        name="resource_binding",
        status="unknown",
        reason="development_replay_bindings_not_ir_proved",
    )

    # Final three-valued PE classification for the development case.
    # Structural dominance / trusted-bypass mechanism success must not claim
    # PE PASS while principal/effect/resource bindings remain UNKNOWN.
    if ordinary_dominates and cfg_complete:
        final_status: FinalProtectedEffectStatus = "UNKNOWN"
        final_reason = "ordinary_guard_structural_dominance_not_pe_pass"
    elif (
        bypass_authority.status == "established"
        and branch_outcome.status == "established"
        and collective_path.status == "established"
        and writer_closure.status == "established"
        and (
            caller_provenance.status in {"established", "not_applicable"}
        )
        and cfg_complete
    ):
        final_status = "UNKNOWN"
        final_reason = "trusted_bypass_mechanism_not_pe_pass_bindings_unresolved"
    elif (
        (
            writer_closure.status == "violated"
            or bypass_authority.status == "violated"
            or (http_param and not ordinary_dominates)
        )
        and cfg_complete
        and bypass_represented
        and collective_path.status in {"violated", "established"}
    ):
        # Client-controlled bypass with complete CFG is a concrete FAIL when
        # the ordinary guard does not dominate (bypass path reaches the sink).
        if not ordinary_dominates and (
            http_param or writer_closure.status == "violated"
        ):
            final_status = "FAIL"
            final_reason = "client_controlled_bypass_reaches_sink"
        else:
            final_status = "UNKNOWN"
            final_reason = "violation_signal_incomplete"
    else:
        final_status = "UNKNOWN"
        final_reason = "provenance_or_closure_incomplete"
        if caller_kind == "unknown":
            final_reason = "caller_provenance_incomplete"

    final_obligation = ObligationResult(
        name="final_protected_effect_status",
        status=(
            "established"
            if final_status == "PASS"
            else "violated" if final_status == "FAIL" else "unknown"
        ),
        reason=final_reason,
    )

    obligations = (
        source_extraction,
        cfg_coverage,
        bypass_predicate,
        value_origin,
        writer_closure,
        caller_provenance,
        ordinary_guard,
        bypass_authority,
        branch_outcome,
        collective_path,
        principal_binding,
        effect_binding,
        resource_binding,
        final_obligation,
    )
    assert tuple(item.name for item in obligations) == OBLIGATION_NAMES

    return OpenWebUIMultiObligationRevisionReport(
        revision_sha=revision_sha,
        label="development_replay",
        source_mode=source_mode,
        obligations=obligations,
        final_protected_effect_status=final_status,
        notes=tuple(notes),
    )


def build_open_webui_multi_obligation_development_replay(
    *,
    vulnerable_files: Mapping[str, str],
    repair_files: Mapping[str, str],
    vulnerable_sha: str = OPEN_WEBUI_VULNERABLE_SHA,
    repair_sha: str = OPEN_WEBUI_REPAIR_SHA,
    vulnerable_kwargs: Mapping[str, Any] | None = None,
    repair_kwargs: Mapping[str, Any] | None = None,
) -> OpenWebUIMultiObligationDevelopmentReplayReport:
    """Build the dual-revision multi-obligation development replay report."""

    vul_kw = dict(vulnerable_kwargs or {})
    rep_kw = dict(repair_kwargs or {})
    return OpenWebUIMultiObligationDevelopmentReplayReport(
        vulnerable=analyze_open_webui_multi_obligation_revision(
            revision_sha=vulnerable_sha,
            files=vulnerable_files,
            source_mode="synthetic_fixture",
            **vul_kw,
        ),
        repair=analyze_open_webui_multi_obligation_revision(
            revision_sha=repair_sha,
            files=repair_files,
            source_mode="synthetic_fixture",
            **rep_kw,
        ),
        source_mode="synthetic_fixture",
    )


def build_open_webui_multi_obligation_live_development_replay(
    *,
    vulnerable_sha: str = OPEN_WEBUI_VULNERABLE_SHA,
    repair_sha: str = OPEN_WEBUI_REPAIR_SHA,
    require_gate: bool = True,
    relative_paths: tuple[str, ...] = OPEN_WEBUI_PIN_RELATIVE_PATHS,
) -> OpenWebUIMultiObligationDevelopmentReplayReport:
    """Fetch pinned Open WebUI revisions and build a live multi-obligation replay.

    Requires ``OVK_OPEN_WEBUI_LIVE_REPLAY=1`` when ``require_gate`` is true.
    Live results remain ``development_replay`` and never held-out success.
    """

    if require_gate and not live_open_webui_replay_enabled():
        raise RuntimeError(
            f"live Open WebUI pin replay requires {OPEN_WEBUI_LIVE_REPLAY_ENV}=1; "
            "synthetic fixtures remain the default CI path"
        )

    vulnerable_files = fetch_open_webui_pin_unit(
        revision_sha=vulnerable_sha,
        relative_paths=relative_paths,
    )
    repair_files = fetch_open_webui_pin_unit(
        revision_sha=repair_sha,
        relative_paths=relative_paths,
    )
    live_kwargs = {
        "function_name": "generate_chat_completion",
        "sink_needle": "metadata",
        "guard_needle": "check_model_access",
        "bypass_field": "bypass_filter",
        "callee_name": "generate_chat_completion",
        "callee_parameter": "bypass_filter",
        "source_roots": ("backend",),
        "source_mode": "live_pin",
    }
    return OpenWebUIMultiObligationDevelopmentReplayReport(
        vulnerable=analyze_open_webui_multi_obligation_revision(
            revision_sha=vulnerable_sha,
            files=vulnerable_files,
            **live_kwargs,
        ),
        repair=analyze_open_webui_multi_obligation_revision(
            revision_sha=repair_sha,
            files=repair_files,
            **live_kwargs,
        ),
        source_mode="live_pin",
    )


# Re-export pin constants for callers that import from this module.
__all__ = [
    "OBLIGATION_NAMES",
    "OPEN_WEBUI_LIVE_REPLAY_ENV",
    "OPEN_WEBUI_REPAIR_SHA",
    "OPEN_WEBUI_REPO",
    "OPEN_WEBUI_VULNERABLE_SHA",
    "ObligationResult",
    "OpenWebUIMultiObligationDevelopmentReplayReport",
    "OpenWebUIMultiObligationRevisionReport",
    "analyze_open_webui_multi_obligation_revision",
    "build_open_webui_multi_obligation_development_replay",
    "build_open_webui_multi_obligation_live_development_replay",
]
